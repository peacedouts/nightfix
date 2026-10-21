package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// On Fargate there's no disk: the first instance to start creates the
// sealing key (wrapped by KMS) and the agent CA in Postgres, and every
// instance, including ones starting at the same moment, ends up with the same.
func TestStatelessBootstrapSharesKeys(t *testing.T) {
	pool := testdb.New(t)
	stub := devstub.New(time.Second)
	srv := httptest.NewServer(stub.Handler())
	t.Cleanup(srv.Close)
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", srv.URL+"/aws")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	ctx := context.Background()
	kms, err := awscall.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "alias/nightfix-sealing"

	type boot struct {
		sl  *signing.Sealer
		ca  *controlplane.CA
		err error
	}
	results := make([]boot, 4)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sl, err := controlplane.BootstrapSealer(ctx, pool, kms, keyID)
			if err != nil {
				results[i].err = err
				return
			}
			ca, err := controlplane.LoadOrCreateCAInDB(ctx, pool, sl)
			results[i] = boot{sl, ca, err}
		}(i)
	}
	wg.Wait()
	sealed, err := results[0].sl.Seal([]byte("pagerduty-routing-key"), "org-1")
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("instance %d: %v", i, r.err)
		}
		if pt, err := r.sl.Open(sealed, "org-1"); err != nil || string(pt) != "pagerduty-routing-key" {
			t.Fatalf("instance %d has a different sealing key: %v", i, err)
		}
		if !r.ca.Cert.Equal(results[0].ca.Cert) {
			t.Fatalf("instance %d has a different agent CA", i)
		}
	}

	// Only ciphertext is stored; a restart decrypts the same key.
	var blob []byte
	if err := pool.QueryRowContext(ctx, `SELECT secret FROM system_keys WHERE name = 'sealing_dek'`).Scan(&blob); err != nil || len(blob) < 32 {
		t.Fatalf("expected a stored KMS ciphertext: %v", err)
	}
	again, err := controlplane.BootstrapSealer(ctx, pool, kms, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Open(sealed, "org-1"); err != nil {
		t.Fatal("restart should load the same sealing key")
	}
	// Pointing at a different KMS key is refused rather than silently forking.
	if _, err := controlplane.BootstrapSealer(ctx, pool, kms, "alias/other"); err == nil || !strings.Contains(err.Error(), "wrapped by KMS key") {
		t.Fatalf("expected a key mismatch error, got %v", err)
	}
	calls, _, _ := stub.Snapshot()
	generated := 0
	for _, c := range calls {
		if c == "kms:GenerateDataKey" {
			generated++
		}
	}
	if generated == 0 || generated > len(results) {
		t.Fatalf("unexpected GenerateDataKey calls: %d", generated)
	}
}

// Installing an agent needs the gateway's CA; the API publishes it, over the
// API's own (publicly trusted) TLS in production.
func TestAgentCAIsPublished(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	resp, err := http.Get(e.api + "/v1/agent-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != string(e.caPEM) {
		t.Fatalf("got %d %q", resp.StatusCode, b)
	}
}

// Customers pin the org's signing key in their agents (key_id=public-key),
// so the API has to hand it to them.
func TestSigningKeyPinIsPublished(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var out struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
		Required []string `json:"required_signers"`
		Pin      string   `json:"agent_pin"`
	}
	e.call("GET", "/v1/signing-keys", nil, &out)
	if len(out.Keys) != 1 || len(out.Required) != 1 || out.Required[0] != out.Keys[0].KeyID {
		t.Fatalf("unexpected keys: %+v", out)
	}
	id, pub, ok := strings.Cut(out.Pin, "=")
	raw, err := base64.StdEncoding.DecodeString(pub)
	if !ok || id != out.Keys[0].KeyID || err != nil || len(raw) != ed25519.PublicKeySize || pub != out.Keys[0].PublicKey {
		t.Fatalf("agent_pin %q isn't key_id=base64(ed25519 public key)", out.Pin)
	}
}
