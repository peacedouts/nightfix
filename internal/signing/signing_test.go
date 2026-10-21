package signing

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/runbook"
)

func bundleFor(t *testing.T, keys ...Key) Bundle {
	t.Helper()
	src, err := os.ReadFile("../../examples/runbooks/ecs-service-restart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := runbook.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	c, d, _ := runbook.Canonical(rb)
	b := Bundle{Name: rb.Metadata.Name, Version: 1, Digest: d, CanonicalJSON: string(c)}
	for _, k := range keys {
		b.Signatures = append(b.Signatures, SignDigest(k, d))
	}
	return b
}

func trust(required []string, keys ...Key) TrustConfig {
	tc := TrustConfig{Keys: map[string]string{}, RequiredSigners: required}
	for _, k := range keys {
		tc.Keys[k.ID] = base64.StdEncoding.EncodeToString(k.Public)
	}
	return tc
}

func TestBundleVerification(t *testing.T) {
	cp, _ := GenerateKey("nightfix-org")
	cust, _ := GenerateKey("customer-ci")

	b := bundleFor(t, cp)
	if _, err := VerifyBundle(b, trust([]string{cp.ID}, cp), nil); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}

	// Customer co-signing required: control-plane signature alone is not enough.
	tc := trust([]string{cp.ID, cust.ID}, cp, cust)
	if _, err := VerifyBundle(b, tc, nil); err == nil || !strings.Contains(err.Error(), cust.ID) {
		t.Fatalf("expected missing co-signature, got %v", err)
	}
	if _, err := VerifyBundle(bundleFor(t, cp, cust), tc, nil); err != nil {
		t.Fatalf("co-signed bundle rejected: %v", err)
	}

	// The agent's locally pinned list wins even if the control plane drops the
	// customer key from its own list.
	stripped := trust([]string{cp.ID}, cp, cust)
	if _, err := VerifyBundle(b, stripped, []string{cp.ID, cust.ID}); err == nil {
		t.Fatal("local pin should still require the customer signature")
	}

	// Tampered content fails the digest check.
	bad := b
	bad.CanonicalJSON = strings.Replace(bad.CanonicalJSON, "forceNewDeployment", "forceNewDeploymenX", 1)
	if _, err := VerifyBundle(bad, trust([]string{cp.ID}, cp), nil); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestEnvelope(t *testing.T) {
	cp, _ := GenerateKey("nightfix-org")
	cust, _ := GenerateKey("acme-ci")
	tc := trust([]string{cp.ID}, cp, cust)
	tc.EnvelopeSigners = []string{cp.ID}
	now := time.Now()
	e := Envelope{AttemptID: "a1", RunID: "r1", StepID: "restart", AgentID: "agent-1", OrgID: "org-1",
		Params: map[string]any{"cluster": "prod"}, ExpiresAt: now.Add(2 * time.Minute).UnixMilli()}
	se, err := SealEnvelope(cp, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnvelope(se, tc, "org-1", "agent-1", now); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if _, err := OpenEnvelope(se, tc, "org-1", "agent-2", now); err == nil {
		t.Fatal("envelope accepted by the wrong agent")
	}
	if _, err := OpenEnvelope(se, tc, "org-1", "agent-1", now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired envelope accepted")
	}
	tampered := se
	tampered.Payload = strings.Replace(se.Payload, `"prod"`, `"staging"`, 1)
	if _, err := OpenEnvelope(tampered, tc, "org-1", "agent-1", now); err == nil {
		t.Fatal("tampered params accepted")
	}
	// A customer co-signer key is trusted for bundles, never for dispatch.
	forged, _ := SealEnvelope(cust, e)
	if _, err := OpenEnvelope(forged, tc, "org-1", "agent-1", now); err == nil || !strings.Contains(err.Error(), "not a control-plane key") {
		t.Fatalf("envelope signed by a customer key accepted: %v", err)
	}
	// An envelope for another org is refused even when the agent id matches.
	if _, err := OpenEnvelope(se, tc, "org-2", "agent-1", now); err == nil {
		t.Fatal("envelope for another org accepted")
	}
}

func TestSealer(t *testing.T) {
	s, _ := NewSealer(make([]byte, 32))
	ct, _ := s.Seal([]byte("routing-key"), "org-a")
	if pt, err := s.Open(ct, "org-a"); err != nil || string(pt) != "routing-key" {
		t.Fatalf("got %q %v", pt, err)
	}
	if _, err := s.Open(ct, "org-b"); err == nil {
		t.Fatal("ciphertext opened under another org")
	}
}
