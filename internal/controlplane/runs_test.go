package controlplane

// Regression tests for runs, dispatch and agent certificates found in QA
// review. runHarness drives the server directly with a fake agent identity.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

func harnessRunbook(steps string) string {
	return `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: qa
  title: qa
spec:
  target:
    agentSelector:
      env: prod
  triggers:
    - type: manual
  policy:
    timeout: 10m
  steps:
` + steps
}

type runHarness struct {
	t    *testing.T
	s    *Server
	a    agentIdentity
	api  *httptest.Server
	key  string
	rule string
}

func setupRunHarness(t *testing.T) *runHarness {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := LoadOrCreateCA(t.TempDir())
	s := New(pool, sealer, ca, Config{PollWait: 50 * time.Millisecond}, nil)
	ctx := context.Background()
	org, err := s.CreateOrg(ctx, "A", "a")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, agentID := ids.NewString(), ids.NewString()
	err = pool.WithOrg(ctx, org.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`INSERT INTO enrollment_rules (id, org_id, method, token_hash, labels) VALUES ($1,$2,'token',$3,'{"env":"prod"}')`, ruleID, org.OrgID, []byte(ruleID)); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents (id, org_id, enrollment_rule_id, labels, cert_serial, cert_expires_at, status, last_seen_at) VALUES ($1,$2,$3,'{"env":"prod"}',$4, now()+interval '1 day','online',now())`, agentID, org.OrgID, ruleID, agentID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.APIHandler())
	t.Cleanup(api.Close)
	return &runHarness{t: t, s: s, a: agentIdentity{OrgID: org.OrgID, AgentID: agentID}, api: api, key: org.APIKey, rule: ruleID}
}

func (e *runHarness) call(method, path string, body []byte) (int, map[string]any) {
	req, _ := http.NewRequest(method, e.api.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *runHarness) startRun(steps string) string {
	if code, out := e.call("PUT", "/v1/runbooks/qa", []byte(harnessRunbook(steps))); code != 200 {
		e.t.Fatalf("publish: %d %v", code, out)
	}
	code, out := e.call("POST", "/v1/runs", []byte(`{"runbook":"qa"}`))
	if code != 200 {
		e.t.Fatalf("run: %d %v", code, out)
	}
	return out["id"].(string)
}

func (e *runHarness) run(id string) map[string]any {
	_, out := e.call("GET", "/v1/runs/"+id, nil)
	return out
}

func (e *runHarness) poll() string {
	d, err := e.s.Poll(context.Background(), e.a, agentapi.PollRequest{FreeSlots: 1})
	if err != nil {
		e.t.Fatalf("poll: %v", err)
	}
	if d.Dispatch == nil {
		return ""
	}
	var env struct {
		AttemptID string `json:"attempt_id"`
	}
	json.Unmarshal([]byte(d.Dispatch.Envelope.Payload), &env)
	return env.AttemptID
}

func (e *runHarness) expireLeases() {
	e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE step_attempts SET lease_expires_at = now() - interval '1 second' WHERE state IN ('dispatched','running')`)
		return err
	})
	if _, err := e.s.ProcessExpiredLeases(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *runHarness) ack(id string) {
	e.t.Helper()
	if err := e.s.Ack(context.Background(), e.a, id, agentapi.Ack{Accepted: true}); err != nil {
		e.t.Fatal(err)
	}
}

func TestOutputIsStorableAndDeduped(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n")
	id := e.poll()
	e.ack(id)
	// A resend after a lost response must not store the chunk twice.
	for i := 0; i < 2; i++ {
		if err := e.s.Output(ctx, e.a, id, agentapi.OutputBatch{Chunks: []agentapi.OutputChunk{{Seq: 1, Stream: "stdout", Data: "hello\n"}}}); err != nil {
			t.Fatalf("output: %v", err)
		}
	}
	// Over-long multi-byte text and NUL bytes used to fail the insert forever.
	for seq, data := range map[int]string{2: "a" + strings.Repeat("é", 20000), 3: "x\x00y", 4: "bad \xff utf8"} {
		if err := e.s.Output(ctx, e.a, id, agentapi.OutputBatch{Chunks: []agentapi.OutputChunk{{Seq: seq, Stream: "stdout", Data: data}}}); err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	var n, seq1 int
	e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		tx.QueryRow(`SELECT count(*) FROM step_output_chunks WHERE attempt_id = $1 AND seq = 1`, id).Scan(&seq1)
		return tx.QueryRow(`SELECT count(*) FROM step_output_chunks WHERE attempt_id = $1`, id).Scan(&n)
	})
	if seq1 != 1 || n != 4 {
		t.Fatalf("stored %d chunks (%d for seq 1); want 4 and 1", n, seq1)
	}
}

func TestManualRunRefusedWhileFrozen(t *testing.T) {
	e := setupRunHarness(t)
	if code, out := e.call("PUT", "/v1/runbooks/qa", []byte(harnessRunbook("    - id: s1\n      type: shell\n      run: echo hi\n"))); code != 200 {
		t.Fatalf("publish: %d %v", code, out)
	}
	if code, out := e.call("POST", "/v1/org/freeze", []byte(`{}`)); code != 200 {
		t.Fatalf("freeze: %d %v", code, out)
	}
	if code, _ := e.call("POST", "/v1/runs", []byte(`{"runbook":"qa"}`)); code != 409 {
		t.Fatalf("run while frozen: got %d, want 409", code)
	}
}

func TestRunConcurrencyIsEnforced(t *testing.T) {
	e := setupRunHarness(t)
	e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n")
	if code, out := e.call("POST", "/v1/runs", []byte(`{"runbook":"qa"}`)); code != 409 || !strings.Contains(fmt.Sprint(out), "concurrency") {
		t.Fatalf("second concurrent run: got %d %v, want 409", code, out)
	}
}

func TestStepEscalateIsRecorded(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	id := e.startRun("    - id: s1\n      type: shell\n      onFailure: escalate\n      run: exit 1\n")
	a := e.poll()
	e.ack(a)
	if err := e.s.Result(ctx, e.a, a, agentapi.Result{Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	runID, _ := ids.Decode("run", id)
	var escalate bool
	e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT coalesce((context->>'escalate')::bool, false) FROM runbook_runs WHERE id = $1`, runID).Scan(&escalate)
	})
	if !escalate {
		t.Fatal("a failed step with onFailure: escalate didn't mark the run for paging")
	}
}

func TestRenewalKeepsPreviousCertUntilNewOneIsUsed(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nightfix-agent"}}, priv)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	old := e.a
	old.Serial = e.a.AgentID // the harness enrolled the agent with this serial
	resp, err := e.s.Renew(ctx, old, agentapi.RenewRequest{CSRPEM: csr})
	if err != nil {
		t.Fatal(err)
	}
	route := func(serial string) (found, current bool) {
		var org, agent string
		var hasPrev bool
		err := e.s.DB.QueryRowContext(ctx, `SELECT org_id, agent_id, is_current, has_prev FROM nfx_route_agent($1)`, serial).
			Scan(&org, &agent, &current, &hasPrev)
		return err == nil, current
	}
	// The response may never reach the agent: its old certificate must still work.
	if ok, cur := route(old.Serial); !ok || cur {
		t.Fatalf("old serial after renewal: found=%v current=%v; want found, not current", ok, cur)
	}
	block, _ := pem.Decode([]byte(resp.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ok, cur := route(SerialHex(cert.SerialNumber)); !ok || !cur {
		t.Fatalf("new serial: found=%v current=%v", ok, cur)
	}
	// A retry with the old certificate replaces the new serial but keeps the old one valid.
	if _, err := e.s.Renew(ctx, old, agentapi.RenewRequest{CSRPEM: csr}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := route(old.Serial); !ok {
		t.Fatal("old serial stopped working after a retried renewal")
	}
}
