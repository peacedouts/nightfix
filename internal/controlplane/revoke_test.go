package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

func TestRevokingAgentsAndEnrollmentRules(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nightfix-agent"}}, priv)
	csr := agentapi.RenewRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	routed := func(serial string) bool {
		var org, agent string
		var cur, prev bool
		return e.s.DB.QueryRowContext(ctx, `SELECT org_id, agent_id, is_current, has_prev FROM nfx_route_agent($1)`, serial).
			Scan(&org, &agent, &cur, &prev) == nil
	}
	a := e.a
	a.Serial = e.a.AgentID // the harness enrolled the agent with this serial

	// The rule is listed with its agent.
	code, _ := e.call("GET", "/v1/enrollment-rules", nil)
	if code != 200 {
		t.Fatalf("list rules: %d", code)
	}
	rule := ids.Encode("enr", e.rule)

	// Revoking the rule stops renewals, but doesn't cut the agent off.
	if code, out := e.call("POST", "/v1/enrollment-rules/"+rule+"/revoke", nil); code != 200 || out["revoked_agents"] != float64(0) {
		t.Fatalf("revoke rule: %d %v", code, out)
	}
	var he httpError
	if _, err := e.s.Renew(ctx, a, csr); !errors.As(err, &he) || he.code != 403 {
		t.Fatalf("renewal under a revoked rule: %v", err)
	}
	if !routed(a.Serial) {
		t.Fatal("revoking the rule alone cut the agent off")
	}
	if code, _ := e.call("POST", "/v1/enrollment-rules/"+rule+"/revoke", nil); code != 404 {
		t.Fatalf("revoking twice: %d", code)
	}

	// Revoking the agent cuts it off at once and drops it from the list.
	agt := ids.Encode("agt", e.a.AgentID)
	if code, out := e.call("POST", "/v1/agents/"+agt+"/revoke", nil); code != 200 {
		t.Fatalf("revoke agent: %d %v", code, out)
	}
	if routed(a.Serial) {
		t.Fatal("a revoked agent's certificate still authenticates")
	}
	if code, _ := e.call("POST", "/v1/agents/"+agt+"/revoke", nil); code != 404 {
		t.Fatalf("revoking twice: %d", code)
	}
	var n int
	if err := e.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM nfx_route_agent($1)`, a.Serial).Scan(&n); err != nil || n != 0 {
		t.Fatalf("route after revoke: %d %v", n, err)
	}
}

func TestRevokingRuleCanRevokeItsAgents(t *testing.T) {
	e := setupRunHarness(t)
	rule := ids.Encode("enr", e.rule)
	if code, out := e.call("POST", "/v1/enrollment-rules/"+rule+"/revoke", []byte(`{"revoke_agents":true}`)); code != 200 || out["revoked_agents"] != float64(1) {
		t.Fatalf("revoke rule and agents: %d %v", code, out)
	}
	var live int
	e.s.DB.QueryRowContext(context.Background(), `SELECT count(*) FROM nfx_route_agent($1)`, e.a.AgentID).Scan(&live)
	if live != 0 {
		t.Fatal("the rule's agent still authenticates")
	}
}

// An agent is only offered steps of a type it reported it can run.
func TestDispatchHonoursAgentCapabilities(t *testing.T) {
	e := setupRunHarness(t)
	setCaps := func(caps string) {
		t.Helper()
		if err := e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
			_, err := tx.Exec(`UPDATE agents SET capabilities = $2::text[] WHERE id = $1`, e.a.AgentID, caps)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setCaps("{aws,wait}")
	e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n")
	if a := e.poll(); a != "" {
		t.Fatalf("an agent without shell was given a shell step (%s)", a)
	}
	setCaps("{shell,aws,wait}")
	if a := e.poll(); a == "" {
		t.Fatal("an agent with shell wasn't given the shell step")
	}
}
