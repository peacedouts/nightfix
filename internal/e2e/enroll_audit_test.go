package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
)

// Enrollment-denial auditing: with no credentials at all (no client cert, no
// token, no AWS identity), anyone who knows an org's ID can append permanent,
// hash-chained audit rows to that org: request a challenge (unauthenticated,
// unlimited), then enroll with a different org_id or a junk IAM proof.
// Before this change the only trace was a challenge row that expires in 5
// minutes. Audit rows are kept for ever, take the org's audit counter lock,
// push real events out of GET /v1/audit-events (last 200), and make every
// later ?verify=true walk longer. The text stored includes attacker input
// (the region string, via verifyIAM's error).
func TestUnauthenticatedCallerFloodsOrgAudit(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	count := func() (n int) {
		if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'agent.enroll_denied'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	const n = 300
	start := time.Now()
	for i := 0; i < n; i++ {
		nonce := e.challenge()
		req := agentapi.EnrollRequest{Method: "iam", OrgID: e.orgID, Nonce: nonce, CSRPEM: "x", Version: "x",
			IAM: &agentapi.IAMRequest{Region: "attacker-controlled text " + strings.Repeat("A", 200), Body: agentapi.STSBody,
				Headers: map[string][]string{
					agentapi.HeaderOrg: {e.orgID}, agentapi.HeaderNonce: {nonce},
					"Authorization": {"AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-nightfix-org;x-nightfix-nonce, Signature=x"}}}}
		if i%2 == 1 {
			req.OrgID, req.IAM = "org_bogus", nil // "challenge was issued for a different org"
		}
		if code, _ := e.gw("/agent/v1/enroll", req, nil); code != 401 {
			t.Fatalf("enroll %d: got %d", i, code)
		}
	}
	after := count()
	var sample string
	e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT data::text FROM audit_events WHERE action = 'agent.enroll_denied' AND data::text LIKE '%attacker%' LIMIT 1`).Scan(&sample)
	})
	t.Logf("%d unauthenticated requests in %v added %d permanent audit rows to the org; sample data: %.200s", 2*n, time.Since(start).Round(time.Millisecond), after-before, sample)
	if after-before > 20 {
		t.Errorf("an unauthenticated caller appended %d audit rows to another org with no limit", after-before)
	}
}

// The 16 KiB audit data cap replaces oversized data with a stub before
// nfx_audit hashes it, so the chain must still verify.
func TestAuditCapKeepsChainVerifiable(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		if err := tx.Audit(e.ctx, "user", "u", "test.big", "x", "y", map[string]string{"blob": strings.Repeat("é\u0000<", 9000)}); err != nil {
			return err
		}
		return tx.Audit(e.ctx, "user", "u", "test.small", "x", "y", map[string]string{"k": "v"})
	}); err != nil {
		t.Fatal(err)
	}
	var data string
	e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT data::text FROM audit_events WHERE action = 'test.big'`).Scan(&data)
	})
	t.Logf("stored: %s", data)
	code := e.callRaw("GET", "/v1/audit-events?verify=true", nil, nil)
	if code != 200 {
		t.Errorf("audit verification after a truncated event: %d", code)
	}
}
