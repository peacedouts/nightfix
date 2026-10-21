package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
)

// An approver who loses the role before the final approval no longer
// counts toward the gate.
func TestApprovalFromSomeoneWhoLostTheRoleNoLongerCounts(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      count: 2\n      fromRoles: [Admin]\n      expiresAfter: 10m\n", false)), nil)
	runID := e.startRun(who.dave, "ecs-restart-gated")
	e.waitRun(runID, "awaiting_approval")
	path := "/v1/runs/" + runID + "/steps/approve/approve"
	e.expect("alice", who.alice, "POST", path, nil, 200, `"status": "pending"`)

	// Alice leaves the platform-admins IdP group (signs in without it).
	aliceNow := e.auth0.UserToken("auth0|alice", "alice@acme.dev", "org_acme")
	e.expect("alice re-sync", aliceNow, "GET", "/v1/me", nil, 200, "")
	e.expect("alice (no longer admin) has no role now", aliceNow, "POST", path, nil, 403, "")

	out := e.expect("bob", who.bob, "POST", path, nil, 200, "")
	t.Logf("bob's approval result: %s", out)
	if strings.Contains(out, `"status": "approved"`) {
		t.Errorf("gate approved with 2 of 2 although alice no longer holds Admin")
	}
}

// A run outside an incident: when its approval expires, or a freeze cancels
// it, the approval channel says so (the request's buttons would otherwise
// look live).
func TestApprovalExpiryAndCancellationArePosted(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      fromRoles: [Admin]\n      expiresAfter: 10m\n", false)), nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)
	runID := e.startRun(who.dave, "ecs-restart-gated")
	e.waitRun(runID, "awaiting_approval")
	e.waitSlackOn("default", "Approval needed")
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE approval_gates SET expires_at = now() WHERE status = 'pending'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.waitRun(runID, "timed_out")
	time.Sleep(2 * time.Second) // let the outbox drain
	msgs := e.slackOn("default")
	t.Logf("default channel after expiry: %d message(s)", len(msgs))
	for _, m := range msgs {
		t.Logf("  %.160s", m)
	}
	if len(msgs) == 1 {
		t.Errorf("expiry was not posted to the approval channel; only the original request is there")
	}

	// Freeze cancels a second gated run: also silent.
	runB := e.startRun(who.dave, "ecs-restart-gated")
	e.waitRun(runB, "awaiting_approval")
	e.waitFor("second request", 10*time.Second, func() bool { return len(e.slackOn("default")) >= 2 })
	e.call("POST", "/v1/org/freeze", nil, nil)
	e.waitRun(runB, "cancelled")
	time.Sleep(2 * time.Second)
	if n := len(e.slackOn("default")); n == 2 {
		t.Errorf("freeze cancellation was not posted to the approval channel either (%d messages)", n)
	}
}

// policy.allowedRoles decides who may start a runbook by hand.
func TestAllowedRolesAreEnforced(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	src := gatedRunbook(t, "admins-only", "", false)
	src = strings.Replace(src, "      name: Approve the restart\n      type: approval\n", "      type: note\n      markdown: restart\n", 1)
	src = strings.Replace(src, "allowedRoles: [Responder, Admin]", "allowedRoles: [Admin]", 1)
	if !strings.Contains(src, "allowedRoles: [Admin]") {
		t.Fatal("fixture has no allowedRoles to replace")
	}
	e.callRaw("PUT", "/v1/runbooks/admins-only", []byte(src), nil)
	params := map[string]any{"runbook": "admins-only", "params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}}
	e.expect("dave (responder)", who.dave, "POST", "/v1/runs", params, 403, "can only be started by Admin")
	e.expect("alice (admin)", who.alice, "POST", "/v1/runs", params, 200, "run_")

	bogus := strings.Replace(src, "allowedRoles: [Admin]", "allowedRoles: [Wizard]", 1)
	if code, out := e.userCall(e.key, "PUT", "/v1/runbooks/admins-only", bogus); code != 422 || !strings.Contains(out, "allowedRoles") {
		t.Fatalf("publish with allowedRoles: [Wizard]: got %d %s", code, out)
	}
}
