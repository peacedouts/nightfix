package e2e

import "testing"

// Regression tests for approvals found in QA round 2.

// A run parked at an approval gate still holds its concurrency slot;
// otherwise approving two parked runs would run both at once.
func TestConcurrencyCountsRunsAwaitingApproval(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      fromRoles: [Responder]\n      expiresAfter: 10m\n", false)), nil)
	a := e.startRun(who.alice, "ecs-restart-gated")
	e.waitRun(a, "awaiting_approval")
	code, out := e.userCall(who.alice, "POST", "/v1/runs", map[string]any{"runbook": "ecs-restart-gated",
		"params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}})
	if code != 409 {
		t.Fatalf("second identical run while the first awaits approval: got %d %s, want 409", code, out)
	}
}

// An approval channel that has been used can still have its webhook URL
// rotated (a leaked URL must be replaceable).
func TestUsedApprovalChannelCanBeReplaced(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      fromRoles: [Responder]\n      expiresAfter: 10m\n", false)), nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)
	a := e.startRun(who.alice, "ecs-restart-gated")
	e.waitRun(a, "awaiting_approval")
	e.waitSlackOn("default", "Approval needed")
	if code, out := e.userCall(who.alice, "PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=new"}); code != 200 {
		t.Fatalf("replace a used channel: got %d %s", code, out)
	}
}
