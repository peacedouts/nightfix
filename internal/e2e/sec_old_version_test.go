package e2e

import (
	"strings"
	"testing"
)

// An earlier runbook version may lack an approval gate the current one
// added; starting it is a rollback, which only admins may do.
func TestStartingAnEarlierVersionNeedsAdmin(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	v1 := gatedRunbook(t, "two-versions", "", false)
	v1 = strings.Replace(v1, "      name: Approve the restart\n      type: approval\n", "      type: note\n      markdown: no gate yet\n", 1)
	e.callRaw("PUT", "/v1/runbooks/two-versions", []byte(v1), nil)
	e.callRaw("PUT", "/v1/runbooks/two-versions", []byte(gatedRunbook(t, "two-versions", "", false)), nil)

	params := map[string]any{"cluster": "prod-east", "service": "checkout-api"}
	old := map[string]any{"runbook": "two-versions", "version": 1, "params": params}
	e.expect("dave (responder), version 1", who.dave, "POST", "/v1/runs", old, 403, "only admins can start an earlier version")
	e.expect("dave (responder), latest", who.dave, "POST", "/v1/runs", map[string]any{"runbook": "two-versions", "params": params}, 200, "run_")
	// (other parameters: the run above holds the concurrency slot for these)
	old["params"] = map[string]any{"cluster": "prod-east", "service": "search-api"}
	e.expect("alice (admin), version 1", who.alice, "POST", "/v1/runs", old, 200, "run_")
}
