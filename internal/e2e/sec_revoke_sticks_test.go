package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A revoked IAM agent re-enrolls at once (it treats the 401 as a lost
// identity), and used to be back within seconds. The identity it enrolled
// as is now refused.
func TestRevokedIAMAgentCannotReenrollAsTheSameIdentity(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var agents []map[string]any
	e.call("GET", "/v1/agents", nil, &agents)
	if len(agents) != 1 {
		t.Fatalf("agents: %v", agents)
	}
	e.call("POST", "/v1/agents/"+agents[0]["id"].(string)+"/revoke", nil, nil)

	var audit []map[string]any
	defer func() {
		if t.Failed() {
			e.call("GET", "/v1/audit-events", nil, &audit)
			for _, a := range audit {
				t.Log(toJSON(a))
			}
			e.call("GET", "/v1/agents", nil, &agents)
			t.Log("agents:", toJSON(agents))
		}
	}()
	e.waitFor("a refused re-enrollment", 20*time.Second, func() bool {
		e.call("GET", "/v1/audit-events", nil, &audit)
		for _, a := range audit {
			if a["action"] == "agent.enroll_denied" && strings.Contains(fmt.Sprint(a["actor"]), "assumed-role/nightfix-agent") {
				return true
			}
		}
		return false
	})
	e.call("GET", "/v1/agents", nil, &agents)
	if len(agents) != 0 {
		t.Fatalf("the revoked agent's identity enrolled again: %v", agents)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
