package e2e

// Claims from README.md checked against the running system. Each test names
// the sentence it checks.

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/controlplane"
)

func countAudit(e *env, action string) int {
	var audit []map[string]any
	e.call("GET", "/v1/audit-events", nil, &audit)
	n := 0
	for _, a := range audit {
		if a["action"] == action {
			n++
		}
	}
	return n
}

// README "Agent enrollment": denials are audited once the caller has proved
// an AWS identity; refusals before that aren't.
func TestDocAuditEveryEnrollmentDenialIsAudited(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	before := countAudit(e, "agent.enroll_denied")

	// A forged IAM proof for this org (someone probing the enrollment endpoint).
	n := e.challenge()
	forged := e.sign(e.aws, n)
	forged["Authorization"] = []string{forged["Authorization"][0][:len(forged["Authorization"][0])-4] + "beef"}
	if code, body := e.enrollIAM(e.aws, n, forged, agentapi.STSBody); code != 401 {
		t.Fatalf("forged signature: %d %s", code, body)
	}
	// Refused before the caller proved an identity: deliberately not audited
	// (an unauthenticated caller could otherwise fill the org's audit log).
	if got := countAudit(e, "agent.enroll_denied"); got != before {
		t.Errorf("a forged (unauthenticated) enrollment wrote to the org's audit log (enroll_denied %d -> %d)", before, got)
	}

	// The legitimate role, refused because its rule is at max_agents.
	before = countAudit(e, "agent.enroll_denied")
	n = e.challenge()
	if code, body := e.enrollIAM(e.aws, n, e.sign(e.aws, n), agentapi.STSBody); code != 403 || !strings.Contains(body, "at most 1") {
		t.Fatalf("over max_agents: %d %s", code, body)
	}
	if got := countAudit(e, "agent.enroll_denied"); got <= before {
		t.Errorf("an enrollment refused at max_agents (403) was not audited (enroll_denied %d -> %d)", before, got)
	}
}

// README "Approvals": "Requests go to the incident's service Slack targets;
// runs outside an incident (or services with no Slack target) use the
// runbook team's approval channel, else the org default".
func TestDocAuditApprovalForServiceWithoutSlackUsesApprovalChannel(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	// billing pages through PagerDuty only; the catch-all service has a Slack target.
	e.call("POST", "/v1/services", map[string]any{"name": "billing"}, nil)
	e.call("POST", "/v1/services/billing/escalation-targets",
		map[string]any{"type": "pagerduty", "routing_key": "pd-billing", "events_url": e.stubURL + "/pagerduty"}, nil)
	e.call("POST", "/v1/services/catch-all/escalation-targets", map[string]any{"type": "slack", "url": e.stubURL + "/slack?channel=catchall"}, nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)

	e.callRaw("PUT", "/v1/runbooks/billing-approve", []byte(`apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: billing-approve
  title: Approval only
spec:
  triggers:
    - type: manual
  steps:
    - id: approve
      type: approval
      fromRoles: [Admin]
      expiresAfter: 10m
    - id: done
      type: note
      markdown: done
`), nil)

	// An incident on billing, from a signed webhook.
	var integ map[string]string
	e.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "billing hook", "default_service": "billing"}, &integ)
	body := []byte(`{"summary":"billing errors","dedup_key":"billing-errors"}`)
	req, _ := http.NewRequest("POST", integ["ingest_url"], bytes.NewReader(body))
	req.Header.Set(controlplane.WebhookSignatureHeader, controlplane.SignWebhook(integ["signing_secret"], body, time.Now()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("webhook: %v %v", resp, err)
	}
	resp.Body.Close()
	e.waitFor("incident on billing", 10*time.Second, func() bool { return e.incident(1) != nil })

	var run map[string]string
	e.call("POST", "/v1/runs", map[string]any{"runbook": "billing-approve", "incident": 1}, &run)
	e.waitRun(run["id"], "awaiting_approval")
	time.Sleep(2 * time.Second) // let the outbox drain

	onDefault := strings.Contains(fmt.Sprint(e.slackOn("default")), "Approval needed")
	onCatchAll := strings.Contains(fmt.Sprint(e.slackOn("catchall")), "Approval needed")
	if !onDefault || onCatchAll {
		t.Errorf("approval request for a service with no Slack target: org approval channel got it=%v, catch-all service's Slack target got it=%v (README says the approval channel)",
			onDefault, onCatchAll)
	}
}

// README "Identity": "the org's last owner credential can't be revoked
// (create a new owner key first, then revoke the old one)".
func TestDocAuditLastOwnerCredentialCantBeRevoked(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	// An owner binding that reaches nobody: a team with no members and no IdP group.
	e.call("POST", "/v1/teams", map[string]string{"slug": "ghosts"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "ghosts", "role": "owner"}, nil)

	var keys map[string][]map[string]any
	e.call("GET", "/v1/api-keys", nil, &keys)
	if len(keys["keys"]) != 1 {
		t.Fatalf("expected only the bootstrap key: %v", keys)
	}
	id := fmt.Sprint(keys["keys"][0]["id"])
	code, out := e.userCall(e.key, "POST", "/v1/api-keys/"+id+"/revoke", nil)
	if code != http.StatusConflict {
		t.Errorf("revoking the only owner key (the only owner binding is a team nobody is in): got %d %s, want 409", code, out)
		if c, _ := e.userCall(e.key, "GET", "/v1/me", nil); c == http.StatusUnauthorized {
			t.Log("the org now has no usable owner credential; only an operator can recover it")
		}
	}
}
