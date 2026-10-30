package e2e

import (
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
)

// Regression tests for RBAC and publishing.
func TestRBACHardening(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.call("PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "owners"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "platform-admins", "auth0_group": "platform"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "payments", "auth0_group": "payments-eng"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "owners", "role": "owner"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "platform-admins", "role": "admin"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "payments", "role": "responder",
		"scope": map[string]any{"teams": []string{"payments"}}}, nil)
	e.call("POST", "/v1/services", map[string]any{"name": "ledger", "team": "finance"}, nil)
	e.call("POST", "/v1/services", map[string]any{"name": "payments-api", "team": "payments"}, nil)

	bob := e.auth0.UserToken("auth0|bob", "bob@acme.dev", "org_acme", "platform")
	dave := e.auth0.UserToken("auth0|dave", "dave@acme.dev", "org_acme", "payments-eng")
	expect := func(who, tok, method, path string, body any, want int, contains string) {
		t.Helper()
		code, out := e.userCall(tok, method, path, body)
		if code != want || (contains != "" && !strings.Contains(out, contains)) {
			t.Fatalf("%s %s %s: got %d %s, want %d %q", who, method, path, code, out, want, contains)
		}
	}
	expect("bob", bob, "GET", "/v1/me", nil, 200, "")
	expect("dave", dave, "GET", "/v1/me", nil, 200, "")

	// An admin can't become owner by joining a team that holds the owner role,
	// or hand out admin by adding people to an admin team.
	expect("bob", bob, "POST", "/v1/teams/owners/members", map[string]string{"email": "bob@acme.dev"}, 403, "only an owner")
	expect("bob", bob, "POST", "/v1/teams/platform-admins/members", map[string]string{"email": "dave@acme.dev"}, 403, "only an owner")
	expect("bob", bob, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "dave@acme.dev", "role": "admin"}, 403, "")
	// Adding to a responder team is still an admin's job.
	expect("bob", bob, "POST", "/v1/teams/payments/members", map[string]string{"email": "bob@acme.dev"}, 200, "")

	// A team-scoped responder can't attach triggers to another team's service.
	rb := func(service string) string {
		return `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: payments-check
  title: Check payments
  team: payments
spec:
  target:
    agentSelector:
      env: staging
  triggers:
    - type: alert
      services: [` + service + `]
      match: 'alert.severity == "warning"'
      mode: one-click
  steps:
    - id: describe
      type: aws
      service: ecs
      action: DescribeServices
      input:
        cluster: staging
        services: [payments-api]
`
	}
	expect("dave", dave, "PUT", "/v1/runbooks/payments-check", rb("ledger"), 403, "service ledger")
	expect("dave", dave, "PUT", "/v1/runbooks/payments-check", rb("payments-api"), 200, "")

	// A removed member gets 403 with a clear reason (it used to surface as 401).
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE org_members SET status = 'removed' WHERE user_id = (SELECT id FROM nfx_org_user_by_email('dave@acme.dev'))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expect("dave-removed", dave, "GET", "/v1/me", nil, 403, "removed from this org")
	// Bad credentials are still a 401.
	expect("bogus-key", "nfx_not_a_real_key", "GET", "/v1/me", nil, 401, "invalid API key")

	// An oversized runbook is refused, not truncated and published.
	big := runbookYAML(t, "2m") + "# " + strings.Repeat("x", 520<<10) + "\n"
	expect("owner", e.key, "PUT", "/v1/runbooks/ecs-service-restart", big, 413, "512 KiB")
}
