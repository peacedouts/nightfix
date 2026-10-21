package e2e

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
)

// Emails name people in role bindings, team membership and Slack, so only
// an address the IdP verified may identify anyone. Mallory signs up with
// Alice's address and never verifies it.
func TestUnverifiedEmailCannotBecomeMemberOrMatchBinding(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.call("PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "payments"}, nil)

	claims := e.auth0.UserClaims("auth0|mallory", "alice@acme.dev", "org_acme")
	claims["https://nightfix.dev/email_verified"] = false
	e.expect("mallory (unverified)", e.auth0.Mint("RS256", claims), "GET", "/v1/me", nil, 401, "isn't verified")
	delete(claims, "https://nightfix.dev/email_verified")
	e.expect("mallory (no claim)", e.auth0.Mint("RS256", claims), "GET", "/v1/me", nil, 401, "isn't verified")
	// The standard claim counts too, and a false anywhere wins.
	claims["email_verified"], claims["https://nightfix.dev/email_verified"] = false, true
	e.expect("mallory (conflicting)", e.auth0.Mint("RS256", claims), "GET", "/v1/me", nil, 401, "isn't verified")

	// She never became a member, so a grant to Alice's address finds no one.
	if members := e.expect("owner", e.key, "GET", "/v1/members", nil, 200, ""); strings.Contains(members, "alice@acme.dev") {
		t.Fatalf("an unverified email became a member: %s", members)
	}
	e.expect("owner", e.key, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "alice@acme.dev", "role": "responder"},
		404, "verified email")

	// A member whose stored email was never verified (signed in before
	// verification was checked) matches nothing either, and can't link Slack.
	var carol string
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		if err := tx.QueryRow(`SELECT nfx_upsert_user('auth0|carol', 'carol@acme.dev', 'Carol', false)`).Scan(&carol); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO org_members (org_id, user_id, last_login_at) VALUES ($1,$2,now())`, e.rawOrg, carol); err != nil {
			return err
		}
		code := sha256.Sum256([]byte("ABCDEFGHJKLM"))
		_, err := tx.Exec(`INSERT INTO slack_link_codes (code_hash, org_id, user_id, expires_at) VALUES ($1,$2,$3, now() + interval '5 minutes')`,
			code[:], e.rawOrg, carol)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.expect("owner", e.key, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "carol@acme.dev", "role": "responder"},
		404, "verified email")
	e.expect("owner", e.key, "POST", "/v1/teams/payments/members", map[string]string{"email": "carol@acme.dev"}, 404, "verified email")
	var app map[string]string
	e.call("POST", "/v1/slack-apps", map[string]string{"signing_secret": slackSecret, "team_id": "T0ACME"}, &app)
	if out := e.slackCommand(app["commands_url"], "T0ACME", "U_CAROL", "carol", "link ABCD-EFGH-JKLM"); !strings.Contains(out, "isn't verified") {
		t.Fatalf("an unverified member linked Slack: %s", out)
	}

	// Signing in with verified emails provisions Alice and refreshes Carol;
	// then both can be granted roles by email.
	e.expect("alice", e.auth0.UserToken("auth0|alice", "alice@acme.dev", "org_acme"), "GET", "/v1/me", nil, 200, "alice@acme.dev")
	e.expect("carol", e.auth0.UserToken("auth0|carol", "carol@acme.dev", "org_acme"), "GET", "/v1/me", nil, 200, "carol@acme.dev")
	e.expect("owner", e.key, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "alice@acme.dev", "role": "responder"}, 200, "rb_")
	e.expect("owner", e.key, "POST", "/v1/teams/payments/members", map[string]string{"email": "carol@acme.dev"}, 200, "")
	var members []map[string]any
	json.Unmarshal([]byte(e.expect("owner", e.key, "GET", "/v1/members", nil, 200, "")), &members)
	for _, m := range members {
		if m["email_verified"] != true {
			t.Fatalf("members should all be verified now: %v", members)
		}
	}

	// Two accounts that both verified the same address: a grant by email is
	// refused rather than landing on whichever comes first.
	e.expect("alice (google)", e.auth0.UserToken("google-oauth2|alice", "alice@acme.dev", "org_acme"), "GET", "/v1/me", nil, 200, "")
	e.expect("owner", e.key, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "alice@acme.dev", "role": "viewer"},
		409, "more than one")
}
