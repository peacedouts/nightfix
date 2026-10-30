package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// gatedRunbook is the ECS restart runbook with an approval step in front of
// the restart. Without auto, it keeps only the manual trigger.
func gatedRunbook(t *testing.T, name, approval string, auto bool) string {
	src := runbookYAML(t, "2m")
	src = strings.Replace(src, "  name: ecs-service-restart\n", "  name: "+name+"\n", 1)
	if !auto {
		i, j := strings.Index(src, "    - type: alert\n"), strings.Index(src, "    - type: manual\n")
		src = src[:i] + src[j:]
	}
	return strings.Replace(src, "    - id: restart\n", "    - id: approve\n      name: Approve the restart\n      type: approval\n"+approval+"    - id: restart\n", 1)
}

type people struct{ alice, bob, dave, carol string }

// Alice and Bob are platform admins, Dave is an on-call responder, Carol has
// no role (a viewer).
func (e *env) people() people {
	e.call("PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "platform-admins", "auth0_group": "platform"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "oncall", "auth0_group": "oncall"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "platform-admins", "role": "admin"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "oncall", "role": "responder"}, nil)
	return people{
		alice: e.auth0.UserToken("auth0|alice", "alice@acme.dev", "org_acme", "platform"),
		bob:   e.auth0.UserToken("auth0|bob", "bob@acme.dev", "org_acme", "platform"),
		dave:  e.auth0.UserToken("auth0|dave", "dave@acme.dev", "org_acme", "oncall"),
		carol: e.auth0.UserToken("auth0|carol", "carol@acme.dev", "org_acme"),
	}
}

func (e *env) expect(who, tok, method, path string, body any, want int, contains string) string {
	e.t.Helper()
	code, out := e.userCall(tok, method, path, body)
	if code != want || (contains != "" && !strings.Contains(out, contains)) {
		e.t.Fatalf("%s %s %s: got %d %s, want %d %q", who, method, path, code, out, want, contains)
	}
	return out
}

func (e *env) run(id string) map[string]any {
	var run map[string]any
	e.call("GET", "/v1/runs/"+id, nil, &run)
	return run
}

func (e *env) waitRun(id, status string) map[string]any {
	e.t.Helper()
	var run map[string]any
	e.waitFor("run "+status, 30*time.Second, func() bool {
		run = e.run(id)
		return run["status"] == status
	})
	return run
}

func (e *env) startRun(tok, runbook string) string {
	e.t.Helper()
	out := e.expect("starter", tok, "POST", "/v1/runs", map[string]any{"runbook": runbook,
		"params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}}, 200, "run_")
	var r map[string]string
	json.Unmarshal([]byte(out), &r)
	return r["id"]
}

// ageLogin pretends the member last signed in to this org age ago.
func (e *env) ageLogin(email string, age time.Duration) {
	e.t.Helper()
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE org_members SET last_login_at = now() - $2::interval
			WHERE user_id = (SELECT id FROM nfx_org_users() WHERE email = $1)`, email, fmt.Sprintf("%d seconds", int(age.Seconds())))
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

// slackOn returns the texts of messages that arrived on a test channel.
func (e *env) slackOn(channel string) []string {
	raw, _ := e.stub.SlackState()
	var out []string
	for _, m := range raw {
		if m["_channel"] == channel {
			b, _ := json.Marshal(m["blocks"])
			out = append(out, fmt.Sprint(m["text"])+" "+string(b))
		}
	}
	return out
}

func (e *env) waitSlackOn(channel, want string) {
	e.t.Helper()
	e.waitFor("slack message on "+channel+" containing "+want, 10*time.Second, func() bool {
		for _, m := range e.slackOn(channel) {
			if strings.Contains(m, want) {
				return true
			}
		}
		return false
	})
}

func countCalls(calls []string, c string) int {
	n := 0
	for _, x := range calls {
		if x == c {
			n++
		}
	}
	return n
}

// A gated run waits, refuses everyone who isn't allowed to approve it, and
// continues once an eligible person approves.
func TestApprovalGatesARun(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      fromRoles: [Admin]\n      excludeRequester: true\n      expiresAfter: 10m\n", false)), nil)
	// Runs outside an incident ask in the runbook team's channel (platform),
	// falling back to the org default.
	e.call("POST", "/v1/teams", map[string]string{"slug": "platform"}, nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"team": "platform", "url": e.stubURL + "/slack?channel=platform"}, nil)
	var channels []map[string]any
	e.call("GET", "/v1/approval-channels", nil, &channels)
	if len(channels) != 2 || strings.Contains(mustJSON(channels), "/slack") {
		t.Fatalf("channels should be listed without their webhook URLs: %v", channels)
	}

	e.expect("api key start", e.key, "POST", "/v1/runs", map[string]any{"runbook": "ecs-restart-gated",
		"params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}}, 403, "a person has to start it")
	runID := e.startRun(who.alice, "ecs-restart-gated")
	e.waitRun(runID, "awaiting_approval")
	calls, _, _ := e.stub.Snapshot()
	if countCalls(calls, "ecs:DescribeServices") != 1 || contains(calls, "ecs:UpdateService") {
		t.Fatalf("only the steps before the approval should have run: %v", calls)
	}
	e.waitSlackOn("platform", "alice@acme.dev started `ecs-restart-gated`")
	e.waitSlackOn("platform", "/steps/approve/approve") // no Slack app yet: API instructions instead of buttons
	if got := e.slackOn("default"); len(got) != 0 {
		t.Fatalf("the team channel should take precedence over the org default: %v", got)
	}
	var pending []map[string]any
	e.call("GET", "/v1/approvals", nil, &pending)
	if len(pending) != 1 || pending[0]["step"] != "approve" || pending[0]["run"] != runID {
		t.Fatalf("expected one pending approval, got %v", pending)
	}

	path := "/v1/runs/" + runID + "/steps/approve/approve"
	e.expect("api key", e.key, "POST", path, nil, 403, "from a person")
	e.expect("alice (requester)", who.alice, "POST", path, nil, 403, "someone else's approval")
	e.expect("carol (viewer)", who.carol, "POST", path, nil, 403, "")
	e.expect("dave (responder)", who.dave, "POST", path, nil, 403, "needs the Admin role")
	e.expect("unknown step", who.bob, "POST", "/v1/runs/"+runID+"/steps/restart/approve", nil, 404, "")

	// The database refuses a requester's vote even if the API check were skipped.
	var me map[string]any
	json.Unmarshal([]byte(e.expect("alice", who.alice, "GET", "/v1/me", nil, 200, "")), &me)
	gate, _ := ids.Decode("apr", fmt.Sprint(pending[0]["gate"]))
	err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO approvals (id, org_id, gate_id, approver_id, approver_email, decision, via)
			VALUES ($1,$2,$3,$4,'alice@acme.dev','approved','api')`, ids.NewString(), e.rawOrg, gate, me["principal"])
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "requester cannot approve") {
		t.Fatalf("database should refuse the requester's approval, got %v", err)
	}

	e.expect("bob", who.bob, "POST", path, map[string]string{"comment": "checked the dashboards"}, 200, `"status": "approved"`)
	e.expect("bob again", who.bob, "POST", path, nil, 409, "already approved")

	run := e.waitRun(runID, "succeeded")
	e.waitSlackOn("platform", "approved by bob@acme.dev (1 of 1)")
	calls, _, _ = e.stub.Snapshot()
	if !contains(calls, "ecs:UpdateService") {
		t.Fatalf("the restart should have run after approval: %v", calls)
	}
	gates := run["approvals"].([]any)
	g := gates[0].(map[string]any)
	d := g["decisions"].([]any)[0].(map[string]any)
	if g["status"] != "approved" || d["by"] != "bob@acme.dev" || d["via"] != "api" || d["comment"] != "checked the dashboards" {
		t.Fatalf("run should record bob's approval: %v", g)
	}
	var audit []map[string]any
	e.call("GET", "/v1/audit-events", nil, &audit)
	if !strings.Contains(mustJSON(audit), "approval.approved") || !strings.Contains(mustJSON(audit), "approval.requested") {
		t.Fatal("approvals should be audited")
	}
}

// One rejection cancels the run; an approval nobody gives times it out.
// Neither one reaches the restart.
func TestApprovalRejectionAndExpiry(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	who := e.people()
	e.callRaw("PUT", "/v1/runbooks/ecs-restart-gated", []byte(gatedRunbook(t, "ecs-restart-gated",
		"      count: 2\n      fromRoles: [Responder]\n      expiresAfter: 10m\n", false)), nil)
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)
	e.expect("bob (admin, not owner)", who.bob, "PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack"}, 200, "")
	e.call("PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack?channel=default"}, nil)
	e.expect("dave (responder)", who.dave, "PUT", "/v1/approval-channels", map[string]string{"url": e.stubURL + "/slack"}, 403, "")

	runA := e.startRun(who.alice, "ecs-restart-gated")
	e.waitRun(runA, "awaiting_approval")
	path := "/v1/runs/" + runA + "/steps/approve/"
	e.expect("dave", who.dave, "POST", path+"approve", nil, 200, `"status": "pending"`)
	e.waitSlackOn("default", "Approval needed")
	e.expect("bob", who.bob, "POST", path+"reject", map[string]string{"comment": "not during the sale"}, 200, `"status": "rejected"`)
	e.waitSlackOn("default", "rejected by bob@acme.dev: not during the sale")
	run := e.waitRun(runA, "cancelled")
	if !strings.Contains(fmt.Sprint(run["error"]), "rejected by bob@acme.dev: not during the sale") {
		t.Fatalf("run error should say who rejected it and why: %v", run["error"])
	}
	e.expect("alice after reject", who.alice, "POST", path+"approve", nil, 409, "already rejected")

	runB := e.startRun(who.alice, "ecs-restart-gated")
	e.waitRun(runB, "awaiting_approval")
	// Fast-forward the clock on the gate instead of waiting 10 minutes.
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE approval_gates SET expires_at = now() WHERE status = 'pending'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	run = e.waitRun(runB, "timed_out")
	if !strings.Contains(fmt.Sprint(run["error"]), "expired with 0 of 2 approvals") {
		t.Fatalf("unexpected error: %v", run["error"])
	}
	e.expect("dave after expiry", who.dave, "POST", "/v1/runs/"+runB+"/steps/approve/approve", nil, 409, "")

	calls, _, _ := e.stub.Snapshot()
	if contains(calls, "ecs:UpdateService") {
		t.Fatalf("nothing should have been restarted: %v", calls)
	}
}

const slackSecret = "8f742231b10e8888abcd99yyyzzz85a5"

func (e *env) slackClick(app, secret, team, user, username, action, gate string, at time.Time) int {
	e.t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"type": "block_actions", "team": map[string]string{"id": team},
		"user":         map[string]string{"id": user, "username": username},
		"actions":      []map[string]string{{"action_id": action, "value": gate}},
		"response_url": e.stubURL + "/slack/response/T0ACME/1/xyz",
	})
	body := "payload=" + url.QueryEscape(string(payload))
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "v0:%s:%s", ts, body)
	req, _ := http.NewRequest("POST", e.api+app, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (e *env) slackSigned(path, secret, body string) (int, string) {
	e.t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "v0:%s:%s", ts, body)
	req, _ := http.NewRequest("POST", e.api+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// slackCommand types "/nightfix <text>" in Slack as the given user.
func (e *env) slackCommand(path, team, user, username, text string) string {
	e.t.Helper()
	code, out := e.slackSigned(path, slackSecret, url.Values{"team_id": {team}, "user_id": {user}, "user_name": {username},
		"command": {"/nightfix"}, "text": {text}}.Encode())
	if code != 200 {
		e.t.Fatalf("slash command: %d %s", code, out)
	}
	return out
}

func (e *env) waitReply(n int) string {
	e.t.Helper()
	var replies []string
	e.waitFor(fmt.Sprintf("slack reply #%d", n), 10*time.Second, func() bool {
		_, replies = e.stub.SlackState()
		return len(replies) >= n
	})
	return replies[n-1]
}

var linkCodeRe = regexp.MustCompile(`[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}`)

// The headline: an auto-remediation that needs approval pages right away
// (nobody waits on a held page), on-call approves from Slack, and the fix runs.
func TestAutoRemediationWaitsForSlackApproval(t *testing.T) {
	e := setup(t, gatedRunbook(t, "ecs-service-restart", "      fromRoles: [Responder]\n      expiresAfter: 10m\n", true))
	who := e.people()
	var app map[string]string
	e.call("POST", "/v1/slack-apps", map[string]string{"signing_secret": slackSecret, "team_id": "T0ACME"}, &app)
	appPath, cmdPath := app["interactivity_url"], app["commands_url"]

	e.alarm("ALARM", "checkout-api")
	e.waitFor("page for the approval", 15*time.Second, func() bool {
		_, _, pd := e.stub.Snapshot()
		return len(pd) == 1
	})
	inc := e.incident(1)
	if status(inc) != "triggered" || inc["paged"] != true {
		t.Fatalf("an approval should end the paging hold: %v", inc)
	}
	tl := strings.Join(e.timeline(1), "\n")
	if !strings.Contains(tl, "approval.requested") || !strings.Contains(tl, "needs an approval") {
		t.Fatalf("timeline should explain the page:\n%s", tl)
	}

	var gate string
	e.waitFor("approval message with buttons", 10*time.Second, func() bool {
		raw, _ := e.stub.SlackState()
		for _, m := range raw {
			b, _ := json.Marshal(m["blocks"])
			if strings.Contains(string(b), "nfx_approve") {
				gate = regexp.MustCompile(`apr_[0-9A-Za-z]+`).FindString(string(b))
			}
		}
		return gate != ""
	})

	now := time.Now()
	// Forged or replayed clicks are refused before anything else happens.
	if c := e.slackClick(appPath, "not-the-secret-xxxxxxxx", "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, now); c != 401 {
		t.Fatalf("forged signature: got %d", c)
	}
	if c := e.slackClick(appPath, slackSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, now.Add(-10*time.Minute)); c != 401 {
		t.Fatalf("stale timestamp: got %d", c)
	}
	if c := e.slackClick(appPath, slackSecret, "T0OTHER", "U_DAVE", "dave", "nfx_approve", gate, now); c != 403 {
		t.Fatalf("other workspace: got %d", c)
	}

	// First click from an unlinked Slack user records nothing and says how to link.
	if c := e.slackClick(appPath, slackSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, now); c != 200 {
		t.Fatalf("click: got %d", c)
	}
	if reply := e.waitReply(1); !strings.Contains(reply, "isn't linked") || !strings.Contains(reply, "/nightfix link") {
		t.Fatalf("expected linking instructions, got %q", reply)
	}
	if run := e.run(fmt.Sprint(inc["remediation_run"])); run["status"] != "awaiting_approval" {
		t.Fatalf("an unlinked click must not approve: %v", run["status"])
	}

	// Linking goes the safe way round: the code comes from Nightfix, signed in
	// as dave, and dave types it into Slack.
	e.expect("api key code", e.key, "POST", "/v1/me/slack-link-code", nil, 403, "")
	var issued map[string]string
	json.Unmarshal([]byte(e.expect("dave gets a code", who.dave, "POST", "/v1/me/slack-link-code", nil, 200, "never share")), &issued)
	code := issued["code"]
	if !linkCodeRe.MatchString(code) {
		t.Fatalf("bad code %q", code)
	}
	if c, _ := e.slackSigned(cmdPath, "not-the-secret-xxxxxxxx", "team_id=T0ACME&user_id=U_DAVE&text=link+"+code); c != 401 {
		t.Fatalf("forged slash command: got %d", c)
	}
	if out := e.slackCommand(cmdPath, "T0ACME", "U_DAVE", "dave", "link "+strings.ToLower(code)); !strings.Contains(out, "approves as dave@acme.dev") {
		t.Fatalf("link: %s", out)
	}
	if out := e.slackCommand(cmdPath, "T0ACME", "U_MALLORY", "mallory", "link "+code); !strings.Contains(out, "unknown or expired") {
		t.Fatalf("a used code must not link again: %s", out)
	}
	if out := e.slackCommand(cmdPath, "T0ACME", "U_DAVE", "dave", "help"); !strings.Contains(out, "Usage") {
		t.Fatalf("usage: %s", out)
	}

	// A Slack app's signing secret speaks for everyone linked through it, so
	// an admin can't register one, a workspace has one active app, and a
	// second app (even an owner's) can't use the links made through the
	// first: a click through it, as dave, records nothing.
	const rogueSecret = "rogue-signing-secret-chosen-by-the-registrar"
	e.expect("admin registers a Slack app", who.alice, "POST", "/v1/slack-apps",
		map[string]string{"signing_secret": rogueSecret, "team_id": "T0ACME"}, 403, "")
	e.expect("second app for the workspace", e.key, "POST", "/v1/slack-apps",
		map[string]string{"signing_secret": rogueSecret, "team_id": "T0ACME"}, 409, "archive it first")
	e.expect("Enterprise Grid ID", e.key, "POST", "/v1/slack-apps",
		map[string]string{"signing_secret": rogueSecret, "team_id": "E0ACME"}, 400, "team_id")
	var rogue map[string]string
	e.call("POST", "/v1/slack-apps", map[string]string{"signing_secret": rogueSecret, "team_id": "T0ROGUE"}, &rogue)
	if c := e.slackClick(rogue["interactivity_url"], rogueSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, time.Now()); c != 403 {
		t.Fatalf("click claiming another workspace through the second app: got %d, want 403", c)
	}
	if c := e.slackClick(rogue["interactivity_url"], rogueSecret, "T0ROGUE", "U_DAVE", "dave", "nfx_approve", gate, time.Now()); c != 200 {
		t.Fatalf("click through the second app: got %d", c)
	}
	if reply := e.waitReply(2); !strings.Contains(reply, "isn't linked") {
		t.Fatalf("a second app used dave's link: %q", reply)
	}
	if run := e.run(fmt.Sprint(inc["remediation_run"])); run["status"] != "awaiting_approval" {
		t.Fatalf("a click through another app decided the gate: %v", run["status"])
	}
	// Apps are listed, and archiving one stops its requests at once.
	e.expect("list Slack apps", who.alice, "GET", "/v1/slack-apps", nil, 200, `"linked_users": 1`)
	e.expect("admin archives", who.alice, "POST", "/v1/slack-apps/"+rogue["id"]+"/archive", nil, 403, "")
	e.call("POST", "/v1/slack-apps/"+rogue["id"]+"/archive", nil, nil)
	if c := e.slackClick(rogue["interactivity_url"], rogueSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, time.Now()); c != 404 {
		t.Fatalf("click through an archived app: got %d", c)
	}
	e.expect("register without a workspace", e.key, "POST", "/v1/slack-apps", map[string]string{"signing_secret": rogueSecret}, 400, "team_id")

	// Group membership is refreshed at sign-in, so a stale sign-in can't approve.
	e.ageLogin("dave@acme.dev", 8*24*time.Hour)
	e.slackClick(appPath, slackSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, time.Now())
	if reply := e.waitReply(3); !strings.Contains(reply, "haven't signed in") {
		t.Fatalf("unexpected reply %q", reply)
	}
	e.expect("dave signs in", who.dave, "GET", "/v1/me", nil, 200, "")

	if c := e.slackClick(appPath, slackSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, time.Now()); c != 200 {
		t.Fatalf("click: got %d", c)
	}
	if reply := e.waitReply(4); !strings.Contains(reply, "You approved") {
		t.Fatalf("unexpected reply %q", reply)
	}
	run := e.waitRun(fmt.Sprint(inc["remediation_run"]), "succeeded")
	d := run["approvals"].([]any)[0].(map[string]any)["decisions"].([]any)[0].(map[string]any)
	if d["by"] != "dave@acme.dev" || d["via"] != "slack" {
		t.Fatalf("approval should be recorded as dave via Slack: %v", d)
	}
	// A second click after the decision gets a clear answer, not an error page.
	e.slackClick(appPath, slackSecret, "T0ACME", "U_DAVE", "dave", "nfx_approve", gate, time.Now())
	if reply := e.waitReply(5); !strings.Contains(reply, "already approved") {
		t.Fatalf("unexpected reply %q", reply)
	}

	e.alarm("OK", "checkout-api")
	e.waitFor("upstream page resolved", 10*time.Second, func() bool {
		_, _, pd := e.stub.Snapshot()
		return len(pd) == 2 && pd[1]["event_action"] == "resolve"
	})
	for _, l := range e.timeline(1) {
		t.Log("  " + l)
	}
}
