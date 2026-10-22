package e2e_test

// Alert routing, the incident lifecycle (acknowledge, resolve, reopen,
// severity) and the REST endpoints around them, including who may use them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// lifecycleHarness is an ingestHarness with Auth0 login, a Slack target that
// records what it was sent, and an org linked to the Auth0 organization
// org_acme. Services: checkout-api (team payments, the webhook integration's
// default, with PagerDuty and Slack targets) and ledger (team finance).
type lifecycleHarness struct {
	*ingestHarness
	idp   *auth0test.Issuer
	slack []string // guarded by pdMu
}

func setupLifecycle(t *testing.T) *lifecycleHarness {
	t.Helper()
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, err := controlplane.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	idp := auth0test.New(t)
	x := &ingestHarness{t: t}
	h := &lifecycleHarness{ingestHarness: x, idp: idp}
	notify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		x.pdMu.Lock()
		defer x.pdMu.Unlock()
		if r.URL.Path == "/slack" {
			h.slack = append(h.slack, fmt.Sprint(ev["text"]))
			return
		}
		x.pd = append(x.pd, fmt.Sprint(ev["event_action"]))
	}))
	t.Cleanup(notify.Close)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	x.srv = controlplane.New(pool, sealer, ca, controlplane.Config{PublicIngestURL: "http://ingest", AllowPrivateTargets: true,
		Auth0: controlplane.Auth0Config{Verifier: &auth0.Verifier{Issuer: idp.Issuer, Audience: idp.Audience, JWKSURL: idp.Srv.URL}}}, log)
	apiSrv := httptest.NewServer(x.srv.APIHandler())
	t.Cleanup(apiSrv.Close)
	ingSrv := httptest.NewServer(x.srv.IngestHandler())
	t.Cleanup(ingSrv.Close)
	x.api, x.ingBase = apiSrv.URL, ingSrv.URL
	org, err := x.srv.CreateOrg(context.Background(), "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	x.key, x.orgID = org.APIKey, org.OrgID
	h.must("POST", "/v1/services", map[string]any{"name": "checkout-api", "team": "payments"})
	h.must("POST", "/v1/services", map[string]any{"name": "ledger", "team": "finance"})
	h.must("POST", "/v1/services/checkout-api/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "k", "events_url": notify.URL + "/pd"})
	h.must("POST", "/v1/services/checkout-api/escalation-targets", map[string]any{"type": "slack", "url": notify.URL + "/slack"})
	var integ map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "wh", "default_service": "checkout-api"}, &integ)
	x.ingest = strings.Replace(integ["ingest_url"], "http://ingest", ingSrv.URL, 1)
	x.secret = integ["signing_secret"]
	h.must("PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"})
	return h
}

// must makes an owner (API key) call that has to succeed.
func (h *lifecycleHarness) must(method, path string, body any) {
	h.t.Helper()
	if code := h.call(method, path, body, nil); code/100 != 2 {
		h.t.Fatalf("%s %s: %d", method, path, code)
	}
}

// as makes a call with a bearer token (an Auth0 access token or an API key).
func (h *lifecycleHarness) as(tok, method, path string, body any) (int, string) {
	h.t.Helper()
	var b []byte
	switch v := body.(type) {
	case nil:
	case string:
		b = []byte(v)
	default:
		b, _ = json.Marshal(v)
	}
	req, _ := http.NewRequest(method, h.api+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *lifecycleHarness) expect(who, tok, method, path string, body any, want int, contains string) string {
	h.t.Helper()
	code, out := h.as(tok, method, path, body)
	if code != want || (contains != "" && !strings.Contains(out, contains)) {
		h.t.Fatalf("%s %s %s: got %d %s, want %d %q", who, method, path, code, out, want, contains)
	}
	return out
}

func (h *lifecycleHarness) user(name string, groups ...string) string {
	return h.idp.UserToken("auth0|"+name, name+"@acme.dev", "org_acme", groups...)
}

// fire sends a webhook alert and processes it.
func (h *lifecycleHarness) fire(body map[string]any) {
	h.t.Helper()
	if code := h.send(body); code != 202 {
		h.t.Fatalf("ingest: %d", code)
	}
	h.tick()
}

func (h *lifecycleHarness) incident(n int) map[string]any {
	h.t.Helper()
	var inc map[string]any
	if code := h.call("GET", fmt.Sprintf("/v1/incidents/%d", n), nil, &inc); code != 200 {
		h.t.Fatalf("incident #%d: %d", n, code)
	}
	return inc
}

func (h *lifecycleHarness) timelineTypes(n int) []string {
	h.t.Helper()
	var tl []map[string]any
	h.call("GET", fmt.Sprintf("/v1/incidents/%d/timeline", n), nil, &tl)
	var out []string
	for _, e := range tl {
		out = append(out, fmt.Sprint(e["type"]))
	}
	return out
}

func (h *lifecycleHarness) timelineMessages(n int, typ string) []string {
	h.t.Helper()
	var tl []map[string]any
	h.call("GET", fmt.Sprintf("/v1/incidents/%d/timeline", n), nil, &tl)
	var out []string
	for _, e := range tl {
		if e["type"] == typ {
			out = append(out, fmt.Sprint(e["actor"], ": ", e["message"]))
		}
	}
	return out
}

// delivered ticks until notifications are delivered and returns what
// PagerDuty and Slack received.
func (h *lifecycleHarness) delivered() (pd, slack []string) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.tick()
		if h.count(`SELECT count(*) FROM notifications WHERE status = 'pending'`) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.pdMu.Lock()
	defer h.pdMu.Unlock()
	return append([]string(nil), h.pd...), append([]string(nil), h.slack...)
}

func countOf(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

// Ordered CEL rules: first match wins, a rule that errors on an alert doesn't
// match, suppress stores the alert without an incident, and anything left
// goes to the integration's default service (the catch-all if it has none).
func TestRoutingRulesRouteSuppressAndFallBack(t *testing.T) {
	h := setupLifecycle(t)
	h.must("POST", "/v1/services", map[string]any{"name": "databases"})
	var res map[string]any
	if code := h.call("PUT", "/v1/routing-rules", []map[string]string{
		// Errors (no such key) on alerts without a team label.
		{"match": `alert.labels.team == "dba"`, "service": "databases"},
		{"match": `alert.severity == "info"`, "action": "suppress"},
		{"match": `alert.source == "rds"`, "service": "databases", "action": "route"},
	}, &res); code != 200 || res["rules"] != float64(3) {
		t.Fatalf("PUT routing rules: %d %v", code, res)
	}

	// Rule 1 matches.
	h.fire(map[string]any{"dedup_key": "dba", "summary": "replica lag", "labels": map[string]string{"team": "dba"}})
	// Rule 1 errors on this alert (no team label), so rule 2 suppresses it.
	h.fire(map[string]any{"dedup_key": "noise", "summary": "fyi", "severity": "info"})
	// First match wins: rule 1 before the suppress rule.
	h.fire(map[string]any{"dedup_key": "dba-info", "summary": "vacuum ran", "severity": "info", "labels": map[string]string{"team": "dba"}})
	// Rule 3, after rule 1 errored.
	h.fire(map[string]any{"dedup_key": "rds", "summary": "rds cpu", "source": "rds"})
	// No rule matches: the integration's default service.
	h.fire(map[string]any{"dedup_key": "web", "summary": "5xx", "labels": map[string]string{"team": "web"}})
	// An integration created without a default service routes to the catch-all.
	var integ map[string]string
	h.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "no-default"}, &integ)
	if code := h.sendTo(strings.Replace(integ["ingest_url"], "http://ingest", h.ingBase, 1), integ["signing_secret"],
		map[string]any{"dedup_key": "orphan", "summary": "orphan"}); code != 202 {
		t.Fatalf("ingest: %d", code)
	}
	h.tick()

	bySvc := map[string]int{}
	for _, inc := range h.incidents() {
		bySvc[fmt.Sprint(inc["service"])]++
	}
	if len(bySvc) != 3 || bySvc["databases"] != 1 || bySvc["checkout-api"] != 1 || bySvc["catch-all"] != 1 {
		t.Fatalf("incidents by service: %v; want one each on databases, checkout-api and catch-all", bySvc)
	}
	// Both database alerts (rule 1 and rule 3) are on the one databases incident.
	if n := h.count(`SELECT count(*) FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id JOIN services s ON s.id = a.service_id
		WHERE s.name = 'databases'`); n != 3 {
		t.Fatalf("databases incident has %d alerts, want 3 (dba, dba-info, rds)", n)
	}
	// The suppressed alert is stored and flagged, but joined no incident.
	if n := h.count(`SELECT count(*) FROM alerts a WHERE a.suppressed AND a.summary = 'fyi'
		AND NOT EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id)`); n != 1 {
		t.Fatalf("suppressed alert: %d stored without an incident, want 1", n)
	}
	// It stays suppressed when it fires again.
	h.fire(map[string]any{"dedup_key": "noise", "summary": "fyi", "severity": "info"})
	if n := h.count(`SELECT count(*) FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id WHERE a.summary = 'fyi'`); n != 0 {
		t.Fatal("a repeat of a suppressed alert joined an incident")
	}

	// Replacing the rules with none sends everything to the default service.
	h.must("PUT", "/v1/routing-rules", []map[string]string{})
	h.fire(map[string]any{"dedup_key": "dba-2", "summary": "replica lag 2", "labels": map[string]string{"team": "dba"}})
	if n := h.count(`SELECT count(*) FROM alerts a JOIN services s ON s.id = a.service_id
		WHERE a.summary = 'replica lag 2' AND s.name = 'checkout-api'`); n != 1 {
		t.Fatal("with no rules, the alert should route to the integration's default service")
	}
}

// Bad rule sets are refused whole at PUT time with 400, and a refused PUT
// leaves the previous rules in force. Replacements are audited.
func TestRoutingRulesPutIsValidatedAtomicAndAudited(t *testing.T) {
	h := setupLifecycle(t)
	good := map[string]string{"match": `alert.labels.team == "finance"`, "service": "ledger"}
	h.must("PUT", "/v1/routing-rules", []map[string]string{good})
	audits := func() int {
		return h.count(`SELECT count(*) FROM audit_events WHERE action = 'routing_rules.replace'`)
	}
	if audits() != 1 {
		t.Fatalf("routing rule replacement audited %d times, want 1", audits())
	}

	for name, rules := range map[string]any{
		"unknown service":       []map[string]string{good, {"match": "true", "service": "no-such-service"}},
		"route without service": []map[string]string{good, {"match": "true"}},
		"invalid CEL":           []map[string]string{good, {"match": `alert.labels.team ==`, "service": "ledger"}},
		"not a condition":       []map[string]string{good, {"match": `size(alert.labels)`, "service": "ledger"}},
		"empty match":           []map[string]string{good, {"match": "", "service": "ledger"}},
		"bad action":            []map[string]string{good, {"match": "true", "action": "drop"}},
		"suppress with service": []map[string]string{good, {"match": "true", "action": "suppress", "service": "ledger"}},
		"unknown field":         []map[string]string{{"match": "true", "service": "ledger", "priority": "1"}},
		"not a list":            map[string]string{"match": "true"},
	} {
		code, out := h.as(h.key, "PUT", "/v1/routing-rules", rules)
		if code != 400 {
			t.Errorf("%s: got %d %s, want 400", name, code, out)
		}
	}
	code, out := h.as(h.key, "PUT", "/v1/routing-rules", []map[string]string{good, {"match": "true", "service": "nope"}})
	if code != 400 || !strings.Contains(out, "rule 1") || !strings.Contains(out, "nope") {
		t.Errorf("unknown service: %d %s; want 400 naming the rule and the service", code, out)
	}

	// None of the refused PUTs changed anything.
	if n := h.count(`SELECT count(*) FROM routing_rules`); n != 1 {
		t.Fatalf("%d routing rules after refused PUTs, want the original 1", n)
	}
	if audits() != 1 {
		t.Fatalf("refused PUTs were audited: %d replacements recorded", audits())
	}
	h.fire(map[string]any{"dedup_key": "fin", "summary": "ledger drift", "labels": map[string]string{"team": "finance"}})
	if inc := h.incident(1); inc["service"] != "ledger" {
		t.Fatalf("the original rule should still route to ledger: %v", inc)
	}

	// Only org-wide admins may replace routing rules.
	h.must("POST", "/v1/teams", map[string]string{"slug": "payments", "auth0_group": "payments-eng"})
	h.must("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "payments", "role": "responder"})
	h.expect("responder", h.user("dave", "payments-eng"), "PUT", "/v1/routing-rules", []map[string]string{}, 403, "admin")
	if n := h.count(`SELECT count(*) FROM routing_rules`); n != 1 {
		t.Fatal("a responder replaced the routing rules")
	}
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

// An incident's severity is the highest of its alerts': raised when a more
// severe alert joins or an attached alert's severity rises, never lowered.
// An unknown severity counts as high.
func TestIncidentSeverityIsHighestOfItsAlerts(t *testing.T) {
	h := setupLifecycle(t)
	h.fire(map[string]any{"dedup_key": "A", "summary": "A", "severity": "sev1-ish"})
	if sev := h.incident(1)["severity"]; sev != "high" {
		t.Fatalf("an unknown severity should count as high, got %v", sev)
	}
	h.fire(map[string]any{"dedup_key": "B", "summary": "B", "severity": "warning"})
	if sev := h.incident(1)["severity"]; sev != "high" {
		t.Fatalf("a less severe alert joining lowered the incident to %v", sev)
	}
	// The attached alert B re-fires as critical.
	h.fire(map[string]any{"dedup_key": "B", "summary": "B worse", "severity": "critical"})
	if sev := h.incident(1)["severity"]; sev != "critical" {
		t.Fatalf("an attached alert rising to critical should raise the incident, got %v", sev)
	}
	// And drops back: the incident keeps its highest severity.
	h.fire(map[string]any{"dedup_key": "B", "summary": "B better", "severity": "info"})
	h.fire(map[string]any{"dedup_key": "C", "summary": "C", "severity": "info"})
	if sev := h.incident(1)["severity"]; sev != "critical" {
		t.Fatalf("incident severity dropped to %v", sev)
	}
	if got := len(h.incidents()); got != 1 {
		t.Fatalf("%d incidents, want 1 (one open incident per service)", got)
	}
	if msgs := h.timelineMessages(1, "incident.severity"); len(msgs) != 1 || !strings.Contains(msgs[0], "from high to critical") {
		t.Fatalf("severity timeline: %v", msgs)
	}
}

// ---------------------------------------------------------------------------
// Acknowledge, resolve, reopen
// ---------------------------------------------------------------------------

func setupResponders(h *lifecycleHarness) (dave, erin, carol string) {
	h.must("POST", "/v1/teams", map[string]string{"slug": "payments", "auth0_group": "payments-eng"})
	h.must("POST", "/v1/teams", map[string]string{"slug": "finance", "auth0_group": "finance-eng"})
	h.must("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "payments", "role": "responder",
		"scope": map[string]any{"teams": []string{"payments"}}})
	h.must("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "finance", "role": "responder",
		"scope": map[string]any{"teams": []string{"finance"}}})
	return h.user("dave", "payments-eng"), h.user("erin", "finance-eng"), h.user("carol")
}

func TestAcknowledgeIncident(t *testing.T) {
	h := setupLifecycle(t)
	dave, erin, carol := setupResponders(h)
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	if inc := h.incident(1); inc["status"] != "triggered" || inc["paged"] != true {
		t.Fatalf("new incident: %v", inc)
	}
	pd, _ := h.delivered()
	if strings.Join(pd, ",") != "trigger" {
		t.Fatalf("PagerDuty got %v, want one trigger", pd)
	}

	// Viewers and responders scoped to another team can't acknowledge.
	h.expect("carol (viewer)", carol, "POST", "/v1/incidents/1/acknowledge", nil, 403, "")
	h.expect("erin (finance responder)", erin, "POST", "/v1/incidents/1/acknowledge", nil, 403, "team payments")
	if st := h.incident(1)["status"]; st != "triggered" {
		t.Fatalf("a refused ack changed the incident to %v", st)
	}

	// A responder within scope can.
	h.expect("dave", dave, "POST", "/v1/incidents/1/acknowledge", nil, 200, `"ok": true`)
	if st := h.incident(1)["status"]; st != "acknowledged" {
		t.Fatalf("status after ack: %v", st)
	}
	acks := h.timelineMessages(1, "incident.acknowledged")
	if len(acks) != 1 || !strings.HasPrefix(acks[0], "user: ") || !strings.Contains(acks[0], "dave@acme.dev") {
		t.Fatalf("ack timeline: %v; want one entry by dave", acks)
	}
	var ackAt time.Time
	h.srv.DB.WithOrg(context.Background(), h.orgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT ack_at FROM incidents WHERE number = 1`).Scan(&ackAt)
	})
	if ackAt.IsZero() {
		t.Fatal("ack_at not set")
	}

	// Acknowledging again is a no-op: the first ack stands.
	time.Sleep(10 * time.Millisecond)
	h.expect("dave again", dave, "POST", "/v1/incidents/1/acknowledge", nil, 200, "")
	h.expect("owner", h.key, "POST", "/v1/incidents/1/acknowledge", nil, 200, "")
	if acks := h.timelineMessages(1, "incident.acknowledged"); len(acks) != 1 {
		t.Fatalf("re-acknowledging added timeline entries: %v", acks)
	}
	var ackAt2 time.Time
	h.srv.DB.WithOrg(context.Background(), h.orgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT ack_at FROM incidents WHERE number = 1`).Scan(&ackAt2)
	})
	if !ackAt2.Equal(ackAt) {
		t.Fatalf("re-acknowledging moved ack_at from %v to %v", ackAt, ackAt2)
	}

	// The Slack channel that was paged hears who has it; PagerDuty isn't paged again.
	pd, slack := h.delivered()
	if n := countOf(pd, "trigger"); n != 1 {
		t.Fatalf("PagerDuty got %v after the ack", pd)
	}
	found := 0
	for _, m := range slack {
		if strings.Contains(m, "Acknowledged by dave@acme.dev") {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("Slack should be told once who acknowledged: %q", slack)
	}

	// Another alert joining an acknowledged incident doesn't page or change its status.
	h.fire(map[string]any{"dedup_key": "B", "summary": "checkout slow", "severity": "critical"})
	if inc := h.incident(1); inc["status"] != "acknowledged" || inc["severity"] != "critical" {
		t.Fatalf("after a critical alert joined: %v", inc)
	}
	if pd, _ := h.delivered(); countOf(pd, "trigger") != 1 {
		t.Fatalf("an alert joining an acknowledged incident paged again: %v", pd)
	}

	// Erin can't resolve it either; dave can, which resolves the upstream page.
	h.expect("erin", erin, "POST", "/v1/incidents/1/resolve", nil, 403, "")
	h.expect("carol", carol, "POST", "/v1/incidents/1/resolve", nil, 403, "")
	h.expect("dave", dave, "POST", "/v1/incidents/1/resolve", nil, 200, "")
	if inc := h.incident(1); inc["status"] != "resolved" || inc["resolution"] != "human" {
		t.Fatalf("after resolve: %v", inc)
	}
	if pd, _ := h.delivered(); strings.Join(pd, ",") != "trigger,acknowledge,resolve" {
		t.Fatalf("PagerDuty got %v, want trigger, acknowledge, resolve", pd)
	}
	if msgs := h.timelineMessages(1, "incident.resolved"); len(msgs) != 1 || !strings.Contains(msgs[0], "dave@acme.dev") {
		t.Fatalf("resolve timeline: %v", msgs)
	}
	// Resolving again is a no-op; acknowledging a resolved incident is a conflict.
	h.expect("dave", dave, "POST", "/v1/incidents/1/resolve", nil, 200, "")
	if msgs := h.timelineMessages(1, "incident.resolved"); len(msgs) != 1 {
		t.Fatalf("resolving twice: %v", msgs)
	}
	h.expect("dave", dave, "POST", "/v1/incidents/1/acknowledge", nil, 409, "resolved")

	// Unknown and malformed incident numbers.
	h.expect("owner", h.key, "POST", "/v1/incidents/99/acknowledge", nil, 404, "#99")
	h.expect("owner", h.key, "POST", "/v1/incidents/abc/acknowledge", nil, 404, "")
	h.expect("owner", h.key, "POST", "/v1/incidents/99/resolve", nil, 404, "")
}

// An acknowledged incident stops escalating (alert-incident-model.md §7), and
// in v1 escalation is the customer's PagerDuty: acknowledging in Nightfix has
// to acknowledge the upstream page, or PagerDuty keeps escalating to the next
// person while someone is already working on it.
func TestAcknowledgeAcknowledgesUpstreamPage(t *testing.T) {
	h := setupLifecycle(t)
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	h.must("POST", "/v1/incidents/1/acknowledge", nil)
	if pd, _ := h.delivered(); strings.Join(pd, ",") != "trigger,acknowledge" {
		t.Fatalf("PagerDuty got %v, want trigger then acknowledge", pd)
	}
}

// Acknowledging an incident that is holding its page for auto-remediation
// ends the hold: a human owns it, so the hold expiring doesn't page.
func TestAcknowledgeEndsRemediationHold(t *testing.T) {
	h := setupLifecycle(t)
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	// Pretend incident #1 is holding its page, with the hold already expired.
	h.exec(`UPDATE incidents SET status = 'remediating', paged_at = NULL, hold_until = now() - interval '1 second' WHERE number = 1`)
	h.must("POST", "/v1/incidents/1/acknowledge", nil)
	inc := h.incident(1)
	if inc["status"] != "acknowledged" || inc["hold_until"] != nil {
		t.Fatalf("after ack: %v", inc)
	}
	h.tick()
	if pages := h.timelineMessages(1, "incident.paged"); len(pages) != 1 {
		t.Fatalf("the expired hold paged after the ack: %v", pages)
	}
}

// A resolved incident reopens when one of its alerts re-fires within the
// reopen window: back to triggered (an earlier ack doesn't carry over), paged
// again, at the re-fired alert's severity if that is higher. After the window
// a re-fire opens a new incident instead.
func TestReopenIncident(t *testing.T) {
	h := setupLifecycle(t)
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down", "severity": "warning"})
	h.must("POST", "/v1/incidents/1/acknowledge", nil)
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down", "status": "resolved"})
	if inc := h.incident(1); inc["status"] != "resolved" || inc["resolution"] != "alerts_resolved" {
		t.Fatalf("after the alert resolved: %v", inc)
	}
	if pd, _ := h.delivered(); strings.Join(pd, ",") != "trigger,acknowledge,resolve" {
		t.Fatalf("PagerDuty: %v", pd)
	}

	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down again", "severity": "critical"})
	if got := len(h.incidents()); got != 1 {
		t.Fatalf("%d incidents; the re-fire should reopen #1", got)
	}
	inc := h.incident(1)
	if inc["status"] != "triggered" || inc["resolution"] != "" || inc["resolved_at"] != nil {
		t.Fatalf("reopened incident: %v", inc)
	}
	if inc["severity"] != "critical" {
		t.Fatalf("reopened by a critical alert, the incident is %v", inc["severity"])
	}
	if n := h.count(`SELECT count(*) FROM incidents WHERE number = 1 AND ack_at IS NULL`); n != 1 {
		t.Fatal("the reopened incident still carries the earlier ack")
	}
	types := strings.Join(h.timelineTypes(1), ",")
	if !strings.Contains(types, "incident.resolved,incident.reopened") || strings.Count(types, "incident.paged") != 2 {
		t.Fatalf("timeline: %s", types)
	}
	if pd, _ := h.delivered(); strings.Join(pd, ",") != "trigger,acknowledge,resolve,trigger" {
		t.Fatalf("PagerDuty: %v; the reopen must page again", pd)
	}
	// A reopened incident can be acknowledged again.
	h.must("POST", "/v1/incidents/1/acknowledge", nil)
	if acks := h.timelineMessages(1, "incident.acknowledged"); len(acks) != 2 {
		t.Fatalf("acks: %v", acks)
	}

	// Past the reopen window, a re-fire is a new alert and a new incident.
	h.must("POST", "/v1/services", map[string]any{"name": "batch", "reopen_window": "1s"})
	h.must("PUT", "/v1/routing-rules", []map[string]string{{"match": `alert.summary.startsWith("batch")`, "service": "batch"}})
	h.fire(map[string]any{"dedup_key": "J", "summary": "batch job failed"})
	h.fire(map[string]any{"dedup_key": "J", "summary": "batch job failed", "status": "resolved"})
	time.Sleep(1200 * time.Millisecond)
	h.fire(map[string]any{"dedup_key": "J", "summary": "batch job failed again"})
	st := h.statuses()
	if len(st) != 3 || st[2] != "resolved" || st[3] != "triggered" {
		t.Fatalf("incidents %v; want #2 resolved and a new #3 for the late re-fire", st)
	}
	if n := h.count(`SELECT count(*) FROM alerts WHERE fingerprint LIKE '%:J'`); n != 2 {
		t.Fatalf("%d alerts for the late re-fire's fingerprint, want 2 (a new alert)", n)
	}
}

// ---------------------------------------------------------------------------
// Runbooks and services
// ---------------------------------------------------------------------------

func lifecycleRunbook(title, service string) string {
	return `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: payments-check
  title: ` + title + `
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

func TestRunbookValidateAndGet(t *testing.T) {
	h := setupLifecycle(t)
	dave, _, carol := setupResponders(h)

	// Validate lints without publishing.
	var v map[string]any
	out := h.expect("dave", dave, "POST", "/v1/runbooks/validate", lifecycleRunbook("Check", "checkout-api"), 200, "")
	json.Unmarshal([]byte(out), &v)
	if v["valid"] != true || !strings.HasPrefix(fmt.Sprint(v["digest"]), "sha256:") || v["issues"] != nil {
		t.Fatalf("valid runbook: %v", v)
	}
	h.expect("owner", h.key, "GET", "/v1/runbooks/payments-check", nil, 404, "")
	if n := h.count(`SELECT count(*) FROM runbooks`); n != 0 {
		t.Fatal("validate published the runbook")
	}
	// Lint errors that need the database: a trigger naming an unknown service.
	v = nil
	json.Unmarshal([]byte(h.expect("dave", dave, "POST", "/v1/runbooks/validate", lifecycleRunbook("Check", "no-such-svc"), 200, "")), &v)
	issues, _ := v["issues"].([]any)
	if v["valid"] != false || len(issues) != 1 || !strings.Contains(mustJSON(issues), "no service named no-such-svc") ||
		!strings.Contains(mustJSON(issues), "spec.triggers[0].services") {
		t.Fatalf("unknown service: %v", v)
	}
	// Parse errors come back as issues too.
	v = nil
	json.Unmarshal([]byte(h.expect("dave", dave, "POST", "/v1/runbooks/validate", "kind: [", 200, "")), &v)
	if v["valid"] != false || v["issues"] == nil {
		t.Fatalf("unparsable runbook: %v", v)
	}
	// Viewers can't use the editor's validate.
	h.expect("carol", carol, "POST", "/v1/runbooks/validate", lifecycleRunbook("Check", "checkout-api"), 403, "")

	// Get returns the latest version with its digest, or a given one.
	var p1, p2 map[string]any
	json.Unmarshal([]byte(h.expect("dave", dave, "PUT", "/v1/runbooks/payments-check", lifecycleRunbook("Check", "checkout-api"), 200, "")), &p1)
	json.Unmarshal([]byte(h.expect("dave", dave, "PUT", "/v1/runbooks/payments-check", lifecycleRunbook("Check v2", "checkout-api"), 200, "")), &p2)
	if p1["digest"] != v1Digest(h, dave) || p2["version"] != float64(2) {
		t.Fatalf("publish results: %v %v", p1, p2)
	}
	var got map[string]any
	json.Unmarshal([]byte(h.expect("carol", carol, "GET", "/v1/runbooks/payments-check", nil, 200, "")), &got)
	if got["version"] != float64(2) || got["digest"] != p2["digest"] || got["title"] != "Check v2" ||
		!strings.Contains(fmt.Sprint(got["source_yaml"]), "title: Check v2") {
		t.Fatalf("latest: %v", got)
	}
	got = nil
	json.Unmarshal([]byte(h.expect("carol", carol, "GET", "/v1/runbooks/payments-check?version=1", nil, 200, "")), &got)
	if got["version"] != float64(1) || got["digest"] != p1["digest"] || got["latest_version"] != float64(2) ||
		!strings.Contains(fmt.Sprint(got["source_yaml"]), "title: Check\n") {
		t.Fatalf("version 1: %v", got)
	}
	h.expect("carol", carol, "GET", "/v1/runbooks/payments-check?version=3", nil, 404, "")
	h.expect("carol", carol, "GET", "/v1/runbooks/payments-check?version=x", nil, 400, "")
	h.expect("carol", carol, "GET", "/v1/runbooks/nope", nil, 404, "")
}

// v1Digest is the digest validate computes for version 1's content, which
// must be the digest publishing it records.
func v1Digest(h *lifecycleHarness, tok string) any {
	var v map[string]any
	json.Unmarshal([]byte(h.expect("validate", tok, "POST", "/v1/runbooks/validate", lifecycleRunbook("Check", "checkout-api"), 200, "")), &v)
	return v["digest"]
}

func TestListServices(t *testing.T) {
	h := setupLifecycle(t)
	h.must("POST", "/v1/services", map[string]any{"name": "batch", "max_hold": "3m", "verification_window": "90s"})
	var list []map[string]any
	if code := h.call("GET", "/v1/services", nil, &list); code != 200 {
		t.Fatalf("list: %d", code)
	}
	var names []string
	for _, s := range list {
		names = append(names, fmt.Sprint(s["name"]))
		if !strings.HasPrefix(fmt.Sprint(s["id"]), "svc_") {
			t.Fatalf("service id: %v", s)
		}
		if s["name"] == "batch" && (s["max_hold"] != "3m0s" || s["verification_window"] != "1m30s") {
			t.Fatalf("batch: %v", s)
		}
	}
	if strings.Join(names, ",") != "batch,catch-all,checkout-api,ledger" {
		t.Fatalf("services %v; want every service, by name", names)
	}
	// A viewer can list services; another org's services aren't listed.
	h.expect("carol", h.user("carol"), "GET", "/v1/services", nil, 200, "checkout-api")
	other, err := h.srv.CreateOrg(context.Background(), "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	if out := h.expect("other org", other.APIKey, "GET", "/v1/services", nil, 200, "catch-all"); strings.Contains(out, "checkout-api") {
		t.Fatalf("another org sees this org's services: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Identity: teams, role bindings, Auth0 link
// ---------------------------------------------------------------------------

func TestRoleBindingsListAndDelete(t *testing.T) {
	h := setupLifecycle(t)
	h.must("POST", "/v1/teams", map[string]string{"slug": "owners"})
	h.must("POST", "/v1/teams", map[string]string{"slug": "platform-admins", "auth0_group": "platform"})
	h.must("POST", "/v1/teams", map[string]string{"slug": "payments", "auth0_group": "payments-eng"})
	ids := map[string]string{}
	bind := func(name string, body map[string]any) {
		t.Helper()
		var out map[string]string
		if code := h.call("POST", "/v1/role-bindings", body, &out); code != 200 || !strings.HasPrefix(out["id"], "rb_") {
			t.Fatalf("bind %s: %d %v", name, code, out)
		}
		ids[name] = out["id"]
	}
	bind("owner", map[string]any{"subject_type": "team", "subject": "owners", "role": "owner"})
	bind("admin", map[string]any{"subject_type": "team", "subject": "platform-admins", "role": "admin"})
	bind("responder", map[string]any{"subject_type": "team", "subject": "payments", "role": "responder",
		"scope": map[string]any{"teams": []string{"payments"}}})
	var me map[string]any
	h.call("GET", "/v1/me", nil, &me)
	keyID := fmt.Sprint(me["principal"])
	bind("key", map[string]any{"subject_type": "api_key", "subject": keyID, "role": "viewer"})

	bob := h.user("bob", "platform")
	dave := h.user("dave", "payments-eng")
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	h.expect("dave", dave, "POST", "/v1/incidents/1/acknowledge", nil, 200, "")

	// Teams, with member counts from logins.
	var teams []map[string]any
	json.Unmarshal([]byte(h.expect("carol", h.user("carol"), "GET", "/v1/teams", nil, 200, "")), &teams)
	if mustJSON(teams) != `[{"auth0_group":"","members":0,"name":"owners","slug":"owners"},`+
		`{"auth0_group":"payments-eng","members":1,"name":"payments","slug":"payments"},`+
		`{"auth0_group":"platform","members":0,"name":"platform-admins","slug":"platform-admins"}]` {
		t.Fatalf("teams: %s", mustJSON(teams))
	}

	// Admins list bindings; subjects read as they're written.
	var list []map[string]any
	json.Unmarshal([]byte(h.expect("bob", bob, "GET", "/v1/role-bindings", nil, 200, "")), &list)
	subjects := map[string]string{}
	for _, b := range list {
		subjects[fmt.Sprint(b["id"])] = fmt.Sprint(b["subject_type"], ":", b["subject"], ":", b["role"])
	}
	want := map[string]string{ids["owner"]: "team:owners:owner", ids["admin"]: "team:platform-admins:admin",
		ids["responder"]: "team:payments:responder", ids["key"]: "api_key:" + keyID + ":viewer"}
	if mustJSON(subjects) != mustJSON(want) {
		t.Fatalf("bindings %v, want %v", subjects, want)
	}
	if !strings.Contains(mustJSON(list), `"scope":{"teams":["payments"]}`) {
		t.Fatalf("scoped binding's scope not listed: %s", mustJSON(list))
	}
	h.expect("dave", dave, "GET", "/v1/role-bindings", nil, 403, "admin")

	// Only an owner can remove an admin or owner binding.
	h.expect("bob", bob, "DELETE", "/v1/role-bindings/"+ids["owner"], nil, 403, "only an owner")
	h.expect("bob", bob, "DELETE", "/v1/role-bindings/"+ids["admin"], nil, 403, "only an owner")
	// Responders can't remove anything.
	h.expect("dave", dave, "DELETE", "/v1/role-bindings/"+ids["responder"], nil, 403, "")

	// An admin can remove a responder binding, and it takes effect on the next request.
	h.fire(map[string]any{"dedup_key": "A", "summary": "checkout down", "status": "resolved"})
	h.fire(map[string]any{"dedup_key": "B", "summary": "checkout down again"})
	h.expect("bob", bob, "DELETE", "/v1/role-bindings/"+ids["responder"], nil, 200, "")
	h.expect("dave", dave, "POST", "/v1/incidents/2/acknowledge", nil, 403, "")
	h.expect("bob", bob, "DELETE", "/v1/role-bindings/"+ids["responder"], nil, 404, "")

	// Another org can't see or delete this org's bindings.
	other, err := h.srv.CreateOrg(context.Background(), "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	if out := h.expect("other org", other.APIKey, "GET", "/v1/role-bindings", nil, 200, ""); strings.Contains(out, ids["admin"]) {
		t.Fatalf("another org lists this org's bindings: %s", out)
	}
	h.expect("other org", other.APIKey, "DELETE", "/v1/role-bindings/"+ids["admin"], nil, 404, "")
	h.expect("bob", bob, "GET", "/v1/role-bindings", nil, 200, "") // still an admin

	// An owner can remove the admin binding; bob loses admin at once.
	h.expect("owner", h.key, "DELETE", "/v1/role-bindings/"+ids["admin"], nil, 200, "")
	h.expect("bob", bob, "GET", "/v1/role-bindings", nil, 403, "")
	h.expect("bob", bob, "GET", "/v1/incidents", nil, 200, "") // a member without bindings is a viewer

	// Malformed ids.
	h.expect("owner", h.key, "DELETE", "/v1/role-bindings/not-an-id", nil, 404, "")
	h.expect("owner", h.key, "DELETE", "/v1/role-bindings/"+strings.Replace(ids["owner"], "rb_", "key_", 1), nil, 404, "")

	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'role_binding.delete'`); n != 2 {
		t.Fatalf("%d binding deletions audited, want 2", n)
	}
}

func TestLinkAuth0(t *testing.T) {
	h := setupLifecycle(t) // linked to org_acme
	h.must("POST", "/v1/teams", map[string]string{"slug": "platform-admins", "auth0_group": "platform"})
	h.must("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "platform-admins", "role": "admin"})
	bob := h.user("bob", "platform")

	h.expect("owner", h.key, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "acme"}, 400, "org_")
	h.expect("owner", h.key, "PUT", "/v1/org/auth0", `{"auth0_org_id": "org_x", "extra": 1}`, 400, "")
	// Linking is an owner's call, not an admin's.
	h.expect("bob (admin)", bob, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_bob"}, 403, "owner")

	// An Auth0 organization can be linked to one org only.
	other, err := h.srv.CreateOrg(context.Background(), "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	h.expect("other owner", other.APIKey, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, 409, "another org")
	h.expect("bob", bob, "GET", "/v1/me", nil, 200, "bob@acme.dev") // still signs in to acme
	// Relinking the same one is fine, and audited.
	h.expect("owner", h.key, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, 200, "org_acme")
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'org.link_auth0'`); n != 2 {
		t.Fatalf("%d links audited, want 2", n)
	}
	// Moving to another Auth0 organization: tokens from the old one stop working.
	h.expect("owner", h.key, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme_new"}, 200, "")
	h.expect("bob (old org)", bob, "GET", "/v1/me", nil, 401, "not linked")
	bobNew := h.idp.UserToken("auth0|bob", "bob@acme.dev", "org_acme_new", "platform")
	h.expect("bob (new org)", bobNew, "GET", "/v1/me", nil, 200, "bob@acme.dev")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
