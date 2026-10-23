package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
)

// The per-event CEL budget is a wall-clock deadline set when routing starts,
// so database time spent after routing (a row lock held by a concurrent
// transaction, a slow query) is charged to it. Here the alert's processing
// waits ~2.5s for the org row (tryAutoRun's FOR SHARE) while an unrelated
// transaction updates the org; the runbook's `from:` parameters then resolve
// against an already-expired budget and auto-remediation is skipped, although
// the CEL itself took microseconds.
func TestVerify4CELBudgetChargedForDatabaseWaits(t *testing.T) {
	g := setupGuard(t, nil, autoRunbook{Name: "orders-fix", BeforePaging: true})

	locked := make(chan struct{})
	released := make(chan error, 1)
	go func() {
		released <- g.db.WithOrg(g.ctx, g.rawOrg, func(tx *db.Tx) error {
			if _, err := tx.Exec(`UPDATE orgs SET name = name WHERE id = $1`, g.rawOrg); err != nil {
				return err
			}
			close(locked)
			time.Sleep(2500 * time.Millisecond)
			return nil
		})
	}()
	<-locked
	g.fire("budget-1", "high", ordersSvc)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	g.waitUntil("incident #1 to page or run", 1, func() bool {
		tr, _ := g.pages(1)
		return len(tr) > 0 || len(g.runsFor(1)) > 0
	})
	time.Sleep(time.Second)
	runs := g.runsFor(1)
	tr, _ := g.pages(1)
	t.Logf("runs: %+v; pages: %q", runs, tr)
	if len(runs) == 0 {
		for _, p := range tr {
			if strings.Contains(p, "parameters could not be resolved") || strings.Contains(p, "took too long") {
				t.Fatalf("auto-remediation skipped because a DB lock wait used up the CEL budget: %q", p)
			}
		}
		t.Fatalf("no run started; pages: %q", tr)
	}
}

// Same root cause, advance(): a run that did start fails outright because its
// first step's trivial `when` is evaluated after the budget ran out waiting
// on the org row lock.
func TestVerify4CELBudgetFailsStartedRunAfterDatabaseWait(t *testing.T) {
	g := setupGuard(t, nil)
	rb := `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: orders-note
  title: Note
spec:
  target:
    agentSelector:
      env: prod
  triggers:
    - type: alert
      services: [orders]
      match: 'alert.labels.alertname == "tasks-unhealthy"'
      mode: auto
      beforePaging: true
      cooldown: 1s
      maxRunsPerHour: 10
  policy:
    timeout: 15m
  steps:
    - id: n1
      type: note
      when: 'true'
      markdown: hi
  onFailure:
    action: escalate
`
	var out map[string]any
	if code := g.callRaw("PUT", "/v1/runbooks/orders-note", []byte(rb), &out); code/100 != 2 {
		t.Fatalf("publish: %d %v", code, out)
	}
	locked := make(chan struct{})
	released := make(chan error, 1)
	go func() {
		released <- g.db.WithOrg(g.ctx, g.rawOrg, func(tx *db.Tx) error {
			if _, err := tx.Exec(`UPDATE orgs SET name = name WHERE id = $1`, g.rawOrg); err != nil {
				return err
			}
			close(locked)
			time.Sleep(2500 * time.Millisecond)
			return nil
		})
	}()
	<-locked
	g.fire("budget-2", "high", ordersSvc)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	g.waitUntil("incident #1's run to finish", 1, func() bool {
		r := g.runsFor(1)
		return len(r) > 0 && r[0].Status != "running" && r[0].Status != "pending"
	})
	runs := g.runsFor(1)
	var errText string
	g.db.WithOrg(g.ctx, g.rawOrg, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT COALESCE(error, '') FROM runbook_runs WHERE runbook_name = 'orders-note'`).Scan(&errText)
	})
	t.Logf("runs: %+v; error: %q", runs, errText)
	if runs[0].Status != "succeeded" {
		t.Fatalf("run %s (%q): a `when: true` failed because a DB lock wait used up the CEL budget", runs[0].Status, errText)
	}
}
