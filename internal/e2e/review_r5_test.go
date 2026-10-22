package e2e

// Independent review (round 5): failing tests for bugs found in review.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
)

// approveFirst gates the fix behind an approval as its very first step.
const approveFirst = `    - id: approve
      type: approval
      fromRoles: [Responder]
      expiresAfter: 10m
` + quickFix

// A held auto-remediation must page as soon as it needs an approval
// (README "Approvals"; approvals.go). When the approval is the runbook's
// first step, the gate opens inside decideRemediation before the incident
// is marked remediating, so openGate's "page if this run holds the page"
// check sees a triggered incident and doesn't page; decideRemediation then
// sets remediating and holds the page until max_hold expires.
func TestReviewHeldRunWhoseFirstStepIsAnApprovalPagesAtOnce(t *testing.T) {
	rb := held("orders-gated")
	rb.Steps = approveFirst
	g := setupGuard(t, map[string]any{"max_hold": "30m"}, rb)
	g.fire("A", "high", ordersSvc)
	g.waitUntil("the run to wait for approval", 1, func() bool {
		runs := g.runsFor(1)
		return len(runs) == 1 && runs[0].Status == "awaiting_approval"
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if triggers, _ := g.pages(1); len(triggers) > 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	g.dump(1)
	t.Fatalf("incident is %s and nobody was paged while the held remediation waits for an approval (it pages only when the hold expires, 20m later)",
		status(g.incident(1)))
}

// whenErrors refers to a label the alert doesn't carry, so evaluating
// when: fails and the run fails inside startRun, before decideRemediation
// has marked the incident remediating.
const whenErrors = `    - id: restart
      type: aws
      service: ecs
      action: UpdateService
      when: alert.labels.env == "prod"
      input:
        cluster: ${{ params.cluster }}
        service: ${{ params.service }}
        forceNewDeployment: true
`

// A held run that fails at once pages (onFailure: escalate) and then
// decideRemediation overwrites the incident back to remediating with a
// hold. The incident looks held though it already paged, pages a second
// time when the hold expires, and if its alert clears meanwhile it never
// resolves: checkAlertsCleared ignores a remediating incident whose run
// failed.
func TestReviewHeldRunThatFailsImmediatelyLeavesIncidentConsistent(t *testing.T) {
	rb := held("orders-when")
	rb.Steps = whenErrors
	g := setupGuard(t, map[string]any{"max_hold": "30m"}, rb)
	g.fire("A", "high", ordersSvc)
	g.waitRunStatus(1, "failed")
	g.waitUntil("the failure to page", 1, func() bool { tr, _ := g.pages(1); return len(tr) > 0 })
	time.Sleep(500 * time.Millisecond)
	if st := status(g.incident(1)); st != "triggered" {
		g.dump(1)
		t.Errorf("incident is %s after its remediation failed and it paged; want triggered", st)
	}
	g.clear("A")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if status(g.incident(1)) == "resolved" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	g.dump(1)
	t.Fatalf("every alert cleared but incident #1 is still %s", status(g.incident(1)))
}

// The kill switch must stop every run. tryAutoRun reads orgs.frozen_at
// without a lock (apiStartRun takes FOR SHARE), so an auto run that starts
// while a freeze commits isn't seen by the freeze's cancel sweep: the org
// is frozen with a live run that executes as soon as someone unfreezes.
func TestReviewFreezeRacingAnAutoRunLeavesNoLiveRun(t *testing.T) {
	rb := held("orders-restart")
	g := setupGuard(t, nil, rb)

	// Park the alert processor inside tryAutoRun, after it has read
	// frozen_at, on concurrencyBlocked's advisory lock.
	tx, err := g.db.BeginTx(g.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1 || '/' || $2, 0))`, g.rawOrg, rb.Name); err != nil {
		t.Fatal(err)
	}
	g.fire("A", "high", ordersSvc)
	g.waitUntil("the alert processor to wait on the runbook lock", 1, func() bool {
		var n int
		g.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND wait_event = 'advisory'
			AND query LIKE '%pg_advisory_xact_lock%' AND datname = current_database()`).Scan(&n)
		return n > 0
	})

	// The freeze is requested now. With the fix it waits for the alert's
	// transaction (which holds the freeze flag FOR SHARE), so release the
	// runbook lock while it waits; then its sweep must see the new run.
	frozeDone := make(chan struct{})
	go func() { g.call("POST", "/v1/org/freeze", map[string]any{}, nil); close(frozeDone) }()
	time.Sleep(500 * time.Millisecond)
	tx.Commit() // the alert processor carries on
	<-frozeDone

	g.waitUntil("the run to be recorded", 1, func() bool { return len(g.runsFor(1)) == 1 })
	if runs := g.runsFor(1); runs[0].Status == "running" {
		var frozen bool
		g.db.WithOrg(g.ctx, g.rawOrg, func(tx *db.Tx) error {
			return tx.QueryRow(`SELECT frozen_at IS NOT NULL FROM orgs`).Scan(&frozen)
		})
		// Show the impact: unfreezing runs it.
		g.call("POST", "/v1/org/unfreeze", map[string]any{}, nil)
		ran := false
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && !ran {
			calls, _, _ := g.stub.Snapshot()
			ran = countCalls(calls, "ecs:UpdateService") > 0
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("org frozen=%v yet the auto run started during the freeze is still running; after unfreeze ECS UpdateService called=%v; timeline: %s",
			frozen, ran, strings.Join(g.timeline(1), " | "))
	}
}

// The flap guard counts auto-fixes of one alert ("runs that succeeded and
// whose alerts cleared", FlapGuardThreshold; data-model: verified is "set
// true when the alerts clear after a successful auto run of any severity").
// An auto runbook without beforePaging never becomes the incident's
// remediation_run_id, so checkAlertsCleared never marks it verified and the
// flap guard never counts it: it restarts a flapping service forever.
func TestReviewFlapGuardCountsParallelAutoFixes(t *testing.T) {
	g := setupGuard(t, map[string]any{"reopen_window": "1s"}, autoRunbook{Name: "orders-restart"})
	for n := 1; n <= 3; n++ {
		g.fire("flappy", "high", ordersSvc)
		g.waitRunStatus(n, "succeeded")
		g.clear("flappy")
		g.waitStatus(n, "resolved")
		time.Sleep(1500 * time.Millisecond) // past the reopen window and the 1s cooldown
	}
	g.fire("flappy", "high", ordersSvc)
	g.waitUntil("incident #4", 4, func() bool { tr, _ := g.pages(4); return len(tr) > 0 })
	time.Sleep(time.Second)
	if runs := g.runsFor(4); len(runs) != 0 {
		g.dump(4)
		t.Fatalf("three auto-fixes of this alert in the last minute, yet a fourth auto run started: %+v (all runs %+v)", runs, g.runs())
	}
}

// failsFast forces a new deployment, then waits at most 3s for the service
// to stabilize (with stub.SetHeals(false) it never does).
const failsFast = quickFix + `    - id: wait-stable
      type: wait
      interval: 1s
      timeout: 3s
      check:
        aws:
          service: ecs
          action: DescribeServices
          input:
            cluster: ${{ params.cluster }}
            services: ["${{ params.service }}"]
      until: result.services[0].runningCount == result.services[0].desiredCount
`

// Acknowledging an incident acknowledges its upstream PagerDuty page, so
// PagerDuty's escalation stops (README, apiAck). Someone who acknowledges a
// held remediation (nothing paged yet) owns the incident, but when the run
// then fails, page() sends a PagerDuty trigger and nothing acknowledges it:
// PagerDuty escalates to people while the incident is acknowledged here.
func TestReviewPageAfterAcknowledgeIsAcknowledgedUpstream(t *testing.T) {
	rb := held("orders-restart")
	rb.Steps = failsFast
	g := setupGuard(t, nil, rb)
	g.stub.SetHeals(false)
	g.fire("A", "high", ordersSvc)
	g.waitStatus(1, "remediating")
	g.call("POST", "/v1/incidents/1/acknowledge", map[string]any{}, nil)
	g.waitPaged(1, "timed out")
	time.Sleep(2 * time.Second)
	inc := g.incident(1)
	_, _, pd := g.stub.Snapshot()
	var actions []string
	for _, ev := range pd {
		if ev["dedup_key"] == inc["id"] {
			actions = append(actions, fmt.Sprint(ev["event_action"]))
		}
	}
	if status(inc) != "acknowledged" || len(actions) == 0 || actions[len(actions)-1] != "acknowledge" {
		t.Fatalf("incident is %s here, but PagerDuty received %v for it: the page is live and escalating upstream", status(inc), actions)
	}
}
