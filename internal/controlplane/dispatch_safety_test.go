package controlplane

// Dispatch safety: leases, acks, heartbeats, retries, onFailure, `when`
// conditions and agent certificate checks (agent-protocol.md §3.2, §5.2, §8).
// These drive the server directly through runHarness (runs_test.go).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// dsRB describes a test runbook: harnessRunbook plus optional parameters,
// extra policy lines and a runbook-level onFailure action.
type dsRB struct {
	params, policy, onFailure, steps string
}

func (o dsRB) yaml() string {
	rb := harnessRunbook(o.steps)
	if o.params != "" {
		rb = strings.Replace(rb, "  policy:\n", "  parameters:\n"+o.params+"  policy:\n", 1)
	}
	if o.policy != "" {
		rb = strings.Replace(rb, "    timeout: 10m\n", "    timeout: 10m\n"+o.policy, 1)
	}
	if o.onFailure != "" {
		rb += "  onFailure:\n    action: " + o.onFailure + "\n"
	}
	return rb
}

const dsModeParam = "    mode:\n      type: string\n      values: [fast, slow]\n      default: fast\n"

// dsStart publishes rb as "qa" and starts a run with the given request body
// fields (JSON object members, without braces). It returns the run's API id.
func (e *runHarness) dsStart(rb dsRB, fields string) string {
	e.t.Helper()
	if code, out := e.call("PUT", "/v1/runbooks/qa", []byte(rb.yaml())); code != 200 {
		e.t.Fatalf("publish: %d %v", code, out)
	}
	body := `{"runbook":"qa"`
	if fields != "" {
		body += "," + fields
	}
	code, out := e.call("POST", "/v1/runs", []byte(body+"}"))
	if code != 200 {
		e.t.Fatalf("run: %d %v", code, out)
	}
	return out["id"].(string)
}

func (e *runHarness) dsExec(q string, args ...any) {
	e.t.Helper()
	if err := e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
		_, err := tx.Exec(q, args...)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *runHarness) dsCount(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
		return tx.QueryRow(q, args...).Scan(&n)
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

type dsAttempt struct {
	ID, StepID, State                    string
	N                                    int
	Agent                                sql.NullString
	Lease, Dispatched, Started, Finished sql.NullTime
	NotBefore                            sql.NullTime
	LeaseLeft                            sql.NullFloat64 // seconds until lease_expires_at
	BackoffAfterPrev                     sql.NullFloat64 // not_before minus the previous attempt's finished_at
}

// dsAttempts lists a run's attempts in order.
func (e *runHarness) dsAttempts(runAPIID string) []dsAttempt {
	e.t.Helper()
	runID, err := ids.Decode("run", runAPIID)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []dsAttempt
	if err := e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT a.id, a.step_id, a.state, a.attempt_number, a.agent_id, a.lease_expires_at, a.dispatched_at,
				a.started_at, a.finished_at, a.not_before, extract(epoch FROM a.lease_expires_at - now()),
				extract(epoch FROM a.not_before - p.finished_at)
			FROM step_attempts a LEFT JOIN step_attempts p ON p.run_id = a.run_id AND p.step_index = a.step_index
				AND p.attempt_number = a.attempt_number - 1
			WHERE a.run_id = $1 ORDER BY a.step_index, a.attempt_number`, runID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a dsAttempt
			if err := rows.Scan(&a.ID, &a.StepID, &a.State, &a.N, &a.Agent, &a.Lease, &a.Dispatched, &a.Started, &a.Finished,
				&a.NotBefore, &a.LeaseLeft, &a.BackoffAfterPrev); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *runHarness) dsAttempt(runAPIID, attemptID string) dsAttempt {
	e.t.Helper()
	for _, a := range e.dsAttempts(runAPIID) {
		if a.ID == attemptID {
			return a
		}
	}
	e.t.Fatalf("attempt %s not found", attemptID)
	return dsAttempt{}
}

func (e *runHarness) dsResult(attemptID, status string, outputs map[string]any) {
	e.t.Helper()
	if err := e.s.Result(context.Background(), e.a, attemptID, agentapi.Result{Status: status, Outputs: outputs}); err != nil {
		e.t.Fatalf("result: %v", err)
	}
}

// dsIncident creates incident #1 on a new service and returns its id.
func (e *runHarness) dsIncident() string {
	e.t.Helper()
	svc, inc := ids.NewString(), ids.NewString()
	e.dsExec(`INSERT INTO services (id, org_id, name) VALUES ($1,$2,'checkout')`, svc, e.a.OrgID)
	e.dsExec(`INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
		VALUES ($1,$2,1,$3,$4,'acknowledged','critical','checkout down')`, inc, e.a.OrgID, svc, inc)
	return inc
}

func (e *runHarness) dsPaged(inc string) bool {
	e.t.Helper()
	return e.dsCount(`SELECT count(*) FROM incident_timeline WHERE incident_id = $1 AND type = 'incident.paged'`, inc) > 0
}

// dsAgent enrolls another agent with the harness agent's labels.
func (e *runHarness) dsAgent() agentIdentity {
	e.t.Helper()
	id := ids.NewString()
	e.dsExec(`INSERT INTO agents (id, org_id, enrollment_rule_id, labels, cert_serial, cert_expires_at, status, last_seen_at)
		VALUES ($1,$2,$3,'{"env":"prod"}',$4, now()+interval '1 day','online',now())`, id, e.a.OrgID, e.rule, id)
	return agentIdentity{OrgID: e.a.OrgID, AgentID: id}
}

func wantHTTPError(t *testing.T, what string, err error, code int) {
	t.Helper()
	var he httpError
	if !errors.As(err, &he) || he.code != code {
		t.Fatalf("%s: got %v, want HTTP %d", what, err, code)
	}
}

const dsShell = "    - id: s1\n      type: shell\n      run: echo hi\n"

// ---------------------------------------------------------------------------
// Leases (§5.2, §8.2)
// ---------------------------------------------------------------------------

// A dispatch that's never acknowledged goes back to the queue as the same,
// never-started attempt: no retry is used up, nothing is lost.
func TestExpiredLeaseBeforeAckRequeues(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()
	if a == "" {
		t.Fatal("nothing dispatched")
	}
	e.expireLeases()

	got := e.dsAttempts(id)
	if len(got) != 1 {
		t.Fatalf("%d attempts after an unacked lease expired; want the one attempt re-queued", len(got))
	}
	at := got[0]
	if at.ID != a || at.State != "queued" || at.N != 1 || at.Agent.Valid || at.Lease.Valid || at.Dispatched.Valid || at.Started.Valid || at.Finished.Valid {
		t.Fatalf("re-queued attempt: %+v; want queued #1 with no agent, lease, dispatch or start", at)
	}
	if st := e.run(id)["status"]; st != "running" {
		t.Fatalf("run %v after an unacked lease expired", st)
	}
	// The agent that held it can no longer ack it.
	err := e.s.Ack(ctx, e.a, a, agentapi.Ack{Accepted: true})
	wantHTTPError(t, "late ack of a re-queued attempt", err, 404)

	// It's dispatched again (same attempt) and runs normally.
	if again := e.poll(); again != a {
		t.Fatalf("re-dispatched %q, want the same attempt %s", again, a)
	}
	e.ack(a)
	if at := e.dsAttempt(id, a); at.State != "running" || !at.Started.Valid {
		t.Fatalf("after ack: %+v", at)
	}
	e.dsResult(a, "succeeded", nil)
	if st := e.run(id)["status"]; st != "succeeded" {
		t.Fatalf("run %v", st)
	}
}

// Acked, then silent: the step may have run. A non-idempotent step is never
// re-run, even with retries left; the run needs a human and pages, whatever
// the runbook's onFailure says.
func TestExpiredLeaseAfterAckNonIdempotentNeedsHuman(t *testing.T) {
	for _, step := range []string{
		dsShell, // shell: not idempotent by default
		"    - id: s1\n      type: shell\n      idempotent: false\n      retries: 3\n      run: echo hi\n",
	} {
		e := setupRunHarness(t)
		inc := e.dsIncident()
		id := e.dsStart(dsRB{steps: step + "    - id: s2\n      type: shell\n      run: echo next\n", onFailure: "none"}, `"incident":1`)
		a := e.poll()
		e.ack(a)
		e.expireLeases()

		got := e.dsAttempts(id)
		if len(got) != 1 || got[0].State != "lost" || !got[0].Finished.Valid {
			t.Fatalf("attempts after an acked lease expired: %+v; want one lost attempt and no retry", got)
		}
		run := e.run(id)
		if run["status"] != "needs_human" || !strings.Contains(fmt.Sprint(run["error"]), "may or may not have completed") {
			t.Fatalf("run %v (%v); want needs_human", run["status"], run["error"])
		}
		if !e.dsPaged(inc) {
			t.Fatal("a step that may or may not have run didn't page, with runbook onFailure: none")
		}
		if next := e.poll(); next != "" {
			t.Fatalf("dispatched %s after the run needed a human", next)
		}
		// The agent coming back late with a result changes nothing.
		e.dsResult(a, "succeeded", nil)
		if st := e.run(id)["status"]; st != "needs_human" {
			t.Fatalf("a late result moved the run to %v", st)
		}
	}
}

// A lost idempotent step is re-dispatched while retries remain, then needs a
// human like any other lost step.
func TestExpiredLeaseAfterAckIdempotentRetries(t *testing.T) {
	e := setupRunHarness(t)
	id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      idempotent: true\n      retries: 1\n      run: echo hi\n"}, "")
	a1 := e.poll()
	e.ack(a1)
	e.expireLeases()
	if st := e.run(id)["status"]; st != "running" {
		t.Fatalf("run %v after a lost idempotent step with a retry left", st)
	}
	a2 := e.poll()
	if a2 == "" || a2 == a1 {
		t.Fatalf("idempotent lost step wasn't retried as a new attempt (got %q)", a2)
	}
	if at := e.dsAttempt(id, a2); at.N != 2 {
		t.Fatalf("retry is attempt #%d", at.N)
	}
	e.ack(a2)
	e.expireLeases()
	got := e.dsAttempts(id)
	if len(got) != 2 || got[0].State != "lost" || got[1].State != "lost" {
		t.Fatalf("attempts: %+v; want two lost and no third", got)
	}
	if st := e.run(id)["status"]; st != "needs_human" {
		t.Fatalf("run %v once retries ran out", st)
	}
}

// ---------------------------------------------------------------------------
// Ack
// ---------------------------------------------------------------------------

// A rejected dispatch fails the attempt, isn't retried (the same bundle
// would be rejected again) and applies the step's onFailure.
func TestRejectedAckAppliesOnFailure(t *testing.T) {
	ctx := context.Background()
	reject := func(e *runHarness, a string) {
		t.Helper()
		if err := e.s.Ack(ctx, e.a, a, agentapi.Ack{Accepted: false, Reason: "signature \x00 invalid"}); err != nil {
			t.Fatalf("reject: %v", err)
		}
	}
	next := "    - id: s2\n      type: shell\n      run: echo next\n"

	t.Run("stop", func(t *testing.T) {
		e := setupRunHarness(t)
		inc := e.dsIncident()
		id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      retries: 2\n      run: echo hi\n" + next}, `"incident":1`)
		a := e.poll()
		reject(e, a)
		got := e.dsAttempts(id)
		if len(got) != 1 || got[0].State != "rejected" || !got[0].Finished.Valid {
			t.Fatalf("attempts: %+v; want one rejected, not retried", got)
		}
		run := e.run(id)
		if run["status"] != "failed" || !strings.Contains(fmt.Sprint(run["error"]), "rejected") {
			t.Fatalf("run %v (%v)", run["status"], run["error"])
		}
		if !e.dsPaged(inc) {
			t.Fatal("rejected dispatch didn't escalate (runbook onFailure defaults to escalate)")
		}
		if n := e.dsCount(`SELECT count(*) FROM audit_events WHERE action = 'attempt.rejected'`); n != 1 {
			t.Fatalf("%d attempt.rejected audit events", n)
		}
	})
	t.Run("continue", func(t *testing.T) {
		e := setupRunHarness(t)
		id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      onFailure: continue\n      run: echo hi\n" + next}, "")
		reject(e, e.poll())
		a2 := e.poll()
		if at := e.dsAttempt(id, a2); at.StepID != "s2" {
			t.Fatalf("after a rejected step with onFailure: continue, dispatched %s", at.StepID)
		}
		e.ack(a2)
		e.dsResult(a2, "succeeded", nil)
		if st := e.run(id)["status"]; st != "succeeded" {
			t.Fatalf("run %v", st)
		}
	})
	t.Run("escalate", func(t *testing.T) {
		e := setupRunHarness(t)
		inc := e.dsIncident()
		id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      onFailure: escalate\n      run: echo hi\n", onFailure: "none"}, `"incident":1`)
		reject(e, e.poll())
		if st := e.run(id)["status"]; st != "failed" {
			t.Fatalf("run %v", st)
		}
		if !e.dsPaged(inc) {
			t.Fatal("step onFailure: escalate didn't page when the runbook's onFailure is none")
		}
	})
}

func TestAckRefusedForOthersAndFinishedAttempts(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()

	other := e.dsAgent()
	wantHTTPError(t, "ack by another agent", e.s.Ack(ctx, other, a, agentapi.Ack{Accepted: true}), 404)
	wantHTTPError(t, "reject by another agent", e.s.Ack(ctx, other, a, agentapi.Ack{Accepted: false}), 404)
	wantHTTPError(t, "result by another agent", e.s.Result(ctx, other, a, agentapi.Result{Status: "succeeded"}), 404)

	// An agent in another org can't see the attempt at all.
	e2 := setupRunHarness(t)
	foreign := e2.a
	foreign.AgentID = e.a.AgentID // even claiming the right agent id
	wantHTTPError(t, "ack from another org", e.s.Ack(ctx, foreign, a, agentapi.Ack{Accepted: true}), 404)

	if at := e.dsAttempt(id, a); at.State != "dispatched" || at.Agent.String != e.a.AgentID {
		t.Fatalf("refused acks changed the attempt: %+v", at)
	}

	e.ack(a)
	// A repeat accept is a retry whose first response was lost: a no-op.
	if err := e.s.Ack(ctx, e.a, a, agentapi.Ack{Accepted: true}); err != nil {
		t.Fatalf("second ack (a retry): %v", err)
	}
	wantHTTPError(t, "reject after accepting", e.s.Ack(ctx, e.a, a, agentapi.Ack{Accepted: false}), 409)
	e.dsResult(a, "succeeded", nil)
	wantHTTPError(t, "ack after the result", e.s.Ack(ctx, e.a, a, agentapi.Ack{Accepted: true}), 409)
	if at := e.dsAttempt(id, a); at.State != "succeeded" {
		t.Fatalf("attempt %s after refused acks", at.State)
	}
	if st := e.run(id)["status"]; st != "succeeded" {
		t.Fatalf("run %v", st)
	}
}

// ---------------------------------------------------------------------------
// Heartbeat and Hello lease renewal
// ---------------------------------------------------------------------------

func TestHeartbeatRenewsOnlyListedAttempts(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	r1, r2 := e.startNamed("one"), e.startNamed("two")
	a1, a2 := e.poll(), e.poll()
	if a1 == "" || a2 == "" {
		t.Fatal("expected two dispatches")
	}
	e.ack(a1)
	e.ack(a2)
	// Both leases have run out, but the sweeper hasn't run yet.
	e.dsExec(`UPDATE step_attempts SET lease_expires_at = now() - interval '1 second'`)
	e.dsExec(`UPDATE agents SET status = 'offline', last_seen_at = now() - interval '1 hour' WHERE id = $1`, e.a.AgentID)

	// Another agent can't renew this agent's attempts.
	if err := e.s.Heartbeat(ctx, e.dsAgent(), agentapi.Heartbeat{InFlight: []string{a1, a2}}); err != nil {
		t.Fatal(err)
	}
	if e.dsAttempt(r1, a1).LeaseLeft.Float64 > 0 {
		t.Fatal("another agent's heartbeat renewed the lease")
	}

	if err := e.s.Heartbeat(ctx, e.a, agentapi.Heartbeat{InFlight: []string{a1}}); err != nil {
		t.Fatal(err)
	}
	// A running attempt's lease is the longer RunningLease (5m by default).
	if left := e.dsAttempt(r1, a1).LeaseLeft.Float64; left < 295 || left > 301 {
		t.Fatalf("listed attempt's lease has %.1fs left; want ~300s", left)
	}
	if left := e.dsAttempt(r2, a2).LeaseLeft.Float64; left > 0 {
		t.Fatalf("unlisted attempt's lease was renewed (%.1fs left)", left)
	}
	if n := e.dsCount(`SELECT count(*) FROM agents WHERE id = $1 AND status = 'online' AND last_seen_at > now() - interval '1 minute'`, e.a.AgentID); n != 1 {
		t.Fatal("heartbeat didn't mark the agent online")
	}

	if _, err := e.s.ProcessExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if st := e.dsAttempt(r1, a1).State; st != "running" {
		t.Fatalf("renewed attempt is %s", st)
	}
	if st := e.dsAttempt(r2, a2).State; st != "lost" {
		t.Fatalf("unrenewed attempt is %s, want lost", st)
	}

	// A finished attempt listed in a heartbeat stays finished.
	e.dsResult(a1, "succeeded", nil)
	if err := e.s.Heartbeat(ctx, e.a, agentapi.Heartbeat{InFlight: []string{a1, a2}}); err != nil {
		t.Fatal(err)
	}
	if at := e.dsAttempt(r1, a1); at.State != "succeeded" {
		t.Fatalf("heartbeat revived a finished attempt: %+v", at)
	}
	if at := e.dsAttempt(r2, a2); at.State != "lost" {
		t.Fatalf("heartbeat revived a lost attempt: %+v", at)
	}
}

// Heartbeats keep a step alive only once it's acknowledged: an attempt the
// agent never acked still goes back to the queue when its lease runs out
// (§5.2: "If the lease expires without an Ack, the attempt returns to queued").
func TestHeartbeatDoesNotExtendUnackedDispatch(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()
	e.dsExec(`UPDATE step_attempts SET lease_expires_at = now() - interval '1 second'`)
	if err := e.s.Heartbeat(ctx, e.a, agentapi.Heartbeat{InFlight: []string{a}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.ProcessExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if at := e.dsAttempt(id, a); at.State != "queued" {
		t.Fatalf("unacked attempt listed in a heartbeat is %s after its lease ran out; want queued", at.State)
	}
}

func TestHelloReconcilesInFlight(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	if _, err := e.s.Hello(ctx, e.a, agentapi.Hello{ProtocolVersion: agentapi.ProtocolVersion + 1}); err == nil {
		t.Fatal("unsupported protocol version accepted")
	} else {
		wantHTTPError(t, "hello with a newer protocol", err, 426)
	}
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()
	e.ack(a)
	e.dsExec(`UPDATE step_attempts SET lease_expires_at = now() - interval '1 second'`)
	// The agent reconnects and reports the step it's still running.
	w, err := e.s.Hello(ctx, e.a, agentapi.Hello{ProtocolVersion: agentapi.ProtocolVersion, AgentVersion: "t", Slots: 2, InFlight: []string{a}})
	if err != nil {
		t.Fatal(err)
	}
	if w.AgentID != e.a.AgentID || w.Labels["env"] != "prod" {
		t.Fatalf("welcome: %+v", w)
	}
	if _, err := e.s.ProcessExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if at := e.dsAttempt(id, a); at.State != "running" {
		t.Fatalf("attempt reported in Hello.in_flight is %s", at.State)
	}
}

// ---------------------------------------------------------------------------
// Retries, backoff and onFailure
// ---------------------------------------------------------------------------

// Failed and timed-out attempts are retried `retries` times with exponential
// backoff (runbook-schema.md §3.7), then the step's onFailure applies.
func TestFailedStepRetriesWithBackoff(t *testing.T) {
	e := setupRunHarness(t)
	id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      retries: 3\n      run: echo hi\n" +
		"    - id: s2\n      type: shell\n      run: echo next\n"}, "")
	statuses := []string{"failed", "timed_out", "failed", "failed"}
	var prev []float64
	for i, status := range statuses {
		a := e.poll()
		if a == "" {
			t.Fatalf("attempt %d wasn't dispatched once its backoff passed", i+1)
		}
		if at := e.dsAttempt(id, a); at.N != i+1 || at.StepID != "s1" {
			t.Fatalf("dispatch %d is %s #%d", i+1, at.StepID, at.N)
		}
		e.ack(a)
		e.dsResult(a, status, nil)
		if i == len(statuses)-1 {
			break
		}
		if next := e.poll(); next != "" {
			t.Fatalf("retry #%d dispatched immediately after attempt %d %s; want a backoff", i+2, i+1, status)
		}
		got := e.dsAttempts(id)
		last := got[len(got)-1]
		if last.N != i+2 || last.State != "queued" || !last.NotBefore.Valid {
			t.Fatalf("retry: %+v", last)
		}
		prev = append(prev, last.BackoffAfterPrev.Float64)
		e.dsExec(`UPDATE step_attempts SET not_before = now() WHERE id = $1`, last.ID)
	}
	for i := 1; i < len(prev); i++ {
		if prev[i] < 1.9*prev[i-1] || prev[i] > 2.1*prev[i-1] {
			t.Fatalf("backoffs %v don't double", prev)
		}
	}
	if prev[0] < 1 || prev[len(prev)-1] > 60 {
		t.Fatalf("backoffs %v out of range", prev)
	}
	got := e.dsAttempts(id)
	if len(got) != 4 {
		t.Fatalf("%d attempts; want 1 + 3 retries", len(got))
	}
	if st := e.run(id)["status"]; st != "failed" {
		t.Fatalf("run %v once retries ran out (default onFailure: stop)", st)
	}
	if e.dsCount(`SELECT count(*) FROM step_attempts WHERE step_id = 's2'`) != 0 {
		t.Fatal("the next step ran after a stopped failure")
	}
}

func TestTimedOutStepFailsRunAsTimedOut(t *testing.T) {
	e := setupRunHarness(t)
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()
	e.ack(a)
	e.dsResult(a, "timed_out", nil)
	if st := e.run(id)["status"]; st != "timed_out" {
		t.Fatalf("run %v", st)
	}
}

func TestStepOnFailure(t *testing.T) {
	next := "    - id: s2\n      type: shell\n      run: echo next\n"
	cases := []struct {
		onFailure, runbookOnFailure string
		wantRun                     string
		wantNext, wantPage          bool
	}{
		{"stop", "none", "failed", false, false},
		{"stop", "", "failed", false, true}, // runbook onFailure defaults to escalate
		{"continue", "", "succeeded", true, false},
		{"escalate", "none", "failed", false, true},
	}
	for _, c := range cases {
		t.Run(c.onFailure+"/"+c.runbookOnFailure, func(t *testing.T) {
			e := setupRunHarness(t)
			inc := e.dsIncident()
			id := e.dsStart(dsRB{steps: "    - id: s1\n      type: shell\n      onFailure: " + c.onFailure + "\n      run: exit 1\n" + next,
				onFailure: c.runbookOnFailure}, `"incident":1`)
			a := e.poll()
			e.ack(a)
			e.dsResult(a, "failed", map[string]any{"why": "boom"})
			a2 := e.poll()
			if (a2 != "") != c.wantNext {
				t.Fatalf("next step dispatched: %v, want %v", a2 != "", c.wantNext)
			}
			if a2 != "" {
				e.ack(a2)
				e.dsResult(a2, "succeeded", nil)
			}
			if st := e.run(id)["status"]; st != c.wantRun {
				t.Fatalf("run %v, want %s", st, c.wantRun)
			}
			if p := e.dsPaged(inc); p != c.wantPage {
				t.Fatalf("paged: %v, want %v", p, c.wantPage)
			}
		})
	}
}

// policy.concurrency limits simultaneous runs per parameter set.
func TestRunConcurrencyPerParameterSet(t *testing.T) {
	e := setupRunHarness(t)
	rb := dsRB{params: dsModeParam, policy: "    concurrency: 2\n", steps: dsShell}
	e.dsStart(rb, `"params":{"mode":"fast"}`)
	e.dsStart(rb, `"params":{"mode":"fast"}`)
	if code, out := e.call("POST", "/v1/runs", []byte(`{"runbook":"qa","params":{"mode":"fast"}}`)); code != 409 || !strings.Contains(fmt.Sprint(out), "limit 2") {
		t.Fatalf("third concurrent run: %d %v", code, out)
	}
	// Other parameters are another slot; the default resolves to the same set.
	e.dsStart(rb, `"params":{"mode":"slow"}`)
	if code, _ := e.call("POST", "/v1/runs", []byte(`{"runbook":"qa"}`)); code != 409 {
		t.Fatalf("default params (= fast) bypassed the limit: %d", code)
	}
	// A finished run frees its slot.
	a := e.poll()
	e.ack(a)
	e.dsResult(a, "succeeded", nil)
	e.dsStart(rb, `"params":{"mode":"fast"}`)
}

// ---------------------------------------------------------------------------
// when: conditions (evaluated on the control plane)
// ---------------------------------------------------------------------------

func TestWhenSkipsAndRunsSteps(t *testing.T) {
	steps := "    - id: slow\n      type: shell\n      when: params.mode == \"slow\"\n      run: echo slow\n" +
		"    - id: fast\n      type: shell\n      when: params.mode == \"fast\"\n      run: echo fast\n" +
		"    - id: gate\n      type: approval\n      when: params.mode == \"slow\"\n"
	for _, mode := range []string{"fast", "slow"} {
		t.Run(mode, func(t *testing.T) {
			e := setupRunHarness(t)
			id := e.dsStart(dsRB{params: dsModeParam, steps: steps}, `"params":{"mode":"`+mode+`"}`)
			a := e.poll()
			if at := e.dsAttempt(id, a); at.StepID != mode {
				t.Fatalf("mode %s dispatched step %s first", mode, at.StepID)
			}
			e.ack(a)
			e.dsResult(a, "succeeded", nil)
			if mode == "slow" {
				if n := e.poll(); n != "" {
					t.Fatalf("mode slow ran the fast step (%s)", e.dsAttempt(id, n).StepID)
				}
				if st := e.run(id)["status"]; st != "awaiting_approval" {
					t.Fatalf("run %v; want the approval gate (when true)", st)
				}
				return
			}
			if st := e.run(id)["status"]; st != "succeeded" {
				t.Fatalf("run %v; want succeeded with the approval gate skipped", st)
			}
			runID, _ := ids.Decode("run", id)
			var skipped string
			e.s.DB.WithOrg(context.Background(), e.a.OrgID, func(tx *db.Tx) error {
				return tx.QueryRow(`SELECT context->'steps'->'slow'->>'status' || ',' || (context->'steps'->'gate'->>'status')
					FROM runbook_runs WHERE id = $1`, runID).Scan(&skipped)
			})
			if skipped != "skipped,skipped" {
				t.Fatalf("skipped steps recorded as %q", skipped)
			}
			if n := e.dsCount(`SELECT count(*) FROM approval_gates`); n != 0 {
				t.Fatalf("%d approval gates opened for a skipped approval step", n)
			}
		})
	}
}

func TestWhenReadsEarlierStepOutputs(t *testing.T) {
	e := setupRunHarness(t)
	id := e.dsStart(dsRB{steps: "    - id: check\n      type: shell\n      run: echo hi\n      outputs:\n        healthy: result.exitCode == 0\n        replicas: result.exitCode\n" +
		"    - id: fix\n      type: shell\n      when: '!steps.check.outputs.healthy && steps.check.outputs.replicas < 5'\n      run: echo fix\n" +
		"    - id: scale\n      type: shell\n      when: steps.check.outputs.replicas >= 5\n      run: echo scale\n" +
		"    - id: verify\n      type: shell\n      when: steps.fix.status == \"succeeded\" && steps.scale.status == \"skipped\"\n      run: echo verify\n"}, "")
	a := e.poll()
	e.ack(a)
	// Outputs round-trip through jsonb: numbers come back as doubles.
	e.dsResult(a, "succeeded", map[string]any{"healthy": false, "replicas": 3})
	var ran []string
	for {
		n := e.poll()
		if n == "" {
			break
		}
		ran = append(ran, e.dsAttempt(id, n).StepID)
		e.ack(n)
		e.dsResult(n, "succeeded", nil)
	}
	if strings.Join(ran, ",") != "fix,verify" {
		t.Fatalf("ran %v after check; want fix,verify", ran)
	}
	if st := e.run(id)["status"]; st != "succeeded" {
		t.Fatalf("run %v", st)
	}
}

// A `when` that can't be evaluated fails the run before the step: skipping
// could skip a safety check and running could run a dangerous step, so
// neither is a safe guess. The failure escalates like any other.
func TestWhenErrorFailsRun(t *testing.T) {
	for name, when := range map[string]string{
		"missing output": "steps.check.outputs.nope == 1",
		"not a bool":     "params.mode",
		"unknown step":   "steps.nosuch.status == \"succeeded\"",
	} {
		t.Run(name, func(t *testing.T) {
			e := setupRunHarness(t)
			inc := e.dsIncident()
			id := e.dsStart(dsRB{params: dsModeParam, steps: "    - id: check\n      type: shell\n      run: echo hi\n" +
				"    - id: fix\n      type: shell\n      when: '" + when + "'\n      run: echo fix\n"}, `"incident":1`)
			a := e.poll()
			e.ack(a)
			e.dsResult(a, "succeeded", map[string]any{"healthy": true})
			if n := e.poll(); n != "" {
				t.Fatalf("step with an erroring when was dispatched")
			}
			run := e.run(id)
			if run["status"] != "failed" || !strings.Contains(fmt.Sprint(run["error"]), "step fix: when:") {
				t.Fatalf("run %v (%v)", run["status"], run["error"])
			}
			if !e.dsPaged(inc) {
				t.Fatal("a run that failed on its when condition didn't escalate")
			}
		})
	}
}

// A `when` on the first step is evaluated as the run starts.
func TestWhenOnFirstStep(t *testing.T) {
	e := setupRunHarness(t)
	id := e.dsStart(dsRB{params: dsModeParam, steps: "    - id: s1\n      type: shell\n      when: params.mode == \"slow\"\n      run: echo hi\n"}, "")
	if st := e.run(id)["status"]; st != "succeeded" {
		t.Fatalf("run whose only step is skipped: %v", st)
	}
	if n := e.poll(); n != "" {
		t.Fatal("skipped step was dispatched")
	}
	e2 := setupRunHarness(t)
	id2 := e2.dsStart(dsRB{params: dsModeParam, steps: "    - id: s1\n      type: shell\n      when: params.nosuch == 1\n      run: echo hi\n"}, "")
	if st := e2.run(id2)["status"]; st != "failed" {
		t.Fatalf("run whose first when errors: %v", st)
	}
}

// ---------------------------------------------------------------------------
// Agent certificates (§3.2)
// ---------------------------------------------------------------------------

func dsCertRequest(cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest("POST", "/agent/v1/heartbeat", strings.NewReader(`{"in_flight":[]}`))
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}

func dsFakeCert(serial *big.Int, uris ...string) *x509.Certificate {
	c := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	for _, s := range uris {
		u, _ := url.Parse(s)
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestAuthenticateAgentCertRollover(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	uri := AgentURI(e.a.OrgID, e.a.AgentID)
	oldSerial := big.NewInt(0x1001)
	e.dsExec(`UPDATE agents SET cert_serial = $2 WHERE id = $1`, e.a.AgentID, SerialHex(oldSerial))
	oldCert := dsFakeCert(oldSerial, uri)

	auth := func(c *x509.Certificate) (agentIdentity, error) {
		return e.s.authenticateAgent(dsCertRequest(c))
	}
	refused := func(what string, c *x509.Certificate) {
		t.Helper()
		var ae authError
		if _, err := auth(c); !errors.As(err, &ae) {
			t.Fatalf("%s: got %v, want an auth error", what, err)
		}
	}
	a, err := auth(oldCert)
	if err != nil || a.AgentID != e.a.AgentID || a.OrgID != e.a.OrgID || a.Serial != SerialHex(oldSerial) {
		t.Fatalf("current cert: %+v %v", a, err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nightfix-agent"}}, priv)
	resp, err := e.s.Renew(ctx, a, agentapi.RenewRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(resp.CertPEM))
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Until the new certificate is used, the old one keeps working...
	if _, err := auth(oldCert); err != nil {
		t.Fatalf("previous cert right after renewal: %v", err)
	}
	// ...but only until its expiry.
	e.dsExec(`UPDATE agents SET prev_cert_expires_at = now() - interval '1 second' WHERE id = $1`, e.a.AgentID)
	refused("previous cert after its expiry", oldCert)
	e.dsExec(`UPDATE agents SET prev_cert_expires_at = now() + interval '1 hour' WHERE id = $1`, e.a.AgentID)
	if _, err := auth(oldCert); err != nil {
		t.Fatalf("previous cert before its expiry: %v", err)
	}

	// The first request with the new certificate retires the old one.
	a, err = auth(newCert)
	if err != nil || a.Serial != SerialHex(newCert.SerialNumber) {
		t.Fatalf("new cert: %+v %v", a, err)
	}
	if n := e.dsCount(`SELECT count(*) FROM agents WHERE id = $1 AND prev_cert_serial IS NULL AND prev_cert_expires_at IS NULL`, e.a.AgentID); n != 1 {
		t.Fatal("using the new certificate didn't retire the previous one")
	}
	refused("previous cert once the new one was used", oldCert)
	if _, err := auth(newCert); err != nil {
		t.Fatalf("new cert again: %v", err)
	}
}

func TestAuthenticateAgentRefusesMismatchedIdentity(t *testing.T) {
	e := setupRunHarness(t)
	other := e.dsAgent()
	serial := big.NewInt(0x2002)
	e.dsExec(`UPDATE agents SET cert_serial = $2 WHERE id = $1`, e.a.AgentID, SerialHex(serial))
	e.dsExec(`UPDATE agents SET prev_cert_serial = 'aa', prev_cert_expires_at = now() + interval '1 hour' WHERE id = $1`, e.a.AgentID)
	e2 := setupRunHarness(t)

	for name, c := range map[string]*x509.Certificate{
		"another agent's URI":        dsFakeCert(serial, AgentURI(e.a.OrgID, other.AgentID)),
		"another org's URI":          dsFakeCert(serial, AgentURI(e2.a.OrgID, e.a.AgentID)),
		"no URI SAN":                 dsFakeCert(serial),
		"lookalike URI":              dsFakeCert(serial, AgentURI(e.a.OrgID, e.a.AgentID)+"x"),
		"unknown serial, right URI":  dsFakeCert(big.NewInt(0x3003), AgentURI(e.a.OrgID, e.a.AgentID)),
		"other agent's serial + URI": dsFakeCert(serial, AgentURI(other.OrgID, other.AgentID)),
		// Valid at the handshake, expired since (a kept-alive connection).
		"expired certificate": func() *x509.Certificate {
			c := dsFakeCert(serial, AgentURI(e.a.OrgID, e.a.AgentID))
			c.NotAfter = time.Now().Add(-time.Second)
			return c
		}(),
	} {
		var ae authError
		if _, err := e.s.authenticateAgent(dsCertRequest(c)); !errors.As(err, &ae) {
			t.Errorf("%s: got %v, want an auth error", name, err)
		}
	}
	// A refused request mustn't retire the agent's previous certificate.
	if n := e.dsCount(`SELECT count(*) FROM agents WHERE id = $1 AND prev_cert_serial = 'aa'`, e.a.AgentID); n != 1 {
		t.Fatal("a refused certificate retired the previous serial")
	}

	// No client certificate at all.
	r := httptest.NewRequest("POST", "/agent/v1/heartbeat", strings.NewReader(`{}`))
	var ae authError
	if _, err := e.s.authenticateAgent(r); !errors.As(err, &ae) {
		t.Fatalf("no TLS: %v", err)
	}
	// Through the gateway, refusals are 401 and a good certificate is served.
	w := httptest.NewRecorder()
	e.s.AgentHandler().ServeHTTP(w, dsCertRequest(dsFakeCert(serial)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("gateway with a mismatched cert: %d", w.Code)
	}
	w = httptest.NewRecorder()
	e.s.AgentHandler().ServeHTTP(w, dsCertRequest(dsFakeCert(serial, AgentURI(e.a.OrgID, e.a.AgentID))))
	if w.Code != http.StatusOK {
		t.Fatalf("gateway heartbeat with a good cert: %d %s", w.Code, w.Body)
	}
}

func TestRetryBackoffIsCapped(t *testing.T) {
	for n, want := range map[int]time.Duration{2: 2 * time.Second, 3: 4 * time.Second, 6: 32 * time.Second, 7: time.Minute, 11: time.Minute} {
		if got := retryBackoff(n); got != want {
			t.Errorf("retryBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// A result that arrives after its attempt was declared lost (the agent was
// quiet past its running lease) can't change the run any more, but it's
// recorded, once, so whoever handles the run knows what happened.
func TestLateResultForLostAttemptIsRecorded(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	r1 := e.startNamed("one")
	a1 := e.poll()
	if a1 == "" {
		t.Fatal("expected a dispatch")
	}
	e.ack(a1)
	e.dsExec(`UPDATE step_attempts SET lease_expires_at = now() - interval '1 second'`)
	if _, err := e.s.ProcessExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if st := e.dsAttempt(r1, a1).State; st != "lost" {
		t.Fatalf("attempt is %q after its lease expired, want lost", st)
	}
	for range 2 {
		if err := e.s.Result(ctx, e.a, a1, agentapi.Result{Status: "succeeded"}); err != nil {
			t.Fatalf("late result: %v", err)
		}
	}
	state := e.dsAttempt(r1, a1).State
	noted := e.dsCount(`SELECT (length(error) - length(replace(error, 'late result: succeeded', ''))) / length('late result: succeeded')
		FROM step_attempts WHERE id = $1`, a1)
	errText := fmt.Sprintf("%d note(s)", noted)
	if state != "lost" || noted != 1 {
		t.Fatalf("after a late result the attempt is %q with error %q; want lost, noted once", state, errText)
	}
}
