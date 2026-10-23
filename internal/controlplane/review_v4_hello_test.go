package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
)

// agent.handleDispatch: when the ack's response is lost (the ack was recorded,
// so the attempt is "running"), the agent doesn't run the step, doesn't put it
// in its in-flight map, and reports it "failed ... not started" from a
// goroutine that retries with backoff, precisely so the attempt isn't declared
// lost ("may or may not have completed"). The ack failed because the gateway
// was unreachable, so the next poll fails too and the main loop says hello as
// soon as the gateway is back, listing nothing in flight. loseUnlisted then
// marks the attempt lost before the "not started" result arrives, and that
// result is only noted as late.
func TestVerify4HelloLosesAttemptWhoseAckResponseWasLost(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	inc := e.dsIncident()
	id := e.dsStart(dsRB{steps: dsShell + "    - id: s2\n      type: shell\n      run: echo next\n", onFailure: "none"}, `"incident":1`)
	a := e.poll()
	e.ack(a) // recorded; the agent never saw the response

	// Gateway back: the agent's hello wins the race with the backed-off "not
	// started" result. The agent lists the attempt as in flight until that
	// result is delivered (TestNotStartedAttemptStaysListedUntilReported).
	if _, err := e.s.Hello(ctx, e.a, agentapi.Hello{ProtocolVersion: agentapi.ProtocolVersion, AgentVersion: "t", Slots: 1,
		InFlight: []string{a}}); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Result(ctx, e.a, a, agentapi.Result{Status: "failed",
		Error: "the agent couldn't confirm the dispatch with the control plane, so the step was not started"}); err != nil {
		t.Fatal(err)
	}
	at := e.dsAttempt(id, a)
	run := e.run(id)
	t.Logf("attempt %s; run %v (%v); paged: %v", at.State, run["status"], run["error"], e.dsPaged(inc))
	if at.State == "lost" {
		t.Fatalf("a step the agent never started was declared lost (run %v: %v)", run["status"], run["error"])
	}
	if strings.Contains(fmt.Sprint(run["error"]), "may or may not have completed") {
		t.Fatalf("run says the step may have run: %v", run["error"])
	}
}

// loseUnlisted runs onAttemptFinished inside Hello with no isolation. If that
// fails for one attempt (here: its runbook version no longer decodes, as after
// a binary rollback past a new runbook field; any non-transient error does
// the same), every hello from the agent fails with 500. A restarted agent
// can't poll until a hello succeeds, so it is out of service, for all its
// work, indefinitely (the lease worker hits the same error and only backs
// off). The lease worker isolates such a row with a savepoint; Hello doesn't.
func TestVerify4HelloFailsWhenLosingAnAttemptFails(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	id := e.dsStart(dsRB{steps: dsShell}, "")
	a := e.poll()
	e.ack(a)
	// As superuser (runbook versions are immutable to the app role).
	var dbName string
	if err := e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT current_database()`).Scan(&dbName)
	}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"))
	u.Path = "/" + dbName
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`UPDATE runbook_versions SET canonical_json = replace(canonical_json, '"spec":{', '"spec":{"futureField":1,')`); err != nil {
		t.Fatal(err)
	}
	_, err = e.s.Hello(ctx, e.a, agentapi.Hello{ProtocolVersion: agentapi.ProtocolVersion, AgentVersion: "t", Slots: 1})
	t.Logf("attempt %s; hello error: %v", e.dsAttempt(id, a).State, err)
	if err != nil {
		t.Fatalf("a restarted agent's hello fails because one of its old attempts can't be finished: %v", err)
	}
}
