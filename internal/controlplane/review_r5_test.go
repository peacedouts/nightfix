package controlplane

// Independent review (round 5): failing control-plane tests.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
)

// Each step may return up to 1 MiB of outputs (the agent's cap), and every
// later dispatch envelope carries the whole run context, every earlier
// step's outputs included, whether or not the step uses them. The agent
// reads at most 16 MiB of a poll response (agent/client.go), so from the
// 17th such step on the dispatch can't be decoded: the agent treats the poll
// as failed, the attempt sits dispatched until its lease expires, is
// re-queued, and is handed out again the same way until the run times out.
func TestReviewDispatchEnvelopeStaysReadableByTheAgent(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	var steps strings.Builder
	const n = 18
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&steps, "    - id: s%d\n      type: shell\n      run: \"true\"\n", i)
	}
	e.startRun(steps.String())
	blob := strings.Repeat("a", 1000*1000) // under the agent's 1 MiB outputs cap
	// Every dispatch the agent gets stays readable; once the run's outputs
	// outgrow what can be sent, the run fails instead of wedging.
	for i := 1; i <= n; i++ {
		resp, err := e.s.Poll(ctx, e.a, agentapi.PollRequest{FreeSlots: 1})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Dispatch == nil {
			break
		}
		if b, _ := json.Marshal(resp); len(b) > 16<<20 {
			t.Fatalf("the dispatch for step s%d is %.1f MiB; the agent reads at most 16 MiB", i, float64(len(b))/(1<<20))
		}
		var env struct {
			AttemptID string `json:"attempt_id"`
		}
		json.Unmarshal([]byte(resp.Dispatch.Envelope.Payload), &env)
		e.ack(env.AttemptID)
		if err := e.s.Result(ctx, e.a, env.AttemptID, agentapi.Result{Status: "succeeded", Outputs: map[string]any{"blob": blob}}); err != nil {
			t.Fatalf("result %d: %v", i, err)
		}
	}
	var status, msg string
	e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT status, coalesce(error, '') FROM runbook_runs`).Scan(&status, &msg)
	})
	if status != "failed" || !strings.Contains(msg, "outputs total") {
		t.Fatalf("run with outputs too large to send: %s %q", status, msg)
	}
}
