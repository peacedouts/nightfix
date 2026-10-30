package controlplane

import (
	"context"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/agentapi"
)

// Result's new outputs cap ("hold the control plane to the same bound
// whatever an agent sends") applies only when the status is "succeeded". The
// same 3 MiB of outputs reported with status "failed" is stored as is.
func TestOutputsCapBypassedByNonSuccessStatus(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	e.startNamed("one")
	a1 := e.poll()
	if a1 == "" {
		t.Fatal("expected a dispatch")
	}
	e.ack(a1)
	big := map[string]any{"x": strings.Repeat("a", 3<<20)}
	if err := e.s.Result(ctx, e.a, a1, agentapi.Result{Status: "failed", Error: "boom", Outputs: big}); err != nil {
		t.Fatalf("result: %v", err)
	}
	n := e.dsCount(`SELECT coalesce(octet_length(outputs::text), 0) FROM step_attempts WHERE id = $1`, a1)
	t.Logf("stored outputs: %d bytes", n)
	if n > agentapi.MaxOutputBytes {
		t.Errorf("a failed result stored %d bytes of outputs, over the %d cap", n, agentapi.MaxOutputBytes)
	}
}
