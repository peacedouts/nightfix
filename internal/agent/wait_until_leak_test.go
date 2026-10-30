package agent

// A wait step's `until` is evaluated against the check's response, and an
// evaluation error is streamed as a log line. Secret material in the response
// (GetSecretValue, SSM SecureString, KMS Decrypt) must be redacted from that
// line too, not only the step's declared secrets: a CEL error can quote a
// value ("no such key: <value>", a regexp error quoting the pattern).

import (
	"context"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/runbook"
)

func TestWaitUntilErrorDoesNotLeakSecretMaterial(t *testing.T) {
	const secret = "db-master-password-7f3a91"
	calls := 0
	h := newVHarness(t, awsFunc(func(context.Context, string, string, map[string]any) (map[string]any, error) {
		calls++
		return map[string]any{"Parameter": map[string]any{"Name": "/db/state", "Type": "SecureString", "Value": secret}}, nil
	}))
	st := runbook.Step{ID: "w", Type: "wait", Interval: "1s", Timeout: "3s",
		Check: &runbook.Check{AWS: &runbook.AWSCall{Service: "ssm", Action: "GetParameter", Input: map[string]any{"Name": "/db/state"}}},
		// A lookup table keyed by the parameter's value: errors with "no such
		// key" while the value isn't one of the expected states.
		Until: `{"ready": true, "done": true}[result.Parameter.Value]`}
	res, sent := h.run(vStep(st, nil), 3*time.Second)
	if calls == 0 {
		t.Fatal("check never ran")
	}
	if leaks := findLeaks(res, sent, secret); len(leaks) > 0 {
		t.Fatalf("SecureString value leaked: %+v\nstream: %q", leaks, sent)
	}
}
