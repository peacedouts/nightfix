package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/signing"
)

// A step's inputs never see alert data, even in a bundle that skipped the
// control plane's linter: the alert's labels arrive unvalidated in the
// envelope, and whoever shaped them would choose what the step acts on.
func TestStepInputsDontSeeAlertData(t *testing.T) {
	src := strings.Replace(verifyRunbook, "service: ${{ params.service }}", "service: ${{ alert.labels.service }}", 1)
	f, gw := newResFixture(t, src, Config{})
	d := f.dispatch(func(e *signing.Envelope) {
		e.Context = map[string]any{"alert": map[string]any{"labels": map[string]any{"service": "payments"}}}
	})
	attempt := attemptIDOf(d)
	gw.mu.Lock()
	gw.queue = append(gw.queue, d)
	gw.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.agent.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "the result", func() bool { return len(gw.resultsFor(attempt)) > 0 })
	if res := gw.resultsFor(attempt)[0]; res.Status != "failed" {
		t.Fatalf("result %+v, want failed", res)
	}
	if f.aws.count() != 0 {
		t.Fatal("the AWS call ran with a value taken from the alert")
	}
}

// Chunks are sized as the control plane stores them: NUL becomes U+FFFD
// there (three bytes for one), so a full chunk of NULs sized before that
// would be cut on arrival.
func TestNULOutputChunksFitAfterReplacement(t *testing.T) {
	s := &sink{}
	st := newStreamer(newTestAgent(t, s), "att")
	w := st.writer("stdout")
	nul := strings.Repeat("\x00", 4096)
	for i := 0; i < 32; i++ {
		w.Write([]byte(nul))
	}
	st.close()
	for _, c := range s.chunks {
		if n := len(strings.ReplaceAll(c.Data, "\x00", "�")); n > agentapi.MaxChunkBytes {
			t.Fatalf("a chunk is %d bytes as stored", n)
		}
	}
}

// Step outputs feed later steps' inputs, so they can't read alert data
// either.
func TestStepOutputsDontSeeAlertData(t *testing.T) {
	f := newVerifyFixture(t, Config{})
	v := &verified{env: signing.Envelope{Context: map[string]any{"alert": map[string]any{"labels": map[string]any{"service": "payments"}}}}}
	vars := f.agent.inputVars(v, nil)
	if _, ok := vars["alert"]; ok {
		t.Fatal("outputs and inputs can read alert data")
	}
}

// An agent set to run only some step types advertises just those, and
// refuses the others even if a control plane sends one anyway.
func TestStepTypesLimitWhatAnAgentRuns(t *testing.T) {
	f := newVerifyFixture(t, Config{StepTypes: []string{"aws", "wait"}})
	if got := f.agent.capabilities(); contains(got, "shell") || !contains(got, "aws") {
		t.Fatalf("capabilities %v", got)
	}
	f.bundle = f.signedBundle(shellRunbook("echo hi"), f.cp)
	ack := f.deliver(f.dispatch(func(e *signing.Envelope) { e.StepID = "script"; e.StepIndex = 0 }))
	if ack.Accepted || !strings.Contains(ack.Reason, "not supported") {
		t.Fatalf("a shell step was accepted by an agent without shell: %+v", ack)
	}
	if _, err := New(Config{Endpoint: "https://x", StepTypes: []string{"python"}}); err == nil {
		t.Fatal("an unknown step type was accepted")
	}
}

// The allowlist can be given inline (NIGHTFIX_ALLOWLIST, for ECS), and an
// empty one in warn or enforce mode is refused at start rather than
// silently refusing (or allowing) everything.
func TestInlineAllowlist(t *testing.T) {
	f := newVerifyFixture(t, Config{AllowlistMode: "enforce", AllowlistYAML: "runbooks:\n  - name: ecs-restart\n    version: \"*\"\n"})
	if f.agent.allowlist == nil || len(f.agent.allowlist.Runbooks) != 1 {
		t.Fatalf("inline allowlist not loaded: %+v", f.agent.allowlist)
	}
	// With both, the file wins: the inline list allows ecs-restart, the file
	// doesn't, so it's refused.
	both := newVerifyFixture(t, Config{AllowlistMode: "enforce",
		AllowlistFile: writeAllowlist(t, "runbooks:\n  - name: aurora-failover\n    version: \"*\"\n"),
		AllowlistYAML: "runbooks:\n  - name: ecs-restart\n    version: \"*\"\n"})
	both.assertRefused(both.dispatch(nil), "not on the local allowlist")
	for _, c := range []Config{
		{Endpoint: "https://x", AllowlistMode: "enforce"},
		{Endpoint: "https://x", AllowlistMode: "warn", AllowlistYAML: "  \n"},
		{Endpoint: "https://x", AllowlistMode: "strict"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}
