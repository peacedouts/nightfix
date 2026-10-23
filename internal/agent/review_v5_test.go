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
