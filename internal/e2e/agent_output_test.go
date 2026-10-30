package e2e

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent"
)

func shellRunbook(name, env, script string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: %s
  title: V3B probe
  team: platform
spec:
  target:
    agentSelector:
      env: %s
  triggers:
    - type: manual
  policy:
    allowedRoles: [Responder, Admin]
    timeout: 15m
  steps:
    - id: s
      name: probe
      type: shell
      timeout: 5m
      run: |
`, name, env)
	for _, l := range strings.Split(script, "\n") {
		b.WriteString("        " + l + "\n")
	}
	return b.String()
}

func (e *env) tokenAgent(env, stateDir, endpoint string, logs *syncBuf) (context.CancelFunc, chan struct{}) {
	var enr map[string]string
	e.call("POST", "/v1/enrollment-rules", map[string]any{"method": "token", "labels": map[string]string{"env": env}}, &enr)
	ag, err := agent.New(agent.Config{Endpoint: endpoint, CAPEM: e.caPEM, EnrollMethod: "token",
		EnrollToken: enr["token"], StateDir: stateDir, AWS: e.aws, Log: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() { ag.Run(ctx); close(done) }()
	return cancel, done
}

func (e *env) startRunbook(runbook string) string {
	out := e.expect("starter", e.key, "POST", "/v1/runs", map[string]any{"runbook": runbook, "params": map[string]string{}}, 200, "run_")
	id := out[strings.Index(out, "run_"):]
	return id[:strings.IndexAny(id, `"`)]
}

func (e *env) attemptState(runID string) string {
	atts, _ := e.run(runID)["attempts"].([]any)
	if len(atts) == 0 {
		return ""
	}
	return fmt.Sprint(atts[len(atts)-1].(map[string]any)["state"])
}

// A step whose output is binary (NUL bytes here; invalid UTF-8 and control
// characters behave the same) JSON-encodes at 6 bytes per byte. One output
// batch of up to 64 x 32 KiB chunks then exceeds the gateway's 4 MiB body
// limit and is refused with 400 on every retry. streamer.close now retries
// that for outputRetryFor (2 min) before the result is sent, so the run
// sits for 2 minutes (and on shutdown, the 40s grace expires and the result
// is never sent).
func TestBinaryOutputDelaysResult(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var pub map[string]any
	e.callRaw("PUT", "/v1/runbooks/out-bin", []byte(shellRunbook("out-bin", "bin", "head -c 1000000 /dev/zero\necho done")), &pub)
	logs := &syncBuf{}
	e.tokenAgent("bin", t.TempDir(), e.gwURL, logs)
	time.Sleep(3 * time.Second)
	runID := e.startRunbook("out-bin")
	start := time.Now()
	var status any
	for time.Since(start) < 25*time.Second {
		status = e.run(runID)["status"]
		if status == "succeeded" || status == "failed" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	l := logs.String()
	t.Logf("after %v: run %v, attempt %s; output upload failures in agent log: %d",
		time.Since(start).Round(time.Second), status, e.attemptState(runID), strings.Count(l, "output upload failed"))
	if i := strings.Index(l, "output upload failed"); i >= 0 {
		t.Logf("first failure: %.300s", l[i:])
	}
	if status != "succeeded" {
		t.Errorf("a one-second step that printed 1 MB of binary output still has no result after 25s (run %v)", status)
	}
}

// agent-protocol.md §8.2: "Agent restarts mid-step: the subprocess dies with
// it. On reconnect, the agent reports the attempt as lost from its side."
// The agent here is cut off, stopped (its "cancelled" result can't get
// through within the shutdown grace) and restarted with the same identity.
// Its Hello lists nothing in flight, yet the control plane keeps the attempt
// "running" until the running lease (now 5 minutes, was 30s) expires.
func TestRestartedAgentDoesNotFreeItsAttempt(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var pub map[string]any
	e.callRaw("PUT", "/v1/runbooks/out-long", []byte(shellRunbook("out-long", "restart", "sleep 300")), &pub)
	cut := newCutter(t, strings.TrimPrefix(e.gwURL, "https://"))
	state := t.TempDir()
	logs := &syncBuf{}
	cancel, done := e.tokenAgent("restart", state, "https://"+cut.ln.Addr().String(), logs)
	time.Sleep(3 * time.Second)
	runID := e.startRunbook("out-long")
	e.waitFor("step running", 20*time.Second, func() bool { return e.attemptState(runID) == "running" })

	cut.setDown(true)
	cancel()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("agent did not stop")
	}
	stoppedAt := time.Now()
	cut.setDown(false)
	// Same state dir, same identity: a restart.
	ag, err := agent.New(agent.Config{Endpoint: "https://" + cut.ln.Addr().String(), CAPEM: e.caPEM, EnrollMethod: "token",
		StateDir: state, AWS: e.aws, Log: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	go ag.Run(e.ctx)
	time.Sleep(30 * time.Second)
	st := e.attemptState(runID)
	t.Logf("%v after the agent stopped and 30s after it restarted with nothing in flight: attempt %s, run %v",
		time.Since(stoppedAt).Round(time.Second), st, e.run(runID)["status"])
	if st == "running" {
		t.Errorf("the restarted agent reported no attempts in flight, but the control plane still has its attempt running; it waits out the 5-minute running lease")
	}
}
