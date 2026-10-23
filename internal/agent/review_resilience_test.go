package agent

// Resilience review: how the agent behaves when things go wrong in a
// customer's account (shutdown mid-step, lost acks, a control plane that is
// briefly unreachable, AWS errors inside wait loops, orphaned processes).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// resGW is a fake control plane that serves hello and poll, records acks,
// results and output, and lets a test intercept any request.
type resGW struct {
	mu      sync.Mutex
	welcome agentapi.Welcome
	queue   []agentapi.Dispatch
	acks    map[string][]agentapi.Ack
	results map[string][]agentapi.Result
	chunks  map[string][]agentapi.OutputChunk
	polls   []agentapi.PollRequest
	// hook runs first; returning true means it wrote the response itself.
	hook func(w http.ResponseWriter, r *http.Request) bool
}

func (g *resGW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	hook := g.hook
	g.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	path := r.URL.Path
	attempt := strings.TrimPrefix(path, "/agent/v1/attempts/")
	switch {
	case path == "/agent/v1/hello":
		g.mu.Lock()
		json.NewEncoder(w).Encode(g.welcome)
		g.mu.Unlock()
		return
	case path == "/agent/v1/poll":
		var req agentapi.PollRequest
		json.NewDecoder(r.Body).Decode(&req)
		g.mu.Lock()
		g.polls = append(g.polls, req)
		var resp agentapi.PollResponse
		if len(g.queue) > 0 && req.FreeSlots > 0 {
			resp.Dispatch = &g.queue[0]
			g.queue = g.queue[1:]
		}
		g.mu.Unlock()
		if resp.Dispatch == nil {
			time.Sleep(100 * time.Millisecond) // a short long-poll
		}
		json.NewEncoder(w).Encode(resp)
		return
	case strings.HasSuffix(path, "/ack"):
		var ack agentapi.Ack
		json.NewDecoder(r.Body).Decode(&ack)
		g.mu.Lock()
		id := strings.TrimSuffix(attempt, "/ack")
		g.acks[id] = append(g.acks[id], ack)
		g.mu.Unlock()
	case strings.HasSuffix(path, "/result"):
		var res agentapi.Result
		json.NewDecoder(r.Body).Decode(&res)
		g.mu.Lock()
		id := strings.TrimSuffix(attempt, "/result")
		g.results[id] = append(g.results[id], res)
		g.mu.Unlock()
	case strings.HasSuffix(path, "/output"):
		var b agentapi.OutputBatch
		json.NewDecoder(r.Body).Decode(&b)
		g.mu.Lock()
		id := strings.TrimSuffix(attempt, "/output")
		g.chunks[id] = append(g.chunks[id], b.Chunks...)
		g.mu.Unlock()
	}
	w.Write([]byte("{}"))
}

func (g *resGW) resultsFor(id string) []agentapi.Result {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]agentapi.Result(nil), g.results[id]...)
}

func (g *resGW) outputFor(id string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var b strings.Builder
	for _, c := range g.chunks[id] {
		b.WriteString(c.Data)
	}
	return b.String()
}

func (g *resGW) setHook(h func(w http.ResponseWriter, r *http.Request) bool) {
	g.mu.Lock()
	g.hook = h
	g.mu.Unlock()
}

// newResFixture is a verifyFixture whose agent talks to a resGW and whose
// bundle is src, signed by the control plane key.
func newResFixture(t *testing.T, src string, cfg Config) (*verifyFixture, *resGW) {
	t.Helper()
	f := newVerifyFixture(t, cfg)
	gw := &resGW{acks: map[string][]agentapi.Ack{}, results: map[string][]agentapi.Result{}, chunks: map[string][]agentapi.OutputChunk{}}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	c, err := newClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.agent.c, f.agent.cfg.Endpoint = c, srv.URL
	f.agent.cfg.Log = quietLog()
	f.bundle = f.signedBundle(src, f.cp)
	gw.welcome = agentapi.Welcome{AgentID: testAgentID, Labels: f.agent.id.Labels, TrustConfig: f.agent.id.Trust}
	return f, gw
}

func shellRunbook(script string) string {
	var b strings.Builder
	b.WriteString(`apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: shell-probe
  title: Shell probe
spec:
  target:
    agentSelector:
      env: prod
  steps:
    - id: script
      type: shell
      timeout: 5m
      run: |
`)
	for _, l := range strings.Split(script, "\n") {
		b.WriteString("        " + l + "\n")
	}
	return b.String()
}

func shellDispatch(f *verifyFixture) agentapi.Dispatch {
	return f.dispatch(func(e *signing.Envelope) { e.StepID, e.StepIndex, e.Params = "script", 0, map[string]any{} })
}

// ECS stops a task with SIGTERM (main cancels Run's context), then SIGKILLs
// it after the stop timeout. agent-protocol.md §9: the agent SIGTERMs the
// script, waits up to 10s, and reports the attempt; the control plane's
// Result handler expects a "cancelled" report from an agent shutting down
// mid-step (it maps it to lost). main exits as soon as Run returns, so
// anything Run hasn't finished by then never happens.
func TestReviewShutdownMidStepReportsAndLetsScriptCleanUp(t *testing.T) {
	dir := t.TempDir()
	pidf, mark := filepath.Join(dir, "pid"), filepath.Join(dir, "cleaned-up")
	script := fmt.Sprintf("echo $$ > %s\ntrap 'sleep 1; echo ok > %s; exit 143' TERM\nsleep 60 &\nwait", pidf, mark)
	state := t.TempDir()
	f, gw := newResFixture(t, shellRunbook(script), Config{StateDir: state})
	cert, key := certPair(t, time.Now().Add(12*time.Hour))
	id := *f.agent.id
	id.CertPEM, id.KeyPEM = cert, key
	if err := saveIdentity(state, &id); err != nil {
		t.Fatal(err)
	}
	d := shellDispatch(f)
	attempt := attemptIDOf(d)
	gw.queue = append(gw.queue, d)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.agent.Run(ctx); close(done) }()
	waitFor(t, 10*time.Second, "script started", func() bool { _, err := os.Stat(pidf); return err == nil })

	cancel() // SIGTERM from ECS
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return within ECS's default 30s stop timeout")
	}
	// main() returns here and the process exits.
	inflight := f.agent.inFlight()
	_, markErr := os.Stat(mark)

	time.Sleep(3 * time.Second) // in the test process the step goroutine lives on; give it every chance
	res := gw.resultsFor(attempt)

	if len(inflight) != 0 {
		t.Errorf("Run returned (and main would exit) with attempts still in flight: %v", inflight)
	}
	if markErr != nil {
		t.Errorf("the script's SIGTERM handler had not finished when Run returned: the process exits and it never does (§9 promises SIGTERM, then up to 10s)")
	}
	if len(res) == 0 {
		t.Errorf("no result was ever sent for attempt %s: sendResult uses Run's cancelled context, so the control plane only learns from lease expiry", attempt)
	}
}

// The control plane records an Ack (attempt now "running") but the response
// never reaches the agent (connection reset, a proxy timing out). The agent
// drops the attempt without running it, never lists it as in flight and
// never reports it, so the control plane later marks it lost: a non-idempotent
// step that never started pages a human with "may or may not have completed".
func TestReviewLostAckResponseIsNeitherRunNorReported(t *testing.T) {
	f, gw := newResFixture(t, verifyRunbook, Config{})
	d := f.dispatch(nil)
	attempt := attemptIDOf(d)
	gw.queue = append(gw.queue, d)
	gw.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/ack") {
			return false
		}
		var ack agentapi.Ack
		json.NewDecoder(r.Body).Decode(&ack)
		gw.mu.Lock()
		gw.acks[attempt] = append(gw.acks[attempt], ack)
		gw.mu.Unlock()
		// Committed, but the response is lost.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
		return true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.agent.pollOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	gw.mu.Lock()
	acks := append([]agentapi.Ack(nil), gw.acks[attempt]...)
	gw.mu.Unlock()
	if len(acks) == 0 || !acks[0].Accepted {
		t.Fatalf("precondition: control plane should have recorded an accepted ack, got %+v", acks)
	}
	time.Sleep(2 * time.Second)
	ran, results, listed := f.aws.count(), len(gw.resultsFor(attempt)), contains(f.agent.inFlight(), attempt)
	if ran == 0 && results == 0 && !listed && len(acks) == 1 {
		t.Errorf("control plane has attempt %s as running, but the agent dropped it silently: ran=%d results=%d in_flight=%v acks=%d; it will be declared lost after the lease",
			attempt, ran, results, listed, len(acks))
	}
}

// The control plane is unreachable for a moment just as a step finishes. The
// result is retried and arrives; the output, which §7.1 says is resent from a
// bounded buffer on reconnect, is dropped after one failed flush.
func TestReviewOutputSurvivesBriefOutageAtStepEnd(t *testing.T) {
	f, gw := newResFixture(t, shellRunbook("sleep 1\necho important-diagnostic-line"), Config{})
	d := shellDispatch(f)
	attempt := attemptIDOf(d)
	gw.queue = append(gw.queue, d)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := f.agent.pollOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	// Down from now (before the script prints) for 2.5s.
	downUntil := time.Now().Add(2500 * time.Millisecond)
	gw.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if time.Now().Before(downUntil) {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	waitFor(t, 30*time.Second, "result delivered", func() bool { return len(gw.resultsFor(attempt)) > 0 })
	time.Sleep(time.Second)
	if r := gw.resultsFor(attempt)[0]; r.Status != "succeeded" {
		t.Fatalf("result %+v", r)
	}
	if out := gw.outputFor(attempt); !strings.Contains(out, "important-diagnostic-line") {
		t.Errorf("result was delivered but the step's output was lost in the outage; control plane has %q", out)
	}
}

type failingAWS struct{ err error }

func (f failingAWS) Call(context.Context, string, string, map[string]any) (map[string]any, error) {
	return nil, f.err
}

// A wait whose check can never succeed (the role lacks the permission, the
// cluster doesn't exist) polls until the step timeout and reports timed_out
// with "step exceeded its timeout": the run (and a held page) waits the full
// timeout, and the result hides the real cause.
func TestReviewWaitWithPermanentAWSErrorIsNotATimeout(t *testing.T) {
	a := newTestAgent(t, &sink{})
	a.cfg.AWS = failingAWS{&awscall.Error{Service: "ecs", Action: "DescribeServices", Code: "AccessDeniedException",
		Message: "User: arn:aws:sts::1:assumed-role/nightfix-agent/x is not authorized to perform: ecs:DescribeServices", Status: 400}}
	v := &verified{env: signing.Envelope{AttemptID: "att"}, rb: &runbook.Runbook{}, step: runbook.Step{ID: "wait-stable", Type: "wait",
		Timeout: "3s", Interval: "200ms", Until: "true",
		Check: &runbook.Check{AWS: &runbook.AWSCall{Service: "ecs", Action: "DescribeServices"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), v.step.StepTimeout())
	defer cancel()
	start := time.Now()
	res := a.execute(ctx, v)
	t.Logf("status=%s after %v, error=%q", res.Status, time.Since(start).Round(100*time.Millisecond), res.Error)
	if res.Status != "failed" || !strings.Contains(res.Error, "AccessDenied") {
		t.Errorf("a permanent AccessDenied in a wait check was reported as %s (%q); want failed with the AWS error", res.Status, res.Error)
	}
}

// A script's backgrounded children are re-parented to PID 1 and killed with
// the step's process group; something must reap them, or each becomes a
// zombie for the agent's lifetime. In ECS, the agent module enables the init
// process (PID 1 reaps them), and the task's stop timeout fits the agent's
// shutdown grace.
func TestAgentTaskDefinitionReapsAndStopsGracefully(t *testing.T) {
	b, err := os.ReadFile("../../deploy/terraform/modules/nightfix-agent/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "initProcessEnabled = true") {
		t.Error("the agent's task definition must set linuxParameters.initProcessEnabled = true")
	}
	m := regexp.MustCompile(`stopTimeout\s*=\s*(\d+)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("the agent's task definition must set stopTimeout")
	}
	if n, _ := strconv.Atoi(m[1]); time.Duration(n)*time.Second <= shutdownGrace+10*time.Second {
		t.Errorf("stopTimeout %ss doesn't leave room for the agent's %s shutdown grace", m[1], shutdownGrace)
	}
}

func zombieChildren(t *testing.T, ppid int) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Skip("no /proc")
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndex(s, ")")
		if i < 0 {
			continue
		}
		fields := strings.Fields(s[i+1:])
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "Z" && fields[1] == strconv.Itoa(ppid) {
			out = append(out, pid)
		}
	}
	return out
}

type scriptedAWS struct {
	mu    sync.Mutex
	errs  []error
	calls int
}

func (s *scriptedAWS) Call(context.Context, string, string, map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls <= len(s.errs) {
		return nil, s.errs[s.calls-1]
	}
	return map[string]any{"ok": true}, nil
}

// A throttled aws step (HTTP 400 ThrottlingException from a JSON-protocol
// service) wasn't performed, so it's retried; AccessDenied isn't.
func TestAWSStepRetriesThrottlingOnly(t *testing.T) {
	step := runbook.Step{ID: "restart", Type: "aws", Timeout: "30s", Service: "ecs", Action: "UpdateService"}
	throttled := &awscall.Error{Service: "ecs", Action: "UpdateService", Code: "ThrottlingException", Status: 400}
	denied := &awscall.Error{Service: "ecs", Action: "UpdateService", Code: "AccessDeniedException", Status: 400}
	for _, c := range []struct {
		errs      []error
		status    string
		wantCalls int
	}{
		{[]error{throttled, throttled}, "succeeded", 3},
		{[]error{denied}, "failed", 1},
	} {
		a := newTestAgent(t, &sink{})
		aws := &scriptedAWS{errs: c.errs}
		a.cfg.AWS = aws
		v := &verified{env: signing.Envelope{AttemptID: "att"}, rb: &runbook.Runbook{}, step: step}
		ctx, cancel := context.WithTimeout(context.Background(), step.StepTimeout())
		res := a.execute(ctx, v)
		cancel()
		if res.Status != c.status || aws.calls != c.wantCalls {
			t.Errorf("errors %v: status %s after %d calls (%s); want %s after %d", c.errs, res.Status, aws.calls, res.Error, c.status, c.wantCalls)
		}
	}
}

// While a "not started" report (after an unconfirmed ack) is still being
// retried, the attempt is listed as in flight, so a hello in the meantime
// doesn't get it declared lost; once the report is delivered, it isn't.
func TestNotStartedAttemptStaysListedUntilReported(t *testing.T) {
	f, gw := newResFixture(t, verifyRunbook, Config{})
	d := f.dispatch(nil)
	attempt := attemptIDOf(d)
	gw.queue = append(gw.queue, d)
	var resultsOK, acksOK atomic.Bool
	gw.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ack") && !acksOK.Load():
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close() // the response is lost
			}
			return true
		case strings.HasSuffix(r.URL.Path, "/result") && !resultsOK.Load():
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := f.agent.pollOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	waitFor(t, 30*time.Second, "the attempt listed while its report is retried", func() bool {
		return contains(f.agent.inFlight(), attempt)
	})
	// While the report is still retrying, the lease expires and the control
	// plane dispatches the same attempt again. The agent must refuse it: if
	// it ran, the stale "not started" report would land on the running
	// attempt.
	acksOK.Store(true)
	gw.mu.Lock()
	gw.queue = append(gw.queue, d)
	gw.mu.Unlock()
	if err := f.agent.pollOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	waitFor(t, 30*time.Second, "the re-dispatch refused", func() bool {
		gw.mu.Lock()
		defer gw.mu.Unlock()
		for _, a := range gw.acks[attempt] {
			if !a.Accepted && strings.Contains(a.Reason, "already accepted") {
				return true
			}
		}
		return false
	})
	if !contains(f.agent.inFlight(), attempt) {
		t.Fatal("the refused re-dispatch unlisted the attempt whose report is pending")
	}
	resultsOK.Store(true)
	waitFor(t, 40*time.Second, "the not-started report delivered and the attempt unlisted", func() bool {
		return len(gw.resultsFor(attempt)) > 0 && !contains(f.agent.inFlight(), attempt)
	})
	if res := gw.resultsFor(attempt); res[0].Status != "failed" || !strings.Contains(res[0].Error, "not started") {
		t.Fatalf("report: %+v", res[0])
	}
	if f.aws.count() != 0 {
		t.Fatal("the step ran although its dispatch was never confirmed")
	}
}
