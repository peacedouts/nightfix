package e2e

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent"
)

// cutter is a TCP proxy in front of the agent gateway that can drop every
// connection, like a NAT gateway or Direct Connect blip in the customer VPC.
// TLS runs end to end through it.
type cutter struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	down   bool
	conns  map[net.Conn]struct{}
}

func newCutter(t *testing.T, target string) *cutter {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &cutter{ln: ln, target: target, conns: map[net.Conn]struct{}{}}
	t.Cleanup(func() { ln.Close(); c.setDown(true) })
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			down := c.down
			c.mu.Unlock()
			if down {
				in.Close()
				continue
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				in.Close()
				continue
			}
			c.mu.Lock()
			c.conns[in], c.conns[out] = struct{}{}, struct{}{}
			c.mu.Unlock()
			go func() { io.Copy(out, in); out.Close(); in.Close() }()
			go func() { io.Copy(in, out); out.Close(); in.Close() }()
		}
	}()
	return c
}

func (c *cutter) setDown(down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.down = down
	if down {
		for k := range c.conns {
			k.Close()
		}
		c.conns = map[net.Conn]struct{}{}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const outageRunbook = `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: outage-shell
  title: Long non-idempotent shell step
  team: platform
spec:
  target:
    agentSelector:
      env: outage
  triggers:
    - type: manual
  policy:
    allowedRoles: [Responder, Admin]
    timeout: 15m
  steps:
    - id: migrate
      name: Long non-idempotent step
      type: shell
      timeout: 5m
      run: |
        sleep 6
        echo finished
`

// agent-protocol.md §8.2: "Control plane unreachable: running steps continue
// to completion ... output and results are buffered and sent on reconnect."
// Here the agent's network to the gateway drops for 45s while a 6s step runs.
// The step succeeds, the agent holds the result and delivers it on
// reconnect, and gets 200 OK. But the 30s lease expired meanwhile, the
// attempt was marked lost, and Result treats a result for a lost attempt as a
// duplicate: the real outcome is discarded and the run waits on a human.
func TestResultHeldThroughOutageIsHonoured(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var pub map[string]any
	e.callRaw("PUT", "/v1/runbooks/outage-shell", []byte(outageRunbook), &pub)

	var enr map[string]string
	e.call("POST", "/v1/enrollment-rules", map[string]any{"method": "token", "labels": map[string]string{"env": "outage"}}, &enr)
	cut := newCutter(t, strings.TrimPrefix(e.gwURL, "https://"))
	logs := &syncBuf{}
	ag, err := agent.New(agent.Config{Endpoint: "https://" + cut.ln.Addr().String(), CAPEM: e.caPEM, EnrollMethod: "token",
		EnrollToken: enr["token"], StateDir: t.TempDir(), AWS: e.aws, Log: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	go ag.Run(e.ctx)
	e.waitFor("outage agent online", 15*time.Second, func() bool {
		var agents []map[string]any
		e.call("GET", "/v1/agents", nil, &agents)
		online := 0
		for _, a := range agents {
			if a["status"] == "online" {
				online++
			}
		}
		return online == 2
	})

	out := e.expect("starter", e.key, "POST", "/v1/runs", map[string]any{"runbook": "outage-shell", "params": map[string]string{}}, 200, "run_")
	runID := out[strings.Index(out, "run_"):]
	runID = runID[:strings.IndexAny(runID, `"`)]
	attemptState := func() string {
		run := e.run(runID)
		atts, _ := run["attempts"].([]any)
		if len(atts) == 0 {
			return ""
		}
		return fmt.Sprint(atts[len(atts)-1].(map[string]any)["state"])
	}
	e.waitFor("step running", 15*time.Second, func() bool { return attemptState() == "running" })

	cut.setDown(true)
	time.Sleep(45 * time.Second)
	t.Logf("while the agent was cut off: attempt %s, run %s", attemptState(), e.run(runID)["status"])
	cut.setDown(false)

	e.waitFor("agent delivered its result", 120*time.Second, func() bool { return strings.Contains(logs.String(), "step finished") })
	l := logs.String()
	if !strings.Contains(l, "status=succeeded") || strings.Contains(l, "giving up") || strings.Contains(l, "result refused") {
		t.Fatalf("agent log:\n%s", l)
	}
	time.Sleep(time.Second)
	run := e.run(runID)
	t.Logf("after reconnect: attempt %s, run %s", attemptState(), run["status"])
	if run["status"] != "succeeded" {
		t.Errorf("the step succeeded and the agent delivered that result after reconnecting (HTTP 200), but the run is %q with attempt %q: the result was discarded",
			run["status"], attemptState())
	}
}
