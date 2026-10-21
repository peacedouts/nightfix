package e2e

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent"
	"github.com/peacedouts/nightfix/internal/db"
)

// An enrollment token is limited-use: once it has enrolled max_agents
// agents it can't enroll another, however long the first has been quiet.
func TestEnrollmentTokenIsLimitedUse(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var enr map[string]string
	e.call("POST", "/v1/enrollment-rules", map[string]any{"method": "token", "labels": map[string]string{"env": "staging"}, "max_agents": 1}, &enr)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	newAgent := func() *agent.Agent {
		ag, err := agent.New(agent.Config{Endpoint: e.gwURL, CAPEM: e.caPEM, EnrollMethod: "token", EnrollToken: enr["token"],
			StateDir: t.TempDir(), AWS: e.aws, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		return ag
	}
	count := func() int {
		var agents []map[string]any
		e.call("GET", "/v1/agents", nil, &agents)
		return len(agents)
	}
	before := count()
	ctx, stop := context.WithCancel(e.ctx)
	go newAgent().Run(ctx)
	e.waitFor("token agent enrolled", 15*time.Second, func() bool { return count() == before+1 })
	stop()
	// The first agent has been gone long enough to no longer count as live.
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE agents SET last_seen_at = now() - interval '11 minutes', created_at = now() - interval '11 minutes'
			WHERE labels->>'env' = 'staging'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	err := newAgent().Run(ctx2)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("second enrollment with a used-up token: %v", err)
	}
	if n := count(); n != before+1 {
		t.Fatalf("%d agents, want %d", n, before+1)
	}
	// Token rules can't be created with a long life.
	if code, out := e.userCall(e.key, "POST", "/v1/enrollment-rules", `{"method":"token","labels":{"env":"x"},"expires_in":"720h"}`); code != 400 {
		t.Fatalf("token rule with a 30-day life: got %d %s, want 400", code, out)
	}
}
