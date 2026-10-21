package controlplane

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// adminDB opens the test database as the table owner, to corrupt data on
// purpose. The admin isn't a superuser (CI runs as an RDS-like admin), so it
// becomes nfx_owner, which the owner-aware policies admit to every org; one
// connection, so the role sticks.
func adminDB(t *testing.T, pool *db.DB) *sql.DB {
	t.Helper()
	var name string
	if err := pool.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"))
	u.Path = "/" + name
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	admin.SetMaxOpenConns(1)
	admin.SetMaxIdleConns(1)
	if _, err := admin.Exec(`SET ROLE nfx_owner`); err != nil {
		t.Fatal(err)
	}
	return admin
}

func (e *runHarness) startNamed(name string) string {
	e.t.Helper()
	rb := strings.Replace(harnessRunbook("    - id: s1\n      type: shell\n      run: sleep 1\n"), "  name: qa\n", "  name: "+name+"\n", 1)
	if code, out := e.call("PUT", "/v1/runbooks/"+name, []byte(rb)); code != 200 {
		e.t.Fatalf("publish: %d %v", code, out)
	}
	code, out := e.call("POST", "/v1/runs", []byte(`{"runbook":"`+name+`"}`))
	if code != 200 {
		e.t.Fatalf("run: %d %v", code, out)
	}
	return out["id"].(string)
}

// One row whose handler always fails must not stop the rest of its queue:
// it's recorded with a retry time and the worker moves on.
func TestWorkerSkipsRowThatKeepsFailing(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	bad := e.startNamed("bad")
	var good []string
	for _, n := range []string{"good1", "good2", "good3"} {
		good = append(good, e.startNamed(n))
	}
	admin := adminDB(t, e.s.DB)
	if _, err := admin.Exec(`UPDATE runbook_runs SET deadline_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	badID, _ := ids.Decode("run", bad)
	// The bad run's version no longer decodes (as after a schema change).
	if _, err := admin.Exec(`UPDATE runbook_versions SET canonical_json = replace(canonical_json, '{', '{"removedField":1,')
		WHERE id = (SELECT runbook_version_id FROM runbook_runs WHERE id = $1)`, badID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.ProcessOverdueRuns(ctx); err != nil {
		t.Fatalf("a failing row ended the worker loop: %v", err)
	}
	for _, g := range good {
		if st := e.run(g)["status"]; st != "timed_out" {
			t.Errorf("healthy overdue run %s is %v; one bad row starved the queue", g, st)
		}
	}
	var failures int
	var retryAt sql.NullTime
	var lastErr sql.NullString
	if err := admin.QueryRow(`SELECT worker_failures, worker_retry_at, worker_error FROM runbook_runs WHERE id = $1`, badID).
		Scan(&failures, &retryAt, &lastErr); err != nil {
		t.Fatal(err)
	}
	if failures != 1 || !retryAt.Valid || !strings.Contains(lastErr.String, "removedField") {
		t.Fatalf("failure not recorded: failures=%d retry=%v err=%q", failures, retryAt, lastErr.String)
	}
	// Not retried before its retry time.
	if n, _ := e.s.ProcessOverdueRuns(ctx); n != 0 {
		t.Fatalf("bad run re-claimed %d time(s) before its retry time", n)
	}
}
