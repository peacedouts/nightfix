package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// The run view returns a bounded tail of each attempt's output; the full
// output of one attempt has its own endpoint.
func TestRunViewBoundsOutput(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.alarm("ALARM", "checkout-api")
	var run map[string]any
	var runID string
	e.waitFor("run finished", 30*time.Second, func() bool {
		inc := e.incident(1)
		run = nil
		if id, ok := inc["remediation_run"].(string); ok {
			runID = id
			e.call("GET", "/v1/runs/"+id, nil, &run)
		}
		return run != nil && run["status"] == "succeeded"
	})
	steps := run["attempts"].([]any)
	first := steps[0].(map[string]any)
	step, attempt := fmt.Sprint(first["step"]), int(first["attempt"].(float64))

	// Append 200 chunks of about 1000 bytes ("chunk 000 ..."), after what the
	// step really printed. Multi-byte
	// runes make sure the tail is cut on a rune boundary.
	rid, _ := ids.Decode("run", runID)
	if err := e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
		var aid string
		if err := tx.QueryRow(`SELECT id FROM step_attempts WHERE run_id = $1 AND step_id = $2 AND attempt_number = $3`,
			rid, step, attempt).Scan(&aid); err != nil {
			return err
		}
		for i := 0; i < 200; i++ {
			d := fmt.Sprintf("chunk %03d ", i)
			d += strings.Repeat("é", (1000-len(d))/2)
			if _, err := tx.Exec(`INSERT INTO step_output_chunks (org_id, attempt_id, seq, stream, data) VALUES ($1,$2,$3,'stdout',$4)`,
				e.rawOrg, aid, 100000+i, d); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	e.call("GET", "/v1/runs/"+runID, nil, &run)
	first = run["attempts"].([]any)[0].(map[string]any)
	out := first["output"].(string)
	if len(out) > 64<<10 || first["output_truncated"] != true || first["output_bytes"].(float64) < 190_000 {
		t.Fatalf("run view: %d bytes, truncated=%v, total=%v", len(out), first["output_truncated"], first["output_bytes"])
	}
	if !strings.Contains(out, "chunk 199 ") || strings.Contains(out, "chunk 000 ") {
		t.Fatalf("run view should keep the newest output")
	}
	if !strings.HasPrefix(out, "é") && !strings.HasPrefix(out, "chunk") {
		t.Fatalf("tail starts mid-rune: %q", out[:4])
	}

	var full map[string]any
	e.call("GET", fmt.Sprintf("/v1/runs/%s/steps/%s/attempts/%d/output", runID, step, attempt), nil, &full)
	fo := full["output"].(string)
	if !strings.Contains(fo, "chunk 000 ") || !strings.Contains(fo, "chunk 199 ") || float64(len(fo)) != full["output_bytes"] {
		t.Fatalf("full output: %d bytes of %v", len(fo), full["output_bytes"])
	}
	if code, _ := e.userCall(e.key, "GET", fmt.Sprintf("/v1/runs/%s/steps/%s/attempts/99/output", runID, step), nil); code != 404 {
		t.Fatalf("missing attempt: %d", code)
	}
}

// Reading an incident must not wait on (or block) work that holds its row
// lock, and its timeline is paged.
func TestIncidentReadsDoNotLockAndTimelinePages(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.alarm("ALARM", "checkout-api")
	e.waitFor("incident", 10*time.Second, func() bool { return e.incident(1) != nil })

	locked, release := make(chan struct{}), make(chan struct{})
	holder := make(chan error, 1)
	go func() {
		holder <- e.db.WithOrg(e.ctx, e.rawOrg, func(tx *db.Tx) error {
			if _, err := tx.Exec(`SELECT 1 FROM incidents WHERE number = 1 FOR UPDATE`); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-holder:
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() {
		ok := e.incident(1) != nil
		code, _ := e.userCall(e.key, "GET", "/v1/incidents/1/timeline", nil)
		done <- ok && code == 200
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("reads failed while the incident was locked")
		}
	case <-time.After(5 * time.Second):
		t.Error("reading an incident waited on its row lock")
	}
	close(release)
	if err := <-holder; err != nil {
		t.Fatal(err)
	}

	var all, page1, page2 []map[string]any
	e.call("GET", "/v1/incidents/1/timeline", nil, &all)
	if len(all) < 2 {
		t.Fatalf("timeline too short to page: %v", all)
	}
	e.call("GET", "/v1/incidents/1/timeline?limit=1", nil, &page1)
	e.call("GET", fmt.Sprintf("/v1/incidents/1/timeline?limit=1&after=%v", page1[0]["id"]), nil, &page2)
	if len(page1) != 1 || len(page2) != 1 || page1[0]["id"] != all[0]["id"] || page2[0]["id"] != all[1]["id"] {
		t.Fatalf("paging: %v then %v, want the first two of %v", page1, page2, all)
	}
}

func TestReadinessChecksTheDatabase(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	resp, err := http.Get(e.api + "/readyz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("readyz: %v %v", resp, err)
	}
	resp.Body.Close()
	e.db.Close()
	resp, err = http.Get(e.api + "/readyz")
	if err != nil || resp.StatusCode != 503 {
		t.Fatalf("readyz with the database gone: %v %v", resp, err)
	}
	resp.Body.Close()
	if resp, err := http.Get(e.api + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz (liveness) must not depend on the database: %v %v", resp, err)
	}
}
