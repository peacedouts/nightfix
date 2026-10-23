package e2e_test

// Limits review (shared-service capacity): what one tenant can make the
// shared control plane do to everyone else, through the API and ingest.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// otherOrg is a second tenant on the same control plane as x's org.
type otherOrg struct {
	id, key, ingest, secret string
}

func (x *ingestHarness) newOtherOrg(slug string) otherOrg {
	x.t.Helper()
	o, err := x.srv.CreateOrg(context.Background(), slug, slug+fmt.Sprint(time.Now().UnixNano()%100000))
	if err != nil {
		x.t.Fatal(err)
	}
	oo := otherOrg{id: o.OrgID, key: o.APIKey}
	x.callAs(oo.key, "POST", "/v1/services", map[string]any{"name": "api"}, nil)
	var integ map[string]string
	x.callAs(oo.key, "POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "wh", "default_service": "api"}, &integ)
	oo.ingest = strings.Replace(integ["ingest_url"], "http://ingest", x.ingBase, 1)
	oo.secret = integ["signing_secret"]
	return oo
}

func (x *ingestHarness) callAs(key, method, path string, body, out any) int {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, x.api+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		x.t.Logf("%s %s -> %d %.300s", method, path, resp.StatusCode, rb)
	}
	if out != nil {
		json.Unmarshal(rb, out)
	}
	return resp.StatusCode
}

// slowRule is a routing condition the API accepts that takes the full CEL
// deadline (250 ms) to evaluate on every alert, then counts as "no match".
func slowRule(i int) string {
	ones := strings.TrimSuffix(strings.Repeat("1,", 100), ",")
	l := "[" + ones + "]"
	return fmt.Sprintf("%s.all(a, %s.all(b, %s.all(c, a + b + c > %d)))", l, l, l, -i-1)
}

// Routing rules have no count limit, and every alert event evaluates every
// rule (each bounded only by the 250 ms CEL deadline) inside its processing
// transaction. Each control-plane instance runs one alert-processing loop for
// all orgs, so one org's rule set stalls everyone's alerts on that instance.
func TestLimitsSlowRoutingRulesStallOtherOrgsAlertProcessing(t *testing.T) {
	x := setupIngest(t, nil)
	quiet := x.newOtherOrg("quiet")

	const n = 40
	var rules []map[string]string
	for i := range n {
		rules = append(rules, map[string]string{"match": slowRule(i), "service": "checkout-api"})
	}
	if code := x.call("PUT", "/v1/routing-rules", rules, nil); code != 200 {
		t.Fatalf("PUT /v1/routing-rules: %d", code)
	}
	if code := x.send(map[string]any{"dedup_key": "noisy-1", "summary": "noisy org alert"}); code != 202 {
		t.Fatalf("noisy ingest %d", code)
	}
	if code := x.sendTo(quiet.ingest, quiet.secret, map[string]any{"dedup_key": "q-1", "summary": "quiet org: checkout down"}); code != 202 {
		t.Fatalf("quiet ingest %d", code)
	}

	// One instance's alert loop, as RunWorkers runs it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			x.srv.ProcessAlertEvents(ctx)
			time.Sleep(250 * time.Millisecond)
		}
	}()
	start := time.Now()
	var opened time.Duration
	for time.Since(start) < 60*time.Second {
		var incs []map[string]any
		x.callAs(quiet.key, "GET", "/v1/incidents", nil, &incs)
		if len(incs) > 0 {
			opened = time.Since(start)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("quiet org's incident opened after %v (noisy org has %d routing rules)", opened.Round(time.Millisecond), n)

	// The API takes a rule set this size in one request (1 MiB body).
	var big []map[string]string
	for i := range 1400 {
		big = append(big, map[string]string{"match": slowRule(i), "service": "checkout-api"})
	}
	b, _ := json.Marshal(big)
	code := x.call("PUT", "/v1/routing-rules", big, nil)
	t.Logf("PUT /v1/routing-rules with %d slow rules (%d KiB): %d; that is %v of CEL per alert event",
		len(big), len(b)>>10, code, time.Duration(len(big))*250*time.Millisecond)

	if opened == 0 || opened > 3*time.Second {
		t.Errorf("another org's alert waited %v behind one org's alert (0 = not within 60s): its %d routing rules cost ~250ms each per event, "+
			"and %d rules (accepted: %d) would hold the instance's alert loop ~%v per event, past idle_in_transaction_session_timeout (5min)",
			opened.Round(time.Millisecond), n, len(big), code, time.Duration(len(big))*240*time.Millisecond)
	}
}

// GET /v1/audit-events re-verifies the org's whole audit chain on every call
// while holding one of the instance's 20 pool connections, with no rate or
// concurrency limit. One org's admin polling it starves every other org's
// ingest (and API, and workers) on that instance.
func TestLimitsAuditPollingStarvesOtherOrgsIngest(t *testing.T) {
	x := setupIngest(t, nil)
	quiet := x.newOtherOrg("quiet")
	ctx := context.Background()

	// One API call stores ~1 MiB in the audit chain (team.create audits the
	// whole request), so the chain's size is the tenant's to choose.
	name := strings.Repeat("n", 1000*1000)
	if code := x.call("POST", "/v1/teams", map[string]any{"slug": "big", "name": name}, nil); code != 200 {
		t.Fatalf("POST /v1/teams: %d", code)
	}
	own := ownerConn(t, x.srv.DB)
	var bytes1 int
	own.QueryRowContext(ctx, `SELECT octet_length(data::text) FROM audit_events WHERE org_id = $1 AND action = 'team.create'`, x.orgID).Scan(&bytes1)
	t.Logf("one POST /v1/teams stored a %d KiB audit event", bytes1>>10)

	// History: 200k ordinary audit events (about a year of a busy org's runs
	// and agent renewals, or an hour of scripted API calls; nothing limits
	// the rate).
	for from := 1; from <= 200_000; from += 2000 {
		if err := x.srv.DB.WithOrg(ctx, x.orgID, func(tx *db.Tx) error {
			_, err := tx.Exec(`SELECT nfx_audit('system', 'control-plane', 'run.finish', 'run', gen_random_uuid()::text,
				jsonb_build_object('status', 'succeeded', 'error', '', 'i', i)) FROM generate_series($1::int, $2::int) i`, from, from+1999)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if code := x.call("GET", "/v1/audit-events", nil, nil); code != 200 {
		t.Fatalf("GET /v1/audit-events: %d", code)
	}
	one := time.Since(start)
	t.Logf("one GET /v1/audit-events took %v", one.Round(time.Millisecond))

	// The noisy org's admin polls it from 40 clients.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var polls atomic.Int64
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", x.api+"/v1/audit-events", nil)
				req.Header.Set("Authorization", "Bearer "+x.key)
				if resp, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					polls.Add(1)
				}
			}
		}()
	}
	time.Sleep(2 * time.Second)
	var worst time.Duration
	codes := []int{}
	for i := range 3 {
		code, d := postSigned(quiet.ingest, quiet.secret, map[string]any{"dedup_key": fmt.Sprint("q-", i), "summary": "quiet org alert", "delivery": i}, 60*time.Second)
		codes = append(codes, code)
		worst = max(worst, d)
	}
	close(stop)
	wg.Wait()
	t.Logf("while polled (%d polls), the quiet org's ingest took up to %v (statuses %v)", polls.Load(), worst.Round(time.Millisecond), codes)
	if worst > 2*time.Second {
		t.Errorf("another org's alert ingest took %v while one org's admin polled GET /v1/audit-events (%v each, chain re-verified per call)",
			worst.Round(time.Millisecond), one.Round(time.Millisecond))
	}
}

// A note step's markdown has no size limit (only the 512 KiB runbook cap),
// and every run of it copies the markdown into the incident's timeline. A
// timeline page is bounded by entry count (1000), not bytes, so one viewer
// request can build hundreds of MiB.
func TestLimitsTimelinePageIsUnboundedInBytes(t *testing.T) {
	x := setupIngest(t, nil)
	x.send(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	x.tick()
	note := strings.Repeat("        "+strings.Repeat("x", 120)+"\n", 3300) // ~420 KiB
	rb := `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: big-note
  title: Big note
spec:
  target:
    agentSelector:
      env: prod
  triggers:
    - type: manual
  policy:
    timeout: 5m
  steps:
    - id: note
      type: note
      markdown: |
` + note
	req, _ := http.NewRequest("PUT", x.api+"/v1/runbooks/big-note", strings.NewReader(rb))
	req.Header.Set("Authorization", "Bearer "+x.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Fixed: note markdown is capped (it's copied to the timeline on every
	// run), and timeline pages stop at about 1 MiB.
	if resp.StatusCode == 422 && strings.Contains(string(pb), "markdown is at most") {
		return
	}
	if resp.StatusCode != 200 {
		t.Fatalf("publish: %d %.300s", resp.StatusCode, pb)
	}
	for range 40 {
		if code := x.call("POST", "/v1/runs", map[string]any{"runbook": "big-note", "incident": 1}, nil); code != 200 {
			t.Fatalf("start run: %d", code)
		}
	}
	req, _ = http.NewRequest("GET", x.api+"/v1/incidents/1/timeline", nil)
	req.Header.Set("Authorization", "Bearer "+x.key)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var entries []map[string]any
	json.Unmarshal(body, &entries)
	n := len(body)
	t.Logf("runbook source %d KiB; after 40 runs, one timeline page (%d entries) is %d MiB", len(rb)>>10, len(entries), n>>20)
	if n > 4<<20 {
		t.Errorf("one timeline page of %d entries is %d MiB; a full page (1000 entries) of the same runs is ~%d MiB",
			len(entries), n>>20, (n>>20)*1000/max(len(entries), 1))
	}
}

// GET /v1/runs/{id} (viewer) bounds the output text it returns, but not the
// attempts' outputs: every attempt's outputs (the agent may send up to 4 MiB
// per result, and a step may be retried 10 times) is loaded and returned in
// one response.
func TestLimitsRunViewOutputsAreUnbounded(t *testing.T) {
	x := setupIngest(t, nil)
	own := ownerConn(t, x.srv.DB)
	rb, ver, run := ids.NewString(), ids.NewString(), ids.NewString()
	mustExec(t, own, `INSERT INTO runbooks (id, org_id, name, title, latest_version) VALUES ($1, $2, 'big', 'big', 1)`, rb, x.orgID)
	mustExec(t, own, `INSERT INTO runbook_versions (id, org_id, runbook_id, version, digest, canonical_json, source_yaml, published_by)
		VALUES ($1, $2, $3, 1, 'd', '{}', '', 'test')`, ver, x.orgID, rb)
	mustExec(t, own, `INSERT INTO runbook_runs (id, org_id, runbook_version_id, runbook_name, digest, trigger_type, mode, requested_by_type,
			requested_by_id, params, context, target_selector, status, deadline_at)
		VALUES ($1, $2, $3, 'big', 'd', 'api', 'manual', 'api_key', 'k', '{}', '{}', '{}', 'failed', now())`, run, x.orgID, ver)
	// Three steps, each failing and retried: 24 attempts, each reporting
	// 1 MiB of outputs (what a well-behaved agent may send; a modified one,
	// up to 4 MiB).
	mustExec(t, own, `INSERT INTO step_attempts (id, org_id, run_id, step_index, step_id, attempt_number, state, outputs)
		SELECT gen_random_uuid(), $1, $2, s, 'step' || s, a, 'failed', jsonb_build_object('dump', repeat('x', 1024*1024 - 32))
		FROM generate_series(0, 2) s, generate_series(1, 8) a`, x.orgID, run)
	req, _ := http.NewRequest("GET", x.api+"/v1/runs/"+ids.Encode("run", run), nil)
	req.Header.Set("Authorization", "Bearer "+x.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	t.Logf("GET /v1/runs/{id}: %d, %d MiB", resp.StatusCode, n>>20)
	if n > 2<<20 {
		t.Errorf("one run view is %d MiB: attempts' outputs are returned in full (the documented view budget is 1 MiB of output)", n>>20)
	}
}
