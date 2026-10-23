package e2e_test

// Reliability review: can Nightfix fail to page without anyone noticing?
// Each test states the behaviour an incident tool needs and fails on the
// current code.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// adminDB connects to the harness's database as the migration admin, acting
// as nfx_owner (which bypasses nothing but owns every table).
func adminDB(t *testing.T, app *db.DB) *sql.DB {
	t.Helper()
	var name string
	if err := app.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"))
	u.Path = "/" + name
	a, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	a.SetMaxOpenConns(2)
	t.Cleanup(func() { a.Close() })
	return a
}

// appConn opens a separate nfx_app pool to the harness's database, so a
// test can hold locks without using one of the server's connections.
func appConn(t *testing.T, app *db.DB) *db.DB {
	t.Helper()
	var name string
	if err := app.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	p, err := db.Open(context.Background(), testdb.AppDSNFor(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// postSigned sends a signed webhook alert with a client timeout and
// returns the status (0 on timeout) and how long it took.
func postSigned(ingest, secret string, body map[string]any, timeout time.Duration) (int, time.Duration) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ingest, bytes.NewReader(b))
	req.Header.Set(controlplane.WebhookSignatureHeader, controlplane.SignWebhook(secret, b, time.Now()))
	c := &http.Client{Timeout: timeout}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, time.Since(start)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

// secondOrg creates another org on the same server with its own service,
// PagerDuty target (recorded in pages) and webhook integration.
type orgB struct {
	id, key, ingest, secret string
	mu                      sync.Mutex
	pages                   []string
}

func (x *ingestHarness) secondOrg(t *testing.T) *orgB {
	t.Helper()
	o, err := x.srv.CreateOrg(context.Background(), "Other", fmt.Sprintf("other%d", time.Now().UnixNano()%100000))
	if err != nil {
		t.Fatal(err)
	}
	b := &orgB{id: o.OrgID, key: o.APIKey}
	pd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		b.mu.Lock()
		b.pages = append(b.pages, fmt.Sprint(ev["event_action"]))
		b.mu.Unlock()
	}))
	t.Cleanup(pd.Close)
	call := func(method, path string, body, out any) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, x.api+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+b.key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		if resp.StatusCode/100 != 2 {
			t.Fatalf("%s %s -> %d %s", method, path, resp.StatusCode, rb)
		}
		if out != nil {
			json.Unmarshal(rb, out)
		}
	}
	call("POST", "/v1/services", map[string]any{"name": "payments"}, nil)
	call("POST", "/v1/services/payments/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "kb", "events_url": pd.URL + "/pd"}, nil)
	var integ map[string]string
	call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "wh", "default_service": "payments"}, &integ)
	b.ingest = strings.Replace(integ["ingest_url"], "http://ingest", x.ingBase, 1)
	b.secret = integ["signing_secret"]
	return b
}

// waitForLockWait waits until some backend of the database is waiting on a
// lock (the stalled alert-processing transaction).
func waitForLockWait(t *testing.T, admin *sql.DB, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND cardinality(pg_blocking_pids(pid)) > 0`).Scan(&n)
		if n > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never started waiting on a lock", what)
}

// Ingest must only persist (alert-incident-model.md §3.2: persist, 202, p99
// under 200 ms). But it takes a shared per-org advisory lock that the alert
// claim holds exclusively for the whole processing transaction (migration
// 0023), so while one of the org's events is being processed, nothing new
// from that org can be stored. Here processing is stalled on a row lock (any
// slow processing transaction does the same: a lock wait, a slow query, a
// CPU-starved task holding its transaction open).
func TestReliabilityIngestDoesNotWaitForAlertProcessing(t *testing.T) {
	x := setupIngest(t, nil)
	admin := adminDB(t, x.srv.DB)
	ctx := context.Background()

	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick() // incident #1 open, paged

	// Something holds incident #1 (an ack, a run result, the deadline worker).
	locker := appConn(t, x.srv.DB)
	ltx, err := locker.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ltx.Rollback()
	ltx.Exec(`SELECT set_config('app.org_id', $1, true)`, x.orgID)
	if _, err := ltx.Exec(`SELECT id FROM incidents FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	// A second alert for the same service joins #1: its processing waits.
	if code := x.send(map[string]any{"dedup_key": "B", "summary": "B down"}); code != 202 {
		t.Fatalf("ingest B: %d", code)
	}
	procCtx, cancelProc := context.WithCancel(ctx)
	defer cancelProc()
	go x.srv.ProcessAlertEvents(procCtx)
	waitForLockWait(t, admin, "alert processing")

	// A new, unrelated alert from the same org should still be persisted at once.
	code, took := postSigned(x.ingest, x.secret, map[string]any{"dedup_key": "C", "summary": "C down"}, 3*time.Second)
	ltx.Rollback()
	if code != http.StatusAccepted {
		t.Fatalf("ingest of an unrelated alert while another event of the org is being processed: status %d after %v "+
			"(0 = client timeout); ingest waits on processing through the shared nfx_ingest advisory lock", code, took.Round(time.Millisecond))
	}
}

// Each ingest request blocked on the org's advisory lock holds one of the
// instance's 20 pool connections (db.Open), so a burst of deliveries for one
// org whose processing is stalled exhausts the pool: every other org's
// ingest, alert processing and pages on that instance stop too, and since
// load balancers spread the burst, on every instance.
func TestReliabilityOneStalledOrgDoesNotStopOtherOrgsPaging(t *testing.T) {
	x := setupIngest(t, nil)
	admin := adminDB(t, x.srv.DB)
	other := x.secondOrg(t)
	ctx := context.Background()

	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick() // org A: incident #1 open, paged

	// Org B has an incident whose page is waiting in the outbox.
	if code, _ := postSigned(other.ingest, other.secret, map[string]any{"dedup_key": "db", "summary": "payments db down"}, 5*time.Second); code != 202 {
		t.Fatalf("org B ingest: %d", code)
	}
	if _, err := x.srv.ProcessAlertEvents(ctx); err != nil {
		t.Fatal(err)
	}

	// Org A's processing stalls (see the previous test).
	locker := appConn(t, x.srv.DB)
	ltx, err := locker.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ltx.Rollback()
	ltx.Exec(`SELECT set_config('app.org_id', $1, true)`, x.orgID)
	if _, err := ltx.Exec(`SELECT id FROM incidents FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	x.send(map[string]any{"dedup_key": "B", "summary": "B down"})
	procCtx, cancelProc := context.WithCancel(ctx)
	defer cancelProc()
	go x.srv.ProcessAlertEvents(procCtx)
	waitForLockWait(t, admin, "alert processing")

	// Org A's alarm storm: 30 deliveries in flight (SNS delivers in parallel).
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			postSigned(x.ingest, x.secret, map[string]any{"dedup_key": fmt.Sprint("storm-", i), "summary": "storm"}, 20*time.Second)
		}()
	}
	time.Sleep(time.Second)
	st := x.srv.DB.Stats()
	t.Logf("server pool during the storm: open=%d in_use=%d waiting=%d", st.OpenConnections, st.InUse, st.WaitCount)

	// Org B is unaffected by org A: its new alert is stored and its pending page goes out.
	codeB, tookB := postSigned(other.ingest, other.secret, map[string]any{"dedup_key": "db2", "summary": "payments db still down"}, 3*time.Second)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, derr := x.srv.DeliverNotifications(dctx)
	cancel()
	other.mu.Lock()
	pages := append([]string(nil), other.pages...)
	other.mu.Unlock()

	ltx.Rollback()
	wg.Wait()
	if codeB != http.StatusAccepted || len(pages) == 0 {
		t.Fatalf("org A's stalled processing plus its burst of deliveries stopped org B: org B ingest status %d after %v (0 = timeout); "+
			"org B's pending page delivered: %v (deliver error: %v)", codeB, tookB.Round(time.Millisecond), pages, derr)
	}
}

// A runbook version the running binary can't decode (FromCanonical refuses
// unknown fields, so this is what a rollback to an older release sees for any
// runbook published with a newer field) makes processing of every alert on
// the runbook's service fail. ProcessAlertEvents records the error and never
// retries, so no incident opens and nobody is paged; principle 5 says an
// incident that can't be evaluated must still page.
func TestReliabilityAlertPagesEvenIfRemediationCantBeEvaluated(t *testing.T) {
	x := setupIngest(t, nil)
	admin := adminDB(t, x.srv.DB)
	rb := `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: restart-checkout
  title: Restart checkout
spec:
  target:
    agentSelector:
      env: prod
  triggers:
    - type: alert
      services: [checkout-api]
      match: 'true'
      mode: auto
      beforePaging: true
      cooldown: 1m
      maxRunsPerHour: 5
  policy:
    timeout: 5m
  steps:
    - id: note
      type: note
      markdown: restarting
`
	var pub map[string]any
	req, _ := http.NewRequest("PUT", x.api+"/v1/runbooks/restart-checkout", strings.NewReader(rb))
	req.Header.Set("Authorization", "Bearer "+x.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&pub)
	resp.Body.Close()
	if pub["version"] != float64(1) {
		t.Fatalf("publish: %d %v", resp.StatusCode, pub)
	}
	// What an older binary sees: a field it doesn't know.
	if _, err := admin.Exec(`SET ROLE nfx_owner; UPDATE runbook_versions SET canonical_json = jsonb_set(canonical_json::jsonb, '{spec,newerField}', 'true')::text`); err != nil {
		t.Fatal(err)
	}

	x.send(map[string]any{"dedup_key": "A", "summary": "checkout down", "severity": "critical"})
	x.tick()
	x.tick()

	var evErr sql.NullString
	var incidents, pages int
	admin.QueryRow(`SELECT error FROM alert_events ORDER BY received_at DESC LIMIT 1`).Scan(&evErr)
	admin.QueryRow(`SELECT count(*) FROM incidents`).Scan(&incidents)
	admin.QueryRow(`SELECT count(*) FROM notifications WHERE kind = 'page'`).Scan(&pages)
	x.pdMu.Lock()
	pd := append([]string(nil), x.pd...)
	x.pdMu.Unlock()
	if incidents == 0 || pages == 0 || len(pd) == 0 {
		t.Fatalf("a critical alert was dropped: incidents=%d pages queued=%d PagerDuty saw %v; alert_events.error=%q",
			incidents, pages, pd, evErr.String)
	}
}

// capture records log lines at Warn and above.
type capture struct {
	mu    sync.Mutex
	lines []string
	errs  atomic.Int64
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		return nil
	}
	if r.Level >= slog.LevelError {
		c.errs.Add(1)
	}
	c.mu.Lock()
	c.lines = append(c.lines, r.Level.String()+" "+r.Message)
	c.mu.Unlock()
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// A page PagerDuty refuses (a revoked routing key: HTTP 400) is retried for
// 24 hours. During that time nothing reaches an operator or the customer:
// every attempt logs at Warn, nothing at Error, /readyz is ok, the incident
// timeline says nothing, and no metric or alarm exists. Ten attempts span
// about 13 minutes at the real backoff (2s doubling, capped at 5m); the test
// skips the waits.
func TestReliabilityPersistentPageFailureIsVisible(t *testing.T) {
	x := setupIngest(t, nil)
	admin := adminDB(t, x.srv.DB)
	logs := &capture{}
	x.srv.Log = slog.New(logs)
	x.pdFail = 1 << 30 // every trigger fails (500 here; a 400 is handled the same)

	x.send(map[string]any{"dedup_key": "A", "summary": "checkout down", "severity": "critical"})
	for range 10 {
		x.tick()
		admin.Exec(`SET ROLE nfx_owner; UPDATE notifications SET next_attempt_at = now() WHERE status = 'pending'`)
	}
	var attempts int
	var status string
	admin.QueryRow(`SELECT attempts, status FROM notifications WHERE kind = 'page'`).Scan(&attempts, &status)
	var timelineFailures int
	admin.QueryRow(`SELECT count(*) FROM incident_timeline WHERE type LIKE 'notification%'`).Scan(&timelineFailures)
	resp, err := http.Get(x.ingBase + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	logs.mu.Lock()
	sample := logs.lines
	if len(sample) > 2 {
		sample = sample[:2]
	}
	logs.mu.Unlock()
	// Both signals: an Error log line (alarmable) and an entry on the
	// incident's timeline (where responders look).
	if logs.errs.Load() == 0 || timelineFailures == 0 {
		t.Fatalf("a critical page failed %d times and is still %q; operator signals: error logs=%d, timeline entries=%d, /readyz=%d; "+
			"log lines look like %q", attempts, status, logs.errs.Load(), timelineFailures, resp.StatusCode, sample)
	}
}

// A rolling deploy stops an instance while a page is in flight: serve
// cancels the workers' context and waits (WaitWorkers) for claimed
// notifications to be recorded, then another instance takes over. The page
// must go out exactly once. (Passes: recorded here as checked.)
func TestReliabilityPageInFlightAtShutdownIsSentOnce(t *testing.T) {
	x := setupIngest(t, nil)
	admin := adminDB(t, x.srv.DB)
	var triggers atomic.Int64
	inFlight := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		if ev["event_action"] == "trigger" {
			select {
			case inFlight <- struct{}{}:
			default:
			}
			time.Sleep(3 * time.Second)
			triggers.Add(1)
		}
		w.WriteHeader(202)
	}))
	t.Cleanup(slow.Close)
	x.call("POST", "/v1/services/checkout-api/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "slow", "events_url": slow.URL + "/pd"}, nil)
	x.send(map[string]any{"dedup_key": "A", "summary": "checkout down"})
	if _, err := x.srv.ProcessAlertEvents(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx1, stop := context.WithCancel(context.Background())
	x.srv.RunWorkers(ctx1, 50*time.Millisecond)
	select {
	case <-inFlight:
	case <-time.After(10 * time.Second):
		t.Fatal("page never sent")
	}
	stop() // SIGTERM
	x.srv.WaitWorkers(20 * time.Second)

	srv2 := controlplane.New(x.srv.DB, x.srv.Sealer, x.srv.CA, controlplane.Config{AllowPrivateTargets: true}, x.srv.Log)
	ctx2, stop2 := context.WithCancel(context.Background())
	defer stop2()
	srv2.RunWorkers(ctx2, 50*time.Millisecond)
	time.Sleep(4 * time.Second)
	var pending int
	admin.QueryRow(`SELECT count(*) FROM notifications WHERE status <> 'sent'`).Scan(&pending)
	if n := triggers.Load(); n != 1 || pending != 0 {
		t.Fatalf("slow PagerDuty target got %d triggers (want 1); unsent notifications: %d", n, pending)
	}
}
