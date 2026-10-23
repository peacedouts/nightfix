package e2e_test

// Alert-storm load test. Not part of CI: set NIGHTFIX_STORM=1.
//
//	NIGHTFIX_STORM=1 go test ./internal/e2e -run TestStorm -v -timeout 30m
//
// Three control-plane instances (each with its own 20-connection pool and
// the production worker tick) share one database. Senders post signed
// webhook alerts round-robin across the three ingest listeners. Knobs:
// NIGHTFIX_STORM_N (events, default 2000), NIGHTFIX_STORM_CONC (concurrent
// senders, default 48), NIGHTFIX_STORM_PD_DELAY (PagerDuty latency, 100ms).

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}

type stormOrg struct {
	id, key, slug string
	ingest        map[string]string // service -> ingest URL path (after the host)
	secret        map[string]string
}

type stormEnv struct {
	t       *testing.T
	ctx     context.Context
	srvs    []*controlplane.Server
	pools   []*db.DB
	ingests []string
	api     string
	admin   *sql.DB
	pdMu    sync.Mutex
	pdFirst map[string]time.Time // routing key -> first trigger received
	pdCount atomic.Int64
	workers bool
	halfway chan struct{}       // closed once half of a send's events have been posted
	groupBy map[string][]string // service -> grouping labels, for newOrg
}

func setupStorm(t *testing.T, workers bool) *stormEnv {
	t.Helper()
	pool := testdb.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, err := controlplane.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &stormEnv{t: t, ctx: ctx, pdFirst: map[string]time.Time{}, workers: workers, halfway: make(chan struct{})}
	pdDelay := time.Duration(envInt("NIGHTFIX_STORM_PD_DELAY_MS", 100)) * time.Millisecond
	pd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		time.Sleep(pdDelay)
		if r.URL.Path == "/pd" && ev["event_action"] == "trigger" {
			e.pdCount.Add(1)
			k := fmt.Sprint(ev["routing_key"])
			e.pdMu.Lock()
			if _, ok := e.pdFirst[k]; !ok {
				e.pdFirst[k] = time.Now()
			}
			e.pdMu.Unlock()
		}
		w.WriteHeader(202)
	}))
	t.Cleanup(pd.Close)
	t.Setenv("STORM_PD_URL", pd.URL)

	var name string
	pool.QueryRow(`SELECT current_database()`).Scan(&name)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	for i := range 3 {
		p := pool
		if i > 0 {
			if p, err = db.Open(ctx, testdb.AppDSNFor(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"), name)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.Close() })
		}
		srv := controlplane.New(p, sealer, ca, controlplane.Config{PublicIngestURL: "http://ingest", AllowPrivateTargets: true}, log)
		ing := httptest.NewServer(srv.IngestHandler())
		t.Cleanup(ing.Close)
		e.srvs, e.pools, e.ingests = append(e.srvs, srv), append(e.pools, p), append(e.ingests, ing.URL)
	}
	api := httptest.NewServer(e.srvs[0].APIHandler())
	t.Cleanup(api.Close)
	e.api = api.URL
	e.admin = adminDB(t, pool)
	return e
}

func (e *stormEnv) startWorkers() {
	for _, s := range e.srvs {
		s.RunWorkers(e.ctx, 0) // production tick (250ms)
	}
}

func (e *stormEnv) call(key, method, path string, body, out any) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, e.api+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		e.t.Fatalf("%s %s -> %d %s", method, path, resp.StatusCode, rb)
	}
	if out != nil {
		json.Unmarshal(rb, out)
	}
}

// newOrg creates an org with the given services, each with a PagerDuty
// target (routing key <slug>/<service>) and a webhook integration.
func (e *stormEnv) newOrg(slug string, services ...string) *stormOrg {
	o, err := e.srvs[0].CreateOrg(e.ctx, slug, slug)
	if err != nil {
		e.t.Fatal(err)
	}
	so := &stormOrg{id: o.OrgID, key: o.APIKey, slug: slug, ingest: map[string]string{}, secret: map[string]string{}}
	for _, svc := range services {
		svcBody := map[string]any{"name": svc}
		if gl := e.groupBy[svc]; gl != nil {
			svcBody["grouping_labels"] = gl
		}
		e.call(so.key, "POST", "/v1/services", svcBody, nil)
		e.call(so.key, "POST", "/v1/services/"+svc+"/escalation-targets", map[string]any{"type": "pagerduty",
			"routing_key": slug + "/" + svc, "events_url": os.Getenv("STORM_PD_URL") + "/pd"}, nil)
		var integ map[string]string
		e.call(so.key, "POST", "/v1/integrations", map[string]any{"type": "webhook", "name": svc, "default_service": svc}, &integ)
		so.ingest[svc] = strings.TrimPrefix(integ["ingest_url"], "http://ingest")
		so.secret[svc] = integ["signing_secret"]
	}
	return so
}

type stormEvent struct {
	org  *stormOrg
	svc  string
	body map[string]any
}

type ingestStats struct {
	lat    []time.Duration
	errors int
	start  time.Time
	end    time.Time
}

var stormClient = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

func (e *stormEnv) post(i int, ev stormEvent) (int, time.Duration) {
	b, _ := json.Marshal(ev.body)
	req, _ := http.NewRequest("POST", e.ingests[i%len(e.ingests)]+ev.org.ingest[ev.svc], bytes.NewReader(b))
	req.Header.Set(controlplane.WebhookSignatureHeader, controlplane.SignWebhook(ev.org.secret[ev.svc], b, time.Now()))
	start := time.Now()
	resp, err := stormClient.Do(req)
	if err != nil {
		return 0, time.Since(start)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

// send posts every event with conc concurrent senders.
func (e *stormEnv) send(events []stormEvent, conc int) *ingestStats {
	st := &ingestStats{start: time.Now()}
	select {
	case <-e.halfway: // used by an earlier send
		e.halfway = make(chan struct{})
	default:
	}
	halfway := e.halfway
	var half sync.Once
	var mu sync.Mutex
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(events) {
					return
				}
				if i == len(events)/2 {
					half.Do(func() { close(halfway) })
				}
				code, d := e.post(w+i, events[i])
				mu.Lock()
				st.lat = append(st.lat, d)
				if code != 202 {
					st.errors++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	st.end = time.Now()
	return st
}

func pct(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s)-1) * p)
	return s[i]
}

// sampler records peak database connections and heap while a scenario runs.
type sampler struct {
	stop                       chan struct{}
	done                       chan struct{}
	maxBackends, maxActive     int
	maxInUse                   []int
	maxHeap                    uint64
	maxUnprocessed, maxPending int
	waitCount                  []int64
	waitDur                    []time.Duration
}

func (e *stormEnv) sample() *sampler {
	s := &sampler{stop: make(chan struct{}), done: make(chan struct{}), maxInUse: make([]int, len(e.pools))}
	go func() {
		defer close(s.done)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			var n, act, unp, pend int
			e.admin.QueryRow(`SELECT count(*), count(*) FILTER (WHERE state <> 'idle') FROM pg_stat_activity WHERE datname = current_database()`).Scan(&n, &act)
			e.admin.QueryRow(`SELECT (SELECT count(*) FROM alert_events WHERE processed_at IS NULL), (SELECT count(*) FROM notifications WHERE status = 'pending')`).Scan(&unp, &pend)
			s.maxBackends, s.maxActive = max(s.maxBackends, n), max(s.maxActive, act)
			s.maxUnprocessed, s.maxPending = max(s.maxUnprocessed, unp), max(s.maxPending, pend)
			for i, p := range e.pools {
				s.maxInUse[i] = max(s.maxInUse[i], p.Stats().InUse)
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			s.maxHeap = max(s.maxHeap, m.HeapInuse)
			select {
			case <-s.stop:
				for _, p := range e.pools {
					st := p.Stats()
					s.waitCount = append(s.waitCount, st.WaitCount)
					s.waitDur = append(s.waitDur, st.WaitDuration)
				}
				return
			case <-t.C:
			}
		}
	}()
	return s
}

func (s *sampler) end() { close(s.stop); <-s.done }

// waitProcessed waits until no alert event is unprocessed and returns when
// that happened.
func (e *stormEnv) waitProcessed(timeout time.Duration) (time.Time, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var n int
		e.admin.QueryRow(`SELECT count(*) FROM alert_events WHERE processed_at IS NULL`).Scan(&n)
		if n == 0 {
			return time.Now(), true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Now(), false
}

// pageEnqueued waits for the first page notification on org/service.
func (e *stormEnv) pageEnqueued(o *stormOrg, svc string, timeout time.Duration) (time.Time, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var at sql.NullTime
		e.admin.QueryRow(`SELECT min(n.created_at) FROM notifications n JOIN incidents i ON i.id = n.incident_id
			JOIN services s ON s.id = i.service_id WHERE n.kind = 'page' AND n.org_id = $1 AND s.name = $2`, o.id, svc).Scan(&at)
		if at.Valid {
			return at.Time, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return time.Time{}, false
}

func (e *stormEnv) pdDelivered(key string, timeout time.Duration) (time.Time, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		e.pdMu.Lock()
		at, ok := e.pdFirst[key]
		e.pdMu.Unlock()
		if ok {
			return at, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return time.Time{}, false
}

func firing(key, summary string, labels map[string]string) map[string]any {
	return map[string]any{"dedup_key": key, "summary": summary, "labels": labels}
}

// probe sends one new alert (opening a new incident) and measures the time
// until its page is enqueued and until PagerDuty receives it.
type probeResult struct {
	ingest, enqueued, delivered time.Duration
	okEnq, okDel                bool
}

func (e *stormEnv) probe(o *stormOrg, svc string, timeout time.Duration) probeResult {
	sent := time.Now()
	code, d := e.post(0, stormEvent{o, svc, firing("probe", "probe: "+svc+" down", nil)})
	if code != 202 {
		e.t.Errorf("probe ingest status %d", code)
	}
	r := probeResult{ingest: d}
	var at time.Time
	if at, r.okEnq = e.pageEnqueued(o, svc, timeout); r.okEnq {
		r.enqueued = at.Sub(sent)
	}
	if at, r.okDel = e.pdDelivered(o.slug+"/"+svc, timeout); r.okDel {
		r.delivered = at.Sub(sent)
	}
	return r
}

func (r probeResult) String() string {
	f := func(d time.Duration, ok bool) string {
		if !ok {
			return "not within timeout"
		}
		return d.Round(time.Millisecond).String()
	}
	return fmt.Sprintf("ingest %v, page enqueued after %s, PagerDuty received after %s", r.ingest.Round(time.Millisecond), f(r.enqueued, r.okEnq), f(r.delivered, r.okDel))
}

// processingRate reports events/s over the first and last 20% of processed
// events (a rising per-event cost shows as a falling rate).
func (e *stormEnv) processingRate(since time.Time) string {
	rows, err := e.admin.Query(`SELECT processed_at FROM alert_events WHERE processed_at IS NOT NULL AND received_at >= $1 ORDER BY processed_at`, since)
	if err != nil {
		return err.Error()
	}
	defer rows.Close()
	var ts []time.Time
	for rows.Next() {
		var t time.Time
		rows.Scan(&t)
		ts = append(ts, t)
	}
	if len(ts) < 10 {
		return "n/a"
	}
	k := len(ts) / 5
	rate := func(a, b time.Time, n int) float64 { return float64(n) / max(b.Sub(a).Seconds(), 1e-3) }
	return fmt.Sprintf("%.0f ev/s first 20%%, %.0f ev/s last 20%%, %.0f ev/s overall",
		rate(ts[0], ts[k], k), rate(ts[len(ts)-1-k], ts[len(ts)-1], k), rate(ts[0], ts[len(ts)-1], len(ts)-1))
}

func (e *stormEnv) report(name string, st *ingestStats, s *sampler, done time.Time, okDone bool, probes map[string]probeResult) {
	t := e.t
	t.Logf("=== %s", name)
	t.Logf("ingest: %d requests in %v (%.0f req/s), errors=%d, p50=%v p95=%v p99=%v max=%v", len(st.lat), st.end.Sub(st.start).Round(time.Millisecond),
		float64(len(st.lat))/st.end.Sub(st.start).Seconds(), st.errors, pct(st.lat, .5).Round(time.Millisecond), pct(st.lat, .95).Round(time.Millisecond),
		pct(st.lat, .99).Round(time.Millisecond), pct(st.lat, 1).Round(time.Millisecond))
	if okDone {
		t.Logf("all events processed %v after the first send (%v after the last ingest returned)", done.Sub(st.start).Round(time.Millisecond), done.Sub(st.end).Round(time.Millisecond))
	} else {
		t.Logf("events NOT all processed within the timeout")
	}
	t.Logf("processing rate: %s", e.processingRate(st.start))
	for k, p := range probes {
		t.Logf("probe %s: %s", k, p)
	}
	t.Logf("db: peak backends=%d (non-idle %d), peak pool in-use per instance=%v (limit 20), pool waits=%v (total wait %v), peak unprocessed=%d, peak pending notifications=%d, peak heap=%dMiB, PagerDuty triggers=%d",
		s.maxBackends, s.maxActive, s.maxInUse, s.waitCount, s.waitDur, s.maxUnprocessed, s.maxPending, s.maxHeap>>20, e.pdCount.Load())
	var incidents, timeline, notes int
	e.admin.QueryRow(`SELECT (SELECT count(*) FROM incidents), (SELECT count(*) FROM incident_timeline), (SELECT count(*) FROM notifications)`).Scan(&incidents, &timeline, &notes)
	t.Logf("rows: incidents=%d timeline=%d notifications=%d", incidents, timeline, notes)
}

func stormGuard(t *testing.T) {
	if os.Getenv("NIGHTFIX_STORM") == "" || testing.Short() {
		t.Skip("load test: set NIGHTFIX_STORM=1")
	}
}

// One noisy org: N distinct alerts on one service (grouped into one
// incident). Mid-storm, the same org opens a new incident on another
// service, and a quiet org opens one too.
func TestStormOneOrg(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_N", 2000), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, true)
	noisy := e.newOrg("noisy", "web", "db")
	quiet := e.newOrg("quiet", "api")
	e.startWorkers()
	var evs []stormEvent
	for i := range n {
		evs = append(evs, stormEvent{noisy, "web", firing(fmt.Sprint("host-", i), "web 5xx high", map[string]string{"host": fmt.Sprint("h", i)})})
	}
	s := e.sample()
	probes := map[string]probeResult{}
	var pw sync.WaitGroup
	pw.Add(1)
	go func() {
		defer pw.Done()
		<-e.halfway // inside the storm
		var mu sync.Mutex
		var w sync.WaitGroup
		for _, p := range []struct {
			name string
			o    *stormOrg
			svc  string
		}{{"same org, new incident (noisy/db)", noisy, "db"}, {"other org (quiet/api)", quiet, "api"}} {
			w.Add(1)
			go func() {
				defer w.Done()
				r := e.probe(p.o, p.svc, 5*time.Minute)
				mu.Lock()
				probes[p.name] = r
				mu.Unlock()
			}()
		}
		w.Wait()
	}()
	st := e.send(evs, conc)
	done, ok := e.waitProcessed(10 * time.Minute)
	pw.Wait()
	s.end()
	e.report(fmt.Sprintf("one org, %d events, %d senders, 3 instances", n, conc), st, s, done, ok, probes)
}

// The same number of events spread across 20 orgs, plus a quiet org.
func TestStormTwentyOrgs(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_N", 2000), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, true)
	var orgs []*stormOrg
	for i := range 20 {
		orgs = append(orgs, e.newOrg(fmt.Sprint("org", i), "web"))
	}
	quiet := e.newOrg("quiet", "api")
	e.startWorkers()
	var evs []stormEvent
	for i := range n {
		o := orgs[i%len(orgs)]
		evs = append(evs, stormEvent{o, "web", firing(fmt.Sprint("host-", i), "web 5xx high", map[string]string{"host": fmt.Sprint("h", i)})})
	}
	s := e.sample()
	probes := map[string]probeResult{}
	var pw sync.WaitGroup
	pw.Add(1)
	go func() {
		defer pw.Done()
		<-e.halfway
		probes["other org (quiet/api)"] = e.probe(quiet, "api", 5*time.Minute)
	}()
	st := e.send(evs, conc)
	done, ok := e.waitProcessed(10 * time.Minute)
	pw.Wait()
	s.end()
	e.report(fmt.Sprintf("20 orgs, %d events, %d senders, 3 instances", n, conc), st, s, done, ok, probes)
}

// Baseline: ingest alone (no workers), so its latency without processing
// contending for the per-org lock can be compared with TestStormOneOrg.
func TestStormIngestOnlyBaseline(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_N", 2000), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, false)
	noisy := e.newOrg("noisy", "web")
	var evs []stormEvent
	for i := range n {
		evs = append(evs, stormEvent{noisy, "web", firing(fmt.Sprint("host-", i), "web 5xx high", nil)})
	}
	s := e.sample()
	st := e.send(evs, conc)
	s.end()
	e.report(fmt.Sprintf("ingest only (no workers), one org, %d events, %d senders", n, conc), st, s, st.end, true, nil)
	// Then let one instance's workers drain the backlog, to time processing alone.
	start := time.Now()
	e.startWorkers()
	done, ok := e.waitProcessed(10 * time.Minute)
	t.Logf("backlog of %d drained by 3 instances in %v (ok=%v); %s", n, done.Sub(start).Round(time.Millisecond), ok, e.processingRate(st.start))
}

// A big incident clearing: N alerts in one incident, then all resolve.
// Each resolve counts the incident's firing alerts (checkAlertsCleared).
func TestStormResolveWave(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_N", 2000), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, true)
	o := e.newOrg("noisy", "web")
	e.startWorkers()
	var fire, res []stormEvent
	for i := range n {
		fire = append(fire, stormEvent{o, "web", firing(fmt.Sprint("host-", i), "web down", nil)})
		res = append(res, stormEvent{o, "web", map[string]any{"dedup_key": fmt.Sprint("host-", i), "summary": "web ok", "status": "resolved"}})
	}
	s := e.sample()
	st := e.send(fire, conc)
	done, ok := e.waitProcessed(10 * time.Minute)
	t.Logf("firing wave processed in %v (ok=%v); %s", done.Sub(st.start).Round(time.Millisecond), ok, e.processingRate(st.start))
	st2 := e.send(res, conc)
	done2, ok2 := e.waitProcessed(10 * time.Minute)
	s.end()
	e.report(fmt.Sprintf("resolve wave: %d alerts in one incident clear", n), st2, s, done2, ok2, nil)
}

// As many noisy orgs as there are instances (a regional AWS event fires
// alarms for many customers at once), and a quiet org that opens one
// incident halfway through the storm and another just after it.
func TestStormThreeNoisyOrgs(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_N", 2000), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, true)
	var orgs []*stormOrg
	for i := range 3 {
		orgs = append(orgs, e.newOrg(fmt.Sprint("noisy", i), "web"))
	}
	quiet := e.newOrg("quiet", "api", "db")
	e.startWorkers()
	var evs []stormEvent
	for i := range n {
		o := orgs[i%len(orgs)]
		evs = append(evs, stormEvent{o, "web", firing(fmt.Sprint("host-", i), "web 5xx high", nil)})
	}
	s := e.sample()
	probes := map[string]probeResult{}
	var mu sync.Mutex
	var pw sync.WaitGroup
	pw.Add(1)
	go func() {
		defer pw.Done()
		<-e.halfway
		r := e.probe(quiet, "api", 5*time.Minute)
		mu.Lock()
		probes["quiet org, halfway through the storm (quiet/api)"] = r
		mu.Unlock()
	}()
	st := e.send(evs, conc)
	r := e.probe(quiet, "db", 5*time.Minute)
	mu.Lock()
	probes["quiet org, right after the storm's last delivery (quiet/db)"] = r
	mu.Unlock()
	done, ok := e.waitProcessed(10 * time.Minute)
	pw.Wait()
	s.end()
	e.report(fmt.Sprintf("3 noisy orgs, %d events, %d senders, 3 instances", n, conc), st, s, done, ok, probes)
}

// One org whose service groups by host: every alert opens its own incident
// and pages (PagerDuty only). Pages per org are capped at NotifyWorkers/4 in
// flight across all instances, so this times how long the last page takes,
// and a new page on another service of the same org queued behind them.
func TestStormManyIncidentsOneOrg(t *testing.T) {
	stormGuard(t)
	n, conc := envInt("NIGHTFIX_STORM_INCIDENTS", 500), envInt("NIGHTFIX_STORM_CONC", 48)
	e := setupStorm(t, true)
	e.groupBy = map[string][]string{"web": {"host"}}
	noisy := e.newOrg("noisy", "web", "db")
	quiet := e.newOrg("quiet", "api")
	e.startWorkers()
	var evs []stormEvent
	for i := range n {
		evs = append(evs, stormEvent{noisy, "web", firing(fmt.Sprint("host-", i), "host down", map[string]string{"host": fmt.Sprint("h", i)})})
	}
	s := e.sample()
	st := e.send(evs, conc)
	done, ok := e.waitProcessed(10 * time.Minute)
	probes := map[string]probeResult{
		"same org, new incident after the storm (noisy/db)": e.probe(noisy, "db", 10*time.Minute),
		"other org after the storm (quiet/api)":             e.probe(quiet, "api", 10*time.Minute),
	}
	deadline := time.Now().Add(10 * time.Minute)
	for e.pdCount.Load() < int64(n+2) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	allPaged := time.Now()
	s.end()
	e.report(fmt.Sprintf("one org, %d alerts each opening an incident", n), st, s, done, ok, probes)
	t.Logf("all %d pages delivered %v after the first send (PagerDuty latency %dms)", e.pdCount.Load(), allPaged.Sub(st.start).Round(time.Millisecond), envInt("NIGHTFIX_STORM_PD_DELAY_MS", 100))
}
