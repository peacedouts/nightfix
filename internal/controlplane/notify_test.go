package controlplane

// Regression tests for the notification outbox (migration 0020): one bad
// row or slow endpoint must not hold up anyone else's pages, delivery stays
// in order per destination with concurrent workers, pages outlast a long
// upstream outage, and tenant-supplied URLs can't reach internal addresses.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

type notifyHarness struct {
	t   *testing.T
	s   *Server
	log *syncBuffer
	n   int
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func setupNotify(t *testing.T, cfg Config) *notifyHarness {
	t.Helper()
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return &notifyHarness{t: t, s: New(pool, sealer, nil, cfg, log), log: buf}
}

func (h *notifyHarness) with(org string, fn func(tx *db.Tx) error) {
	h.t.Helper()
	if err := h.s.DB.WithOrg(context.Background(), org, fn); err != nil {
		h.t.Fatal(err)
	}
}

func (h *notifyHarness) exec(org, q string, args ...any) {
	h.t.Helper()
	h.with(org, func(tx *db.Tx) error { _, err := tx.Exec(q, args...); return err })
}

// org creates an org with one service and returns both ids.
func (h *notifyHarness) org() (org, svc string) {
	h.t.Helper()
	h.n++
	org, svc = testdb.CreateOrg(h.t, h.s.DB, "org"+ids.NewString()[24:]), ids.NewString()
	h.exec(org, `INSERT INTO services (id, org_id, name) VALUES ($1,$2,'svc')`, svc, org)
	return org, svc
}

func (h *notifyHarness) target(org, svc, typ, secret string, cfg map[string]string) string {
	h.t.Helper()
	sealed, err := h.s.seal([]byte(secret), org, sealNotifyCredential)
	if err != nil {
		h.t.Fatal(err)
	}
	id := ids.NewString()
	if cfg == nil {
		cfg = map[string]string{}
	}
	h.exec(org, `INSERT INTO escalation_targets (id, org_id, service_id, type, config, credential) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, org, svc, typ, db.JSON[map[string]string]{V: cfg}, sealed)
	return id
}

func (h *notifyHarness) channel(org, url string) string {
	h.t.Helper()
	sealed, _ := h.s.seal([]byte(url), org, sealNotifyCredential)
	id := ids.NewString()
	h.exec(org, `INSERT INTO approval_channels (id, org_id, credential, created_by) VALUES ($1,$2,$3,'test')`, id, org, sealed)
	return id
}

func (h *notifyHarness) incident(org, svc string) string {
	h.t.Helper()
	h.n++
	id := ids.NewString()
	h.exec(org, `INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
		VALUES ($1,$2,$3,$4,$5,'triggered','critical','checkout down')`, id, org, h.n, svc, id)
	return id
}

func (h *notifyHarness) notify(org, inc, target, kind string) string {
	h.t.Helper()
	id := ids.NewString()
	h.exec(org, `INSERT INTO notifications (id, org_id, incident_id, target_id, kind, payload) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, org, inc, target, kind, db.JSON[map[string]any]{V: map[string]any{
			"incident_id": inc, "incident_number": 1, "kind": kind, "title": "checkout down", "service": "svc",
			"severity": "critical", "reason": "r"}})
	return id
}

func (h *notifyHarness) notifyChannel(org, channel, kind string) string {
	h.t.Helper()
	id := ids.NewString()
	h.exec(org, `INSERT INTO notifications (id, org_id, channel_id, kind, payload) VALUES ($1,$2,$3,$4,$5)`,
		id, org, channel, kind, db.JSON[map[string]any]{V: map[string]any{"kind": kind, "reason": "r",
			"approval": map[string]any{"runbook": "rb", "requested_by": "me"}}})
	return id
}

type notifyRow struct {
	Status, LastError string
	Attempts          int
	Next              time.Time
}

func (h *notifyHarness) row(org, id string) notifyRow {
	h.t.Helper()
	var r notifyRow
	h.with(org, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT status, coalesce(last_error, ''), attempts, next_attempt_at FROM notifications WHERE id = $1`, id).
			Scan(&r.Status, &r.LastError, &r.Attempts, &r.Next)
	})
	return r
}

// due makes every pending notification due now (skipping the backoff).
func (h *notifyHarness) due(org string) {
	h.t.Helper()
	h.exec(org, `UPDATE notifications SET next_attempt_at = now() WHERE status = 'pending'`)
}

func (h *notifyHarness) deliver() int {
	h.t.Helper()
	n, err := h.s.DeliverNotifications(context.Background())
	if err != nil {
		h.t.Fatalf("DeliverNotifications: %v", err)
	}
	return n
}

// roundTripper fakes the network for allowlisted hosts.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okResponse(r *http.Request) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}, Request: r}
}

// pdRecorder is a PagerDuty stand-in that records what it accepted.
type pdRecorder struct {
	mu     sync.Mutex
	events []string // "<dedup_key> <action>"
	status func(action string) int
	delay  time.Duration
}

func (p *pdRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ev map[string]any
	json.NewDecoder(r.Body).Decode(&ev)
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	action, _ := ev["event_action"].(string)
	key, _ := ev["dedup_key"].(string)
	if p.status != nil {
		if code := p.status(action); code != 200 {
			w.WriteHeader(code)
			return
		}
	}
	p.mu.Lock()
	p.events = append(p.events, key+" "+action)
	p.mu.Unlock()
}

func (p *pdRecorder) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.events...)
}

// A transport error echoing a certificate SAN with a NUL byte used to fail
// the UPDATE of last_error; the claim rolled back, DeliverNotifications
// returned the error, and the same row was claimed first on every tick, so
// delivery stopped for every tenant.
func TestNotifyPoisonedErrorDoesNotStallOtherTenants(t *testing.T) {
	var mu sync.Mutex
	var delivered []string
	h := setupNotify(t, Config{NotifyWorkers: 1, NotifyHTTPClient: &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/services/poison" {
			return nil, errors.New("tls: x509: certificate is valid for evil\x00.example, \xff\xfe not hooks.slack.com")
		}
		mu.Lock()
		delivered = append(delivered, r.URL.Path)
		mu.Unlock()
		return okResponse(r), nil
	})}})
	a, asvc := h.org()
	poisoned := h.notify(a, h.incident(a, asvc), h.target(a, asvc, "slack", "https://hooks.slack.com/services/poison", nil), "page")
	b, bsvc := h.org()
	page := h.notify(b, h.incident(b, bsvc), h.target(b, bsvc, "slack", "https://hooks.slack.com/services/b", nil), "page")

	for range 3 {
		h.deliver()
		h.due(a)
	}
	if got := h.row(b, page); got.Status != "sent" {
		t.Fatalf("org B's page is %q; a poisoned row in org A must not hold it up", got.Status)
	}
	got := h.row(a, poisoned)
	if got.Status != "pending" || got.Attempts != 3 {
		t.Fatalf("poisoned row: status %q, %d attempts; want pending with 3 attempts recorded", got.Status, got.Attempts)
	}
	if strings.ContainsRune(got.LastError, 0) || !utf8.ValidString(got.LastError) || strings.Contains(got.LastError, "evil") {
		t.Fatalf("last_error %q must be clean and must not echo transport details", got.LastError)
	}
	if got.LastError != "could not connect to Slack" {
		t.Fatalf("last_error %q, want the generic reason", got.LastError)
	}
}

func TestNotifyErrorTextIsCleanedAndCapped(t *testing.T) {
	in := "a\x00b\xffc" + strings.Repeat("é", 1000)
	out := cleanNotifyError(in)
	if strings.ContainsRune(out, 0) || !utf8.ValidString(out) || len(out) > maxNotifyErrorLen {
		t.Fatalf("cleanNotifyError gave %d bytes, valid=%v, NUL=%v", len(out), utf8.ValidString(out), strings.ContainsRune(out, 0))
	}
	if !strings.HasPrefix(out, "ab�c") {
		t.Fatalf("cleanNotifyError(%q...) = %q...", in[:6], out[:8])
	}
}

// Three tenants with hanging Slack URLs used to delay another org's page by
// 30s (sequential delivery, 10s timeout, inside the claim transaction).
func TestNotifyHangingEndpointDoesNotDelayOtherOrgs(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hang.Close)
	t.Cleanup(func() { close(release) }) // runs before hang.Close
	arrived := make(chan time.Time, 1)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- time.Now():
		default:
		}
	}))
	t.Cleanup(fast.Close)

	h := setupNotify(t, Config{AllowPrivateTargets: true})
	var hung []string
	var hungOrgs []string
	for range 3 {
		o, svc := h.org()
		hung = append(hung, h.notify(o, h.incident(o, svc), h.target(o, svc, "slack", hang.URL+"/hook", nil), "page"))
		hungOrgs = append(hungOrgs, o)
	}
	d, dsvc := h.org()
	page := h.notify(d, h.incident(d, dsvc), h.target(d, dsvc, "slack", fast.URL+"/hook", nil), "page")

	start := time.Now()
	done := make(chan struct{})
	go func() { defer close(done); h.s.DeliverNotifications(context.Background()) }()
	select {
	case at := <-arrived:
		if lag := at.Sub(start); lag > time.Second {
			t.Fatalf("org D's page arrived after %v; hanging endpoints of other orgs must not delay it", lag)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("org D's page wasn't delivered within 3s while other orgs' endpoints hung")
	}
	select {
	case <-done:
	case <-time.After(notifyRequestTimeout + 5*time.Second):
		t.Fatal("DeliverNotifications didn't return after the request timeout")
	}
	if got := h.row(d, page); got.Status != "sent" {
		t.Fatalf("org D's page is %q", got.Status)
	}
	for i, id := range hung {
		if got := h.row(hungOrgs[i], id); got.Status != "pending" || got.LastError != "could not connect to Slack" {
			t.Fatalf("hung page: %+v; want pending with a generic reason", got)
		}
	}
}

// With several workers, a resolve can't be claimed while its page is in
// flight (leased) or backing off, while other destinations proceed.
func TestNotifyClaimKeepsOrderAcrossWorkers(t *testing.T) {
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	a, svc := h.org()
	tgt := h.target(a, svc, "pagerduty", "rk", map[string]string{"events_url": "http://127.0.0.1:1/pd"})
	inc := h.incident(a, svc)
	page := h.notify(a, inc, tgt, "page")
	resolve := h.notify(a, inc, tgt, "resolve")
	ch := h.channel(a, "http://127.0.0.1:1/slack")
	ask := h.notifyChannel(a, ch, "approval")
	h.notifyChannel(a, ch, "update")
	b, bsvc := h.org()
	other := h.notify(b, h.incident(b, bsvc), h.target(b, bsvc, "pagerduty", "rk", map[string]string{"events_url": "http://127.0.0.1:1/pd"}), "page")

	claim := func() string {
		t.Helper()
		var org, id string
		err := h.s.DB.QueryRow(`SELECT org_id, id FROM nfx_claim_notification('1 minute', $1, 100)`, ids.NewString()).Scan(&org, &id)
		if err != nil && !isNoRows(err) {
			t.Fatal(err)
		}
		return id
	}
	got := map[string]bool{}
	for range 3 {
		got[claim()] = true
	}
	if !got[page] || !got[ask] || !got[other] {
		t.Fatalf("three workers claimed %v; want the page, the approval request and org B's page", got)
	}
	if id := claim(); id != "" {
		t.Fatalf("a fourth worker claimed %s; the resolve and update must wait for the leased rows ahead of them", id)
	}
	// An expired lease (crashed worker) makes the page claimable again,
	// and the resolve still waits behind it.
	h.exec(a, `UPDATE notifications SET lease_until = now() - interval '1 second' WHERE id = $1`, page)
	if id := claim(); id != page {
		t.Fatalf("after its lease expired, claimed %q; want the page %s again", id, page)
	}
	if id := claim(); id == resolve {
		t.Fatal("the resolve was claimed while the page ahead of it was leased")
	}
}

// End to end with several delivery workers: PagerDuty sees every page
// before its resolve, even when pages fail and back off.
func TestNotifyOrderHoldsWithConcurrentWorkers(t *testing.T) {
	var mu sync.Mutex
	failed := map[string]bool{}
	pd := &pdRecorder{delay: 5 * time.Millisecond}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		json.Unmarshal(b, &ev)
		key := ev["dedup_key"].(string)
		mu.Lock()
		first := !failed[key] && ev["event_action"] == "trigger"
		failed[key] = failed[key] || first
		mu.Unlock()
		if first { // every page fails once
			w.WriteHeader(502)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		pd.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	h := setupNotify(t, Config{AllowPrivateTargets: true, NotifyWorkers: 4})
	org, svc := h.org()
	tgt := h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": srv.URL + "/pd"})
	const incidents = 12
	for range incidents {
		inc := h.incident(org, svc)
		h.notify(org, inc, tgt, "page")
		h.notify(org, inc, tgt, "resolve")
	}
	for range 6 {
		h.deliver()
		h.due(org)
	}
	events := pd.got()
	if len(events) != 2*incidents {
		t.Fatalf("PagerDuty accepted %d events, want %d: %v", len(events), 2*incidents, events)
	}
	seen := map[string]string{}
	for _, e := range events {
		key, action, _ := strings.Cut(e, " ")
		if action == "resolve" && seen[key] != "trigger" {
			t.Fatalf("%s resolved before it was paged: %v", key, events)
		}
		seen[key] = action
	}
}

// Pages used to be dropped after 8 attempts (3-4.5 minutes of PagerDuty
// trouble). They now retry until delivered, and stop with a clear reason
// once their incident is resolved.
func TestNotifyPageRetriesPastEightAttemptsUntilResolved(t *testing.T) {
	pd := &pdRecorder{status: func(string) int { return 500 }}
	srv := httptest.NewServer(pd)
	t.Cleanup(srv.Close)
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	tgt := h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": srv.URL + "/pd"})
	inc := h.incident(org, svc)
	page := h.notify(org, inc, tgt, "page")
	ch := h.channel(org, srv.URL+"/slack")
	update := h.notifyChannel(org, ch, "update")

	for range 12 {
		h.deliver()
		h.due(org)
	}
	got := h.row(org, page)
	if got.Status != "pending" || got.Attempts != 12 {
		t.Fatalf("page after 12 failures: %+v; want still pending", got)
	}
	if got.LastError != "PagerDuty returned HTTP 500" {
		t.Fatalf("page last_error %q", got.LastError)
	}
	if u := h.row(org, update); u.Status != "failed" || u.Attempts != maxNotifyAttempts {
		t.Fatalf("approval-channel update: %+v; other kinds keep a bounded attempt count", u)
	}
	// Approval-channel rows have no incident timeline: operators see them in the log.
	if !strings.Contains(h.log.String(), "notification abandoned") || !strings.Contains(h.log.String(), ch) {
		t.Fatalf("abandoned approval-channel notification wasn't logged with its channel:\n%s", h.log.String())
	}

	// Backoff is capped at about 5 minutes.
	h.exec(org, `UPDATE notifications SET next_attempt_at = now() WHERE id = $1`, page)
	h.deliver()
	got = h.row(org, page)
	if wait := time.Until(got.Next); wait < 3*time.Minute || wait > 7*time.Minute {
		t.Fatalf("page retries in %v after 13 attempts; want about 5 minutes", wait)
	}

	h.exec(org, `UPDATE incidents SET status = 'resolved', resolved_at = now() WHERE id = $1`, inc)
	h.due(org)
	h.deliver()
	got = h.row(org, page)
	if got.Status != "failed" || !strings.Contains(got.LastError, "incident was resolved") {
		t.Fatalf("page for a resolved incident: %+v; want failed with the reason", got)
	}
	var msg string
	h.with(org, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT message FROM incident_timeline WHERE incident_id = $1 AND type = 'notification.failed'`, inc).Scan(&msg)
	})
	if !strings.Contains(msg, "incident was resolved") || strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("timeline says %q", msg)
	}
	if len(pd.got()) != 0 {
		t.Fatalf("PagerDuty accepted %v", pd.got())
	}
}

func TestNotifyGivesUpAfter24Hours(t *testing.T) {
	pd := &pdRecorder{status: func(string) int { return 503 }}
	srv := httptest.NewServer(pd)
	t.Cleanup(srv.Close)
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	inc := h.incident(org, svc)
	page := h.notify(org, inc, h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": srv.URL}), "page")
	h.exec(org, `UPDATE notifications SET created_at = now() - interval '25 hours'`)
	h.deliver()
	if got := h.row(org, page); got.Status != "failed" || !strings.Contains(got.LastError, "24 hours") {
		t.Fatalf("day-old page: %+v", got)
	}
}

// HTTP 429 doesn't use up an attempt, and Retry-After is honoured.
func TestNotifyRateLimitHonoursRetryAfter(t *testing.T) {
	var mu sync.Mutex
	replies := []func(w http.ResponseWriter){
		func(w http.ResponseWriter) { w.Header().Set("Retry-After", "120"); w.WriteHeader(429) },
		func(w http.ResponseWriter) { w.WriteHeader(429) },
		func(w http.ResponseWriter) {},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reply := replies[0]
		if len(replies) > 1 {
			replies = replies[1:]
		}
		mu.Unlock()
		reply(w)
	}))
	t.Cleanup(srv.Close)
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	inc := h.incident(org, svc)
	tgt := h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": srv.URL})
	page := h.notify(org, inc, tgt, "page")
	resolve := h.notify(org, inc, tgt, "resolve")

	h.deliver()
	got := h.row(org, page)
	if got.Status != "pending" || got.Attempts != 0 || !strings.Contains(got.LastError, "429") {
		t.Fatalf("after a 429: %+v; want pending with no attempt used", got)
	}
	if wait := time.Until(got.Next); wait < 115*time.Second || wait > 135*time.Second {
		t.Fatalf("retry in %v; want the 120s Retry-After asked for", wait)
	}
	if r := h.row(org, resolve); r.Next.Before(got.Next) {
		t.Fatal("the resolve queued behind the throttled page wasn't moved back with it")
	}
	h.due(org)
	h.deliver()
	got = h.row(org, page)
	if got.Attempts != 0 || time.Until(got.Next) < 7*time.Second {
		t.Fatalf("after a 429 without Retry-After: %+v (retry in %v)", got, time.Until(got.Next))
	}
	h.due(org)
	h.deliver()
	if got = h.row(org, page); got.Status != "sent" || got.Attempts != 1 {
		t.Fatalf("after success: %+v", got)
	}
	if r := h.row(org, resolve); r.Status != "sent" {
		t.Fatalf("resolve: %+v", r)
	}
}

func TestParseRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 0, "0": 0, "-5": 0, "abc": 0, "Wed, 21 Oct 2026 07:28:00 GMT": 0,
		"30": 30 * time.Second, " 7 ": 7 * time.Second, "999999": maxRetryAfter,
	} {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNotifyRetryDelayJitterAndCaps(t *testing.T) {
	for range 200 {
		if d := notifyRetryDelay("page", 30, &deliveryError{}); d < 4*time.Minute || d > 6*time.Minute {
			t.Fatalf("page backoff %v; want 5m ±20%%", d)
		}
		if d := notifyRetryDelay("update", 1, &deliveryError{}); d < 1600*time.Millisecond || d > 2400*time.Millisecond {
			t.Fatalf("first update backoff %v; want 2s ±20%%", d)
		}
	}
}

func TestValidateNotifyURL(t *testing.T) {
	cases := []struct {
		typ, url    string
		prod, devOK bool
	}{
		{"slack", "https://hooks.slack.com/services/T0/B0/x", true, true},
		{"slack", "https://HOOKS.slack.com/services/T0/B0/x", true, true},
		{"slack", "https://hooks.slack.com:443/services/x", true, true},
		{"slack", "http://hooks.slack.com/services/x", false, true},
		{"slack", "https://hooks.slack.com:8443/services/x", false, true},
		{"slack", "https://hooks.slack.com.evil.com/services/x", false, true},
		{"slack", "https://evil.com/#@hooks.slack.com", false, true},
		{"slack", "https://hooks.slack.com@evil.com/x", false, false},
		{"slack", "https://user:pw@hooks.slack.com/x", false, false},
		{"slack", "http://127.0.0.1:9100/slack", false, true},
		{"slack", "http://localhost.evil.com/slack", false, true},
		{"slack", "http://127.0.0.1@evil.com/slack", false, false},
		{"slack", "https://169.254.169.254/latest/meta-data", false, true},
		{"slack", "file:///etc/passwd", false, false},
		{"slack", "hooks.slack.com/services/x", false, false},
		{"slack", "", false, false},
		{"pagerduty", "https://events.pagerduty.com/v2/enqueue", true, true},
		{"pagerduty", "https://events.eu.pagerduty.com/v2/enqueue", true, true},
		{"pagerduty", "https://events.pagerduty.com.evil.com/v2/enqueue", false, true},
		{"pagerduty", "https://hooks.slack.com/services/x", false, true},
		{"pagerduty", "http://10.0.0.5:8080/admin", false, true},
	}
	for _, c := range cases {
		if got := validateNotifyURL(c.typ, c.url, false) == nil; got != c.prod {
			t.Errorf("validateNotifyURL(%s, %q) allowed=%v, want %v", c.typ, c.url, got, c.prod)
		}
		if got := validateNotifyURL(c.typ, c.url, true) == nil; got != c.devOK {
			t.Errorf("validateNotifyURL(%s, %q) with AllowPrivateTargets allowed=%v, want %v", c.typ, c.url, got, c.devOK)
		}
	}
}

// The API refuses internal and non-Slack/PagerDuty URLs unless the dev
// flag is set.
func TestNotifyTargetURLsValidatedAtCreation(t *testing.T) {
	for _, dev := range []bool{false, true} {
		h := setupNotify(t, Config{AllowPrivateTargets: dev})
		org, err := h.s.CreateOrg(context.Background(), "A", "a")
		if err != nil {
			t.Fatal(err)
		}
		api := httptest.NewServer(h.s.APIHandler())
		t.Cleanup(api.Close)
		call := func(method, path string, body any) int {
			b, _ := json.Marshal(body)
			req, _ := http.NewRequest(method, api.URL+path, bytes.NewReader(b))
			req.Header.Set("Authorization", "Bearer "+org.APIKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.StatusCode
		}
		if code := call("POST", "/v1/services", map[string]any{"name": "svc"}); code/100 != 2 {
			t.Fatalf("create service: %d", code)
		}
		internal := []struct {
			path string
			body map[string]any
		}{
			{"/v1/services/svc/escalation-targets", map[string]any{"type": "slack", "url": "http://127.0.0.1:8080/x"}},
			{"/v1/services/svc/escalation-targets", map[string]any{"type": "slack", "url": "http://localhost.evil.com/x"}},
			{"/v1/services/svc/escalation-targets", map[string]any{"type": "slack", "url": "https://internal.example.com/x"}},
			{"/v1/services/svc/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "k", "events_url": "http://169.254.169.254/latest"}},
			{"/v1/approval-channels", map[string]any{"url": "http://127.0.0.1:8080/x"}},
		}
		for _, c := range internal {
			method := "POST"
			if c.path == "/v1/approval-channels" {
				method = "PUT"
			}
			code := call(method, c.path, c.body)
			if !dev && code != 400 {
				t.Errorf("%s %v: got %d, want 400", c.path, c.body, code)
			}
			if dev && code/100 != 2 {
				t.Errorf("with AllowPrivateTargets, %s %v: got %d, want 2xx", c.path, c.body, code)
			}
		}
		for _, c := range []struct {
			method, path string
			body         map[string]any
		}{
			{"POST", "/v1/services/svc/escalation-targets", map[string]any{"type": "slack", "url": "https://hooks.slack.com/services/T/B/x"}},
			{"POST", "/v1/services/svc/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "k"}},
			{"POST", "/v1/services/svc/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "k", "events_url": "https://events.eu.pagerduty.com/v2/enqueue"}},
			{"PUT", "/v1/approval-channels", map[string]any{"url": "https://hooks.slack.com/services/T/B/y"}},
		} {
			if code := call(c.method, c.path, c.body); code/100 != 2 {
				t.Errorf("dev=%v %s %v: got %d, want 2xx", dev, c.path, c.body, code)
			}
		}
	}
}

func TestNotifyAddrAllowed(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "::", "::1", "fc00::1", "fd12::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1",
		"224.0.0.1", "255.255.255.255"} {
		if notifyAddrAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed; want refused", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "54.230.1.1", "2606:4700::1111"} {
		if !notifyAddrAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s refused; want allowed", s)
		}
	}
}

// The notification client refuses internal addresses (whatever a name
// resolves to) unless the dev flag is set, and never follows redirects.
func TestNotifyClientRefusesPrivateAddressesAndRedirects(t *testing.T) {
	var hits sync.Map
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Store(r.URL.Path, true) }))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/redirected", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	_, err := newNotifyClient(false).Post(target.URL+"/direct", "application/json", strings.NewReader("{}"))
	if !errors.Is(err, errAddrNotAllowed) {
		t.Fatalf("POST to %s without the dev flag: err %v, want errAddrNotAllowed", target.URL, err)
	}
	if _, ok := hits.Load("/direct"); ok {
		t.Fatal("the request reached a loopback server")
	}
	resp, err := newNotifyClient(true).Post(redirect.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d; the redirect must not be followed", resp.StatusCode)
	}
	if _, ok := hits.Load("/redirected"); ok {
		t.Fatal("the client followed a redirect")
	}

	// A legacy target pointing inside the network fails with a reason that
	// reveals nothing about it.
	h := setupNotify(t, Config{})
	org, svc := h.org()
	inc := h.incident(org, svc)
	page := h.notify(org, inc, h.target(org, svc, "slack", target.URL+"/secret-webhook", nil), "page")
	h.deliver()
	got := h.row(org, page)
	if got.Status != "failed" || strings.Contains(got.LastError, "127.0.0.1") || strings.Contains(got.LastError, "secret") {
		t.Fatalf("legacy internal target: %+v", got)
	}
	if _, ok := hits.Load("/secret-webhook"); ok {
		t.Fatal("a legacy internal target was reached")
	}
	if strings.Contains(h.log.String(), "secret-webhook") {
		t.Fatal("the webhook URL was logged")
	}
}

// A connection failure is stored as a generic reason, never the dial error
// (which would make the timeline a port scanner) or the URL.
func TestNotifyConnectionFailureReasonIsGeneric(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL + "/services/secret"
	closed.Close()
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	page := h.notify(org, h.incident(org, svc), h.target(org, svc, "slack", url, nil), "page")
	h.deliver()
	if got := h.row(org, page); got.LastError != "could not connect to Slack" {
		t.Fatalf("last_error %q", got.LastError)
	}
	if strings.Contains(h.log.String(), "/services/secret") {
		t.Fatal("the webhook URL was logged")
	}
}

// A worker whose lease expired (and whose row another worker took) can't
// overwrite the newer result.
func TestNotifyStaleLeaseCannotRecord(t *testing.T) {
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	page := h.notify(org, h.incident(org, svc), h.target(org, svc, "slack", "http://127.0.0.1:1/x", nil), "page")
	stale := ids.NewString()
	var id string
	if err := h.s.DB.QueryRow(`SELECT id FROM nfx_claim_notification('1 minute', $1, 100)`, stale).Scan(&id); err != nil || id != page {
		t.Fatalf("claim: %v %s", err, id)
	}
	if n := h.deliver(); n != 0 {
		t.Fatalf("delivered %d notifications while the only one was leased", n)
	}
	h.exec(org, `UPDATE notifications SET lease_until = now() - interval '1 second'`)
	h.exec(org, `UPDATE escalation_targets SET credential = $1`, func() []byte { b, _ := h.s.seal([]byte("http://127.0.0.1:2/y"), org, sealNotifyCredential); return b }())
	h.deliver() // takes the row over: fails, attempt 1
	h.s.recordNotification(context.Background(), &notifyJob{OrgID: org, ID: page, LeaseID: stale, Kind: "page", Type: "slack"}, nil)
	if got := h.row(org, page); got.Status != "pending" || got.Attempts != 1 {
		t.Fatalf("after a stale worker reported success: %+v; its result must be ignored", got)
	}
}

// The claim's ordering check uses the destination indexes: with one org's
// 2,000 incidents x 20 pending notifications behind backed-off heads (and a
// due-but-blocked row behind every head), a claim takes milliseconds. It
// used to take seconds.
func TestNotifyClaimScalesWithBlockedBacklog(t *testing.T) {
	h := setupNotify(t, Config{})
	a, svc := h.org()
	tgt := h.target(a, svc, "pagerduty", "rk", nil)
	h.exec(a, `INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
		SELECT gen_random_uuid(), $1, 1000 + i, $2, 'g' || i, 'triggered', 'critical', 't' FROM generate_series(1, 2000) i`, a, svc)
	h.exec(a, `INSERT INTO notifications (id, org_id, incident_id, target_id, kind, payload, status, attempts, next_attempt_at, created_at)
		SELECT gen_random_uuid(), $1, i.id, $2, 'page', '{}', 'pending', 3, now() + interval '5 minutes', now() - interval '1 hour'
		FROM incidents i`, a, tgt)
	h.exec(a, `INSERT INTO notifications (id, org_id, incident_id, target_id, kind, payload, created_at)
		SELECT gen_random_uuid(), $1, i.id, $2, 'update', '{}', now() - interval '1 hour' + j * interval '1 second'
		FROM incidents i, generate_series(2, 20) j`, a, tgt)
	// What the insert trigger does to rows queued behind a backed-off head.
	var pushed int
	h.with(a, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM notifications WHERE kind = 'update' AND next_attempt_at > now() + interval '4 minutes'`).Scan(&pushed)
	})
	if pushed != 2000*19 {
		t.Fatalf("%d of the rows queued behind backed-off heads start at the head's retry time; want all %d", pushed, 2000*19)
	}
	h.exec(a, `UPDATE notifications SET next_attempt_at = now() - interval '1 minute'
		WHERE kind = 'update' AND created_at = (SELECT max(created_at) FROM notifications WHERE kind = 'update')`)
	h.exec(a, `ANALYZE notifications`)
	b, bsvc := h.org()
	want := h.notify(b, h.incident(b, bsvc), h.target(b, bsvc, "pagerduty", "rk", nil), "page")

	var best time.Duration
	for i := range 3 {
		start := time.Now()
		var id string
		err := h.s.DB.QueryRow(`SELECT id FROM nfx_claim_notification('1 minute', $1, 100)`, ids.NewString()).Scan(&id)
		took := time.Since(start)
		if i == 0 && (err != nil || id != want) {
			t.Fatalf("claim returned %q (%v); want org B's page", id, err)
		}
		if i == 0 || took < best {
			best = took
		}
	}
	t.Logf("claim with 2,000 blocked due rows: %v", best)
	if best > 250*time.Millisecond {
		t.Fatalf("claim took %v with a blocked backlog; want milliseconds", best)
	}
}

// From the independent review of the outbox. A page delivered just as
// shutdown begins is recorded (not left leased, to be sent again).
func TestNotifySuccessAtShutdownIsRecorded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var sends atomic.Int32
	h := setupNotify(t, Config{NotifyWorkers: 1, NotifyHTTPClient: &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		sends.Add(1)
		resp := okResponse(r)
		cancel() // SIGTERM arrives right after Slack accepted the page
		return resp, nil
	})}})
	org, svc := h.org()
	inc := h.incident(org, svc)
	tgt := h.target(org, svc, "slack", "https://hooks.slack.com/services/T/B/x", nil)
	page := h.notify(org, inc, tgt, "page")
	h.notify(org, inc, tgt, "resolve")
	h.s.DeliverNotifications(ctx)
	if got := h.row(org, page); got.Status != "sent" {
		t.Fatalf("a page delivered during shutdown was left %+v", got)
	}
	if n := sends.Load(); n != 1 {
		t.Fatalf("sends during shutdown: %d (nothing new should be claimed)", n)
	}
	h.deliver() // the resolve goes next, and the page isn't repeated
	if n := sends.Load(); n != 2 {
		t.Fatalf("sends after restart: %d, want 2 (page once, then resolve)", n)
	}
}

// One org with as many hanging destinations as there are workers can't
// delay another org's page.
func TestNotifyOneOrgCannotTakeEveryWorker(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hang.Close)
	t.Cleanup(func() { close(release) })
	arrived := make(chan time.Time, 1)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- time.Now():
		default:
		}
	}))
	t.Cleanup(fast.Close)

	h := setupNotify(t, Config{AllowPrivateTargets: true}) // 8 workers
	a, asvc := h.org()
	tgt := h.target(a, asvc, "slack", hang.URL+"/hook", nil)
	for range 8 {
		h.notify(a, h.incident(a, asvc), tgt, "page")
	}
	time.Sleep(10 * time.Millisecond) // org B's page sorts after org A's
	b, bsvc := h.org()
	h.notify(b, h.incident(b, bsvc), h.target(b, bsvc, "slack", fast.URL+"/hook", nil), "page")

	start := time.Now()
	go h.s.DeliverNotifications(context.Background())
	select {
	case at := <-arrived:
		if lag := at.Sub(start); lag > time.Second {
			t.Fatalf("org A's hanging destinations delayed org B's page by %v", lag)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("org B's page never arrived")
	}
}

// A page held back by HTTP 429 (which doesn't use up attempts) still stops
// once its incident is resolved and the page is old.
func TestNotifyThrottledPageStopsForResolvedIncident(t *testing.T) {
	var throttle atomic.Bool
	throttle.Store(true)
	pd := &pdRecorder{status: func(string) int {
		if throttle.Load() {
			return 429
		}
		return 200
	}}
	srv := httptest.NewServer(pd)
	t.Cleanup(srv.Close)
	h := setupNotify(t, Config{AllowPrivateTargets: true})
	org, svc := h.org()
	inc := h.incident(org, svc)
	tgt := h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": srv.URL})
	page := h.notify(org, inc, tgt, "page")
	for range 5 {
		h.deliver()
		h.due(org)
	}
	before := len(pd.got())
	h.exec(org, `UPDATE incidents SET status = 'resolved', resolved_at = now() WHERE id = $1`, inc)
	h.exec(org, `UPDATE notifications SET created_at = now() - interval '3 hours'`)
	throttle.Store(false)
	h.due(org)
	h.deliver()
	if got := h.row(org, page); got.Status != "failed" || len(pd.got()) != before {
		t.Fatalf("page for an incident resolved hours ago: %+v; PagerDuty got %d new events", got, len(pd.got())-before)
	}
}

// A worker whose lease ran out (stalled between claim and send) can't load
// the row, so it can't send after another worker has taken it over.
func TestNotifyStaleClaimIsNotLoaded(t *testing.T) {
	h := setupNotify(t, Config{AllowPrivateTargets: true, NotifyWorkers: 1})
	org, svc := h.org()
	inc := h.incident(org, svc)
	tgt := h.target(org, svc, "pagerduty", "rk", map[string]string{"events_url": "https://events.pagerduty.com/v2/enqueue"})
	page := h.notify(org, inc, tgt, "page")
	stale := ids.NewString()
	var id string
	if err := h.s.DB.QueryRow(`SELECT id FROM nfx_claim_notification('1 minute', $1, 100)`, stale).Scan(&id); err != nil || id != page {
		t.Fatal(err)
	}
	// Too little lease left to start a request.
	h.exec(org, `UPDATE notifications SET lease_until = now() + interval '3 seconds' WHERE id = $1`, page)
	if j, err := h.s.loadNotification(context.Background(), org, page, stale); err != nil || j != nil {
		t.Fatalf("loaded a claim with no time left to send: %v %v", j, err)
	}
}

func TestNotifyAddrAllowedRefusesEmbeddedIPv4(t *testing.T) {
	for _, s := range []string{"::a9fe:a9fe", "::7f00:1", "::a00:1", "::ffff:0:a9fe:a9fe", "fec0::1"} {
		if notifyAddrAllowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed %s", s)
		}
	}
}
