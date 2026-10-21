package e2e_test

// Regression tests for alert ingest and incident handling found in QA review:
// events that used to stall processing for every org, a reopen that collided
// with a newer incident, out-of-order PagerDuty delivery, and alerts that went
// quiet after a human resolve.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

type ingestHarness struct {
	t      *testing.T
	srv    *controlplane.Server
	api    string
	ingest string
	key    string
	secret string
	pdMu   sync.Mutex
	pd     []string
	pdFail int

	orgID   string // the org's UUID
	ingBase string // the ingest listener's URL
	stub    *devstub.Stub
}

func setupIngest(t *testing.T, svc map[string]any) *ingestHarness {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, err := controlplane.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	x := &ingestHarness{t: t}
	pdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		x.pdMu.Lock()
		defer x.pdMu.Unlock()
		a := fmt.Sprint(ev["event_action"])
		if r.URL.Path == "/slack" {
			return
		}
		if a == "trigger" && x.pdFail > 0 {
			x.pdFail--
			x.pd = append(x.pd, a+"(500)")
			w.WriteHeader(500)
			return
		}
		x.pd = append(x.pd, a)
	}))
	t.Cleanup(pdSrv.Close)
	// devstub signs SNS notifications for CloudWatch integrations.
	x.stub = devstub.New(time.Second)
	stubSrv := httptest.NewServer(x.stub.Handler())
	t.Cleanup(stubSrv.Close)
	x.stub.BaseURL = stubSrv.URL
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	x.srv = controlplane.New(pool, sealer, ca, controlplane.Config{PublicIngestURL: "http://ingest",
		SNSCertURLPrefixes: []string{stubSrv.URL + "/sns/"}, AllowPrivateTargets: true}, log)
	apiSrv := httptest.NewServer(x.srv.APIHandler())
	t.Cleanup(apiSrv.Close)
	ingSrv := httptest.NewServer(x.srv.IngestHandler())
	t.Cleanup(ingSrv.Close)
	x.api, x.ingBase = apiSrv.URL, ingSrv.URL
	org, err := x.srv.CreateOrg(context.Background(), "Acme", "acme"+fmt.Sprint(time.Now().UnixNano()%100000))
	if err != nil {
		t.Fatal(err)
	}
	x.key, x.orgID = org.APIKey, org.OrgID
	if svc == nil {
		svc = map[string]any{}
	}
	svc["name"] = "checkout-api"
	x.call("POST", "/v1/services", svc, nil)
	x.call("POST", "/v1/services/checkout-api/escalation-targets", map[string]any{"type": "pagerduty", "routing_key": "k", "events_url": pdSrv.URL + "/pd"}, nil)
	var integ map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "wh", "default_service": "checkout-api"}, &integ)
	x.ingest = strings.Replace(integ["ingest_url"], "http://ingest", ingSrv.URL, 1)
	x.secret = integ["signing_secret"]
	return x
}

func (x *ingestHarness) call(method, path string, body, out any) int {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, x.api+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+x.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		x.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, rb)
	}
	if out != nil {
		json.Unmarshal(rb, out)
	}
	return resp.StatusCode
}

func (x *ingestHarness) send(body map[string]any) int {
	return x.sendTo(x.ingest, x.secret, body)
}

// sendTo posts a signed webhook alert to an integration's ingest URL.
func (x *ingestHarness) sendTo(ingest, secret string, body map[string]any) int {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ingest, bytes.NewReader(b))
	req.Header.Set(controlplane.WebhookSignatureHeader, controlplane.SignWebhook(secret, b, time.Now()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (x *ingestHarness) incidents() []map[string]any {
	var out []map[string]any
	x.call("GET", "/v1/incidents", nil, &out)
	return out
}

func (x *ingestHarness) tick() {
	x.t.Helper()
	if err := x.srv.Tick(context.Background()); err != nil {
		x.t.Fatalf("tick: %v", err)
	}
}

func (x *ingestHarness) statuses() map[float64]string {
	out := map[float64]string{}
	for _, i := range x.incidents() {
		out[i["number"].(float64)] = fmt.Sprint(i["status"])
	}
	return out
}

func TestIngestUnstorableTextDoesNotStallProcessing(t *testing.T) {
	x := setupIngest(t, nil)
	// 299 ASCII bytes then a 2-byte rune: the old byte-wise truncate split it.
	if code := x.send(map[string]any{"dedup_key": "bad", "summary": strings.Repeat("a", 299) + "é"}); code != 202 {
		t.Fatalf("ingest returned %d", code)
	}
	x.send(map[string]any{"dedup_key": "nul", "summary": "x\x00y", "labels": map[string]string{"a": "\x00"}})
	x.send(map[string]any{"dedup_key": "good", "summary": "fine"})
	x.tick()
	x.tick()
	// All three are storable now; one open incident per service by default.
	if got := len(x.incidents()); got != 1 {
		t.Fatalf("got %d incidents, want 1", got)
	}
}

func TestIngestReopenDoesNotCollideWithNewerIncident(t *testing.T) {
	x := setupIngest(t, nil)
	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick()
	x.send(map[string]any{"dedup_key": "A", "summary": "A down", "status": "resolved"})
	x.tick()
	x.send(map[string]any{"dedup_key": "B", "summary": "B down"})
	x.tick()
	x.send(map[string]any{"dedup_key": "A", "summary": "A down again"})
	x.tick() // used to fail with a duplicate key on incidents_open_group, forever
	x.send(map[string]any{"dedup_key": "B", "summary": "B down", "status": "resolved"})
	x.send(map[string]any{"dedup_key": "A", "summary": "A down", "status": "resolved"})
	x.tick()
	x.tick()
	st := x.statuses()
	if len(st) != 2 || st[1] != "resolved" || st[2] != "resolved" {
		t.Fatalf("incidents %v; want #1 and #2 both resolved (A joined #2)", st)
	}
}

func TestIngestPagerDutyResolveNeverOvertakesPage(t *testing.T) {
	x := setupIngest(t, nil)
	x.pdFail = 1
	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick()
	x.send(map[string]any{"dedup_key": "A", "summary": "A down", "status": "resolved"})
	x.tick()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		x.tick()
		x.pdMu.Lock()
		n := len(x.pd)
		x.pdMu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	x.pdMu.Lock()
	defer x.pdMu.Unlock()
	if strings.Join(x.pd, ",") != "trigger(500),trigger,resolve" {
		t.Fatalf("PagerDuty saw %v; the resolve must come after the retried trigger", x.pd)
	}
}

func TestIngestAlertStillFiringAfterHumanResolveOpensNewIncident(t *testing.T) {
	x := setupIngest(t, nil)
	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick()
	x.call("POST", "/v1/incidents/1/resolve", nil, nil)
	x.send(map[string]any{"dedup_key": "A", "summary": "A still down"})
	x.tick()
	st := x.statuses()
	if st[1] != "resolved" || st[2] != "triggered" {
		t.Fatalf("incidents %v; want #1 resolved and a new #2 triggered", st)
	}
}

func TestIngestCloudWatchRequiresTopic(t *testing.T) {
	x := setupIngest(t, nil)
	if code := x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "checkout-api"}, nil); code != 400 {
		t.Fatalf("cloudwatch integration without topic_arn: got %d, want 400", code)
	}
	if code := x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "checkout-api",
		"topic_arn": "arn:aws:sns:us-east-1:123456789012:alarms"}, nil); code/100 != 2 {
		t.Fatalf("cloudwatch integration with topic_arn: got %d", code)
	}
}

// While a page backs off, the notifications queued behind it for the same
// destination move back with it, so they aren't re-checked on every claim.
func TestIngestBlockedNotificationsFollowTheHeadsBackoff(t *testing.T) {
	x := setupIngest(t, nil)
	x.pdFail = 2
	x.send(map[string]any{"dedup_key": "A", "summary": "A down"})
	x.tick() // page fails once
	x.send(map[string]any{"dedup_key": "A", "summary": "A down", "status": "resolved"})
	x.tick() // resolve queued behind the backed-off page
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		x.tick()
		x.pdMu.Lock()
		n := len(x.pd)
		x.pdMu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	var pageNext, resolveNext time.Time
	err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		if err := tx.QueryRow(`SELECT next_attempt_at FROM notifications WHERE kind = 'page' AND status = 'pending'`).Scan(&pageNext); err != nil {
			return err
		}
		return tx.QueryRow(`SELECT next_attempt_at FROM notifications WHERE kind = 'resolve' AND status = 'pending'`).Scan(&resolveNext)
	})
	if err != nil {
		t.Fatalf("expected a pending page and resolve after two failures: %v", err)
	}
	if resolveNext.Before(pageNext) {
		t.Fatalf("resolve is due at %v, before the page it waits for (%v)", resolveNext, pageNext)
	}
}

// A CloudWatch integration with no pinned topic (created before topic_arn
// was required) can be fixed in place instead of recreated.
func TestIngestTopicCanBePinnedOnExistingIntegration(t *testing.T) {
	x := setupIngest(t, nil)
	var integ map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "checkout-api",
		"topic_arn": "arn:aws:sns:us-east-1:123456789012:old"}, &integ)
	clear := func() {
		t.Helper()
		err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
			_, err := tx.Exec(`UPDATE integrations SET config = '{}' WHERE type = 'cloudwatch'`)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	clear() // what a legacy integration looks like
	topic := "arn:aws:sns:us-east-1:123456789012:alarms"
	if code := x.call("PUT", "/v1/integrations/"+integ["id"]+"/topic", map[string]string{"topic_arn": topic}, nil); code != 200 {
		t.Fatalf("pin topic: got %d", code)
	}
	var got string
	x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT config->>'topic_arn' FROM integrations WHERE type = 'cloudwatch'`).Scan(&got)
	})
	if got != topic {
		t.Fatalf("topic_arn is %q, want %q", got, topic)
	}
	if code := x.call("PUT", "/v1/integrations/"+integ["id"]+"/topic", map[string]string{"topic_arn": "not-an-arn"}, nil); code != 400 {
		t.Fatalf("invalid topic: got %d, want 400", code)
	}
}

// GET /v1/integrations shows an unpinned CloudWatch integration as a
// problem, and the last correctly signed delivery it refused for its topic.
func TestIntegrationsListShowsTopicProblems(t *testing.T) {
	x := setupIngest(t, nil)
	var integ map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "checkout-api",
		"topic_arn": "arn:aws:sns:us-east-1:123456789012:alarms"}, &integ)
	find := func() map[string]any {
		t.Helper()
		var list []map[string]any
		if code := x.call("GET", "/v1/integrations", nil, &list); code != 200 {
			t.Fatalf("list: %d", code)
		}
		for _, it := range list {
			if it["id"] == integ["id"] {
				return it
			}
		}
		t.Fatalf("integration %s not listed: %v", integ["id"], list)
		return nil
	}
	if it := find(); it["topic_arn"] != "arn:aws:sns:us-east-1:123456789012:alarms" || it["problem"] != nil {
		t.Fatalf("pinned integration: %v", it)
	}

	// A delivery from another topic is refused and recorded.
	url := strings.Replace(integ["ingest_url"], "http://ingest", x.ingBase, 1)
	other := "arn:aws:sns:us-east-1:123456789012:someone-elses"
	resp, err := http.Post(url, "text/plain", bytes.NewReader(x.stub.SNSEnvelope(other, devstub.CloudWatchAlarm("a", "ALARM", "prod", "checkout-api"))))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("delivery from another topic: %d", resp.StatusCode)
	}
	if it := find(); it["last_rejected_topic"] != other || it["last_rejected_at"] == "" {
		t.Fatalf("refused topic not recorded: %v", it)
	}

	// Legacy: no topic pinned.
	x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE integrations SET config = '{}' WHERE type = 'cloudwatch'`)
		return err
	})
	if it := find(); it["problem"] == nil {
		t.Fatalf("unpinned integration not flagged: %v", it)
	}
	// Pinning clears the problem.
	x.call("PUT", "/v1/integrations/"+integ["id"]+"/topic", map[string]string{"topic_arn": other}, nil)
	if it := find(); it["problem"] != nil || it["topic_arn"] != other {
		t.Fatalf("after pinning: %v", it)
	}
}

// An event that can't be processed is stored with its error, not retried,
// and admins can see it.
func TestFailedAlertEventsAreListed(t *testing.T) {
	x := setupIngest(t, nil)
	if code := x.send(map[string]any{"status": "exploding"}); code != 202 {
		t.Fatalf("ingest: %d", code)
	}
	x.tick()
	var failed []map[string]any
	if code := x.call("GET", "/v1/alert-events/failed", nil, &failed); code != 200 {
		t.Fatalf("list: %d", code)
	}
	if len(failed) != 1 || failed[0]["error"] == "" || !strings.HasPrefix(fmt.Sprint(failed[0]["integration"]), "int_") {
		t.Fatalf("failed events: %v", failed)
	}
}
