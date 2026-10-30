package e2e_test

// Regression tests for ingest: SNS replay and ordering,
// and webhook dedup keys scoped to their integration.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/ids"
)

const snsTopic = "arn:aws:sns:us-east-1:123456789012:alarms"

// cloudwatch creates a CloudWatch integration; returns its ingest URL and id.
func (x *ingestHarness) cloudwatch() (string, string) {
	x.t.Helper()
	var integ map[string]string
	if code := x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "checkout-api",
		"topic_arn": snsTopic}, &integ); code != 200 {
		x.t.Fatalf("create cloudwatch integration: %d", code)
	}
	id, err := ids.Decode("int", path.Base(integ["ingest_url"]))
	if err != nil {
		x.t.Fatal(err)
	}
	return strings.Replace(integ["ingest_url"], "http://ingest", x.ingBase, 1), id
}

func (x *ingestHarness) post(url string, body []byte) (int, string) {
	x.t.Helper()
	resp, err := http.Post(url, "text/plain; charset=UTF-8", bytes.NewReader(body))
	if err != nil {
		x.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// alarm builds a signed SNS notification, sent at sent, of a CloudWatch state
// change that happened at changed.
func (x *ingestHarness) alarm(msgID string, sent time.Time, state string, changed time.Time) []byte {
	m := devstub.CloudWatchAlarm("db-latency", state, "prod-east", "checkout-api")
	m["StateChangeTime"] = changed.UTC().Format("2006-01-02T15:04:05.000-0700")
	return x.stub.SNSEnvelopeAt(snsTopic, m, msgID, sent)
}

func (x *ingestHarness) count(query string, args ...any) int {
	x.t.Helper()
	var n int
	if err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		return tx.QueryRow(query, args...).Scan(&n)
	}); err != nil {
		x.t.Fatal(err)
	}
	return n
}

func TestIngestSNSReplayIsBounded(t *testing.T) {
	x := setupIngest(t, nil)
	cw, cwID := x.cloudwatch()
	now := time.Now()
	first := x.alarm("msg-1", now, "ALARM", now)

	if code, _ := x.post(cw, first); code != http.StatusAccepted {
		t.Fatalf("first delivery: %d", code)
	}
	// SNS retries (or anyone replays) the same MessageId: acknowledged so
	// SNS stops, and stored nowhere.
	if code, body := x.post(cw, first); code != http.StatusOK || !strings.Contains(body, "duplicate") {
		t.Fatalf("replayed MessageId: %d %s", code, body)
	}
	// Validly signed, but sent two hours ago: refused.
	if code, body := x.post(cw, x.alarm("msg-old", now.Add(-2*time.Hour), "ALARM", now)); code != http.StatusUnauthorized || !strings.Contains(body, "older than") {
		t.Fatalf("stale notification: %d %s", code, body)
	}
	// SNS retries for a while, so a late but in-window delivery is accepted.
	if code, _ := x.post(cw, x.alarm("msg-late", now.Add(-50*time.Minute), "ALARM", now)); code != http.StatusAccepted {
		t.Fatalf("late delivery within the window: %d", code)
	}
	// MessageIds are per integration.
	cw2, _ := x.cloudwatch()
	if code, _ := x.post(cw2, first); code != http.StatusAccepted {
		t.Fatalf("same MessageId on another integration: %d", code)
	}
	if n := x.count(`SELECT count(*) FROM alert_events`); n != 3 {
		t.Fatalf("stored %d events, want 3 (first, late, other integration)", n)
	}

	// Subscription confirmation still works.
	if code, body := x.post(cw, x.stub.SNSSubscriptionConfirmation(snsTopic, now)); code != http.StatusOK {
		t.Fatalf("subscription confirmation: %d %s", code, body)
	}
	if n := x.count(`SELECT count(*) FROM audit_events WHERE action = 'integration.sns_subscribed'`); n != 1 {
		t.Fatalf("subscription not confirmed (%d audit events)", n)
	}

	// Expired MessageIds are cleaned up by the worker; live ones stay.
	if err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO ingest_message_ids (org_id, integration_id, message_id, expires_at) VALUES ($1,$2,'gone', now() - interval '1 second')`, x.orgID, cwID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var expired int
	if err := x.srv.DB.QueryRow(`SELECT nfx_expire_ingest_message_ids()`).Scan(&expired); err != nil || expired != 1 {
		t.Fatalf("expired %d message ids (%v), want 1", expired, err)
	}
	if code, _ := x.post(cw, first); code != http.StatusOK {
		t.Fatalf("a live MessageId was cleaned up: replay got %d", code)
	}
}

func TestIngestCloudWatchStateNeverRegresses(t *testing.T) {
	x := setupIngest(t, map[string]any{"reopen_window": "2s"})
	cw, _ := x.cloudwatch()
	t0 := time.Now().Add(-10 * time.Minute)
	deliver := func(msgID, state string, changed time.Time) {
		t.Helper()
		if code, body := x.post(cw, x.alarm(msgID, time.Now(), state, changed)); code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", msgID, code, body)
		}
		x.tick()
	}
	expect := func(when string, want map[float64]string) {
		t.Helper()
		got := x.statuses()
		if len(got) != len(want) {
			t.Fatalf("%s: incidents %v, want %v", when, got, want)
		}
		for n, st := range want {
			if got[n] != st {
				t.Fatalf("%s: incidents %v, want %v", when, got, want)
			}
		}
	}

	deliver("alarm-1", "ALARM", t0)
	deliver("ok-1", "OK", t0.Add(time.Minute))
	expect("after ALARM then OK", map[float64]string{1: "resolved"})

	// The ALARM delivered again after the OK (under a new MessageId, so the
	// dedupe doesn't catch it) is older than the OK: it must not reopen.
	deliver("alarm-1-again", "ALARM", t0)
	expect("stale ALARM within the reopen window", map[float64]string{1: "resolved"})
	// Nor open a new incident once the reopen window has passed.
	time.Sleep(2500 * time.Millisecond)
	deliver("alarm-1-late", "ALARM", t0)
	expect("stale ALARM after the reopen window", map[float64]string{1: "resolved"})

	// A genuinely new ALARM does open one, and the old OK arriving now must
	// not resolve it.
	deliver("alarm-2", "ALARM", t0.Add(2*time.Minute))
	expect("new ALARM", map[float64]string{1: "resolved", 2: "triggered"})
	deliver("ok-1-again", "OK", t0.Add(time.Minute))
	expect("stale OK", map[float64]string{1: "resolved", 2: "triggered"})
	deliver("ok-2", "OK", t0.Add(3*time.Minute))
	expect("new OK", map[float64]string{1: "resolved", 2: "resolved"})
}

func TestIngestWebhookDedupKeysAreScopedToIntegration(t *testing.T) {
	x := setupIngest(t, nil)
	var other map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "webhook", "name": "another tool", "default_service": "checkout-api"}, &other)
	otherURL, otherSecret := strings.Replace(other["ingest_url"], "http://ingest", x.ingBase, 1), other["signing_secret"]

	x.send(map[string]any{"dedup_key": "db-down", "summary": "primary DB down"})
	x.tick()
	// Another tool resolving its own "db-down" must not resolve this one.
	x.sendTo(otherURL, otherSecret, map[string]any{"dedup_key": "db-down", "summary": "replica fine", "status": "resolved"})
	x.tick()
	if st := x.statuses(); st[1] != "triggered" {
		t.Fatalf("another integration's resolve touched this alert: %v", st)
	}
	// Each integration's alert has its own lifecycle within the incident.
	x.sendTo(otherURL, otherSecret, map[string]any{"dedup_key": "db-down", "summary": "replica down"})
	x.tick()
	x.send(map[string]any{"dedup_key": "db-down", "summary": "primary DB back", "status": "resolved"})
	x.tick()
	if st := x.statuses(); len(st) != 1 || st[1] != "triggered" {
		t.Fatalf("incident should stay open while the other tool's alert fires: %v", st)
	}
	if n := x.count(`SELECT count(*) FROM alerts`); n != 2 {
		t.Fatalf("got %d alerts, want one per integration", n)
	}
	x.sendTo(otherURL, otherSecret, map[string]any{"dedup_key": "db-down", "summary": "replica back", "status": "resolved"})
	x.tick()
	if st := x.statuses(); st[1] != "resolved" {
		t.Fatalf("incident should resolve once both alerts clear: %v", st)
	}
}
