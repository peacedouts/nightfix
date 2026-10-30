package e2e_test

// Out-of-order delivery: SNS and webhooks can deliver or commit events out
// of order, and the latest state must still win.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/ids"
)

// SNS doesn't guarantee delivery order, and CloudWatch stamps every state
// change (StateChangeTime), which processEvent uses so that an update older
// than the latest applied one never reopens or resolves anything. But an OK
// that arrives before its ALARM finds no alert, does nothing and records
// nothing, so the older ALARM then opens an alert (and pages) that stays
// firing forever: CloudWatch won't send another OK for an alarm that is
// already OK.
func TestCloudWatchOKDeliveredBeforeItsAlarm(t *testing.T) {
	x := setupIngest(t, nil)
	cw, _ := x.cloudwatch()
	t0 := time.Now().Add(-2 * time.Minute)
	for _, d := range []struct {
		id, state string
		at        time.Time
	}{{"ok-1", "OK", t0.Add(time.Minute)}, {"alarm-1", "ALARM", t0}} {
		if code, body := x.post(cw, x.alarm(d.id, time.Now(), d.state, d.at)); code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", d.id, code, body)
		}
		x.tick()
	}
	if n := x.count(`SELECT count(*) FROM alerts WHERE status = 'firing'`); n != 0 {
		t.Fatalf("the alarm went OK at %s, after the ALARM at %s, yet %d alert is firing (incidents %v); it will never resolve",
			t0.Add(time.Minute).Format(time.TimeOnly), t0.Format(time.TimeOnly), n, x.statuses())
	}
}

// Events are processed in received_at order, but received_at is the ingest
// transaction's start time, not its commit time. A firing event whose ingest
// transaction commits after a later resolved event has been processed is
// applied last, so the alert ends up firing forever. The open transaction
// below stands in for a slow ingest request (it inserts exactly what
// handleIngest inserts).
func TestWebhookEventCommittedLateIsAppliedOutOfOrder(t *testing.T) {
	x := setupIngest(t, nil)
	ctx := context.Background()
	var integID string
	tx, err := x.srv.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('app.org_id', $1, true)`, x.orgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT id FROM integrations WHERE type = 'webhook'`).Scan(&integID); err != nil {
		t.Fatal(err)
	}
	firing, _ := json.Marshal(map[string]any{"dedup_key": "A", "summary": "A down"})
	// What handleIngest does before storing an event (migration 0023).
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock_shared(hashtextextended('nfx_ingest:' || $1, 0))`, x.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,$4)`,
		ids.NewString(), x.orgID, integID, string(firing)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	// The source's next event, sent after the firing one, is accepted and
	// processed while the firing event's ingest is still committing.
	if code := x.send(map[string]any{"dedup_key": "A", "summary": "A ok", "status": "resolved"}); code != 202 {
		t.Fatalf("ingest: %d", code)
	}
	x.tick()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	x.tick()
	if n := x.count(`SELECT count(*) FROM alerts WHERE status = 'firing'`); n != 0 {
		t.Fatalf("the source sent firing then resolved, but %d alert is left firing (incidents %v)", n, x.statuses())
	}
}
