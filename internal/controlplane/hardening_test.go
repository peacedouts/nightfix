package controlplane

// Regression tests for the QA follow-ups: webhook dedup keys scoped to their
// integration (and the migration that rewrote stored fingerprints),
// CloudWatch state ordering, and the email_verified claim.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/migrations"
)

func TestWebhookDedupKeyIsScopedToIntegration(t *testing.T) {
	a, b := ids.NewString(), ids.NewString()
	body := []byte(`{"dedup_key":"db-down","summary":"database down"}`)
	fa, err := normalizeWebhook(a, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := normalizeWebhook(b, body, nil)
	again, _ := normalizeWebhook(a, body, nil)
	if fa.Fingerprint != "wh:"+a+":db-down" || fa.Fingerprint == fb.Fingerprint || again.Fingerprint != fa.Fingerprint {
		t.Fatalf("fingerprints %q / %q / %q: want one per integration, stable", fa.Fingerprint, fb.Fingerprint, again.Fingerprint)
	}

	// Label-hash fingerprints already covered the integration: unchanged.
	keys := []string{"alertname", "service", "instance"}
	labels := map[string]string{"alertname": "HighCPU", "service": "api"}
	h := sha256.New()
	h.Write([]byte(a))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k + "=" + labels[k]))
	}
	lb, _ := json.Marshal(map[string]any{"summary": "cpu", "labels": labels})
	got, _ := normalizeWebhook(a, lb, keys)
	if want := "wh:" + hex.EncodeToString(h.Sum(nil)); got.Fingerprint != want {
		t.Fatalf("label-hash fingerprint changed: %q, want %q", got.Fingerprint, want)
	}
	if !got.StateAt.IsZero() {
		t.Fatal("webhooks carry no source time; StateAt must be zero")
	}
}

func TestCloudWatchFingerprintAndStateTime(t *testing.T) {
	const arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:x"
	msg := func(state, at string) string {
		return `{"AlarmName":"x","NewStateValue":"` + state + `","StateChangeTime":"` + at + `","AlarmArn":"` + arn + `"}`
	}
	a, err := normalizeCloudWatch("int1", msg("ALARM", "2026-10-21T02:14:03.120+0000"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != "cw:int1:"+arn {
		t.Fatalf("CloudWatch fingerprint changed: %q", a.Fingerprint)
	}
	if want := time.Date(2026, 10, 21, 2, 14, 3, 120e6, time.UTC); !a.StateAt.Equal(want) {
		t.Fatalf("StateAt %v, want %v", a.StateAt, want)
	}
	if bad, _ := normalizeCloudWatch("int1", msg("OK", "yesterday"), nil); !bad.StateAt.IsZero() {
		t.Fatal("an unparseable StateChangeTime must not be used for ordering")
	}

	at := func(d time.Duration) sql.NullTime { return sql.NullTime{Time: a.StateAt.Add(d), Valid: true} }
	for _, c := range []struct {
		alert   Alert
		applied sql.NullTime
		want    bool
	}{
		{a, sql.NullTime{}, false}, // nothing applied yet
		{a, at(-time.Second), false},
		{a, at(0), true}, // the same transition again
		{a, at(time.Minute), true},
		{Alert{}, at(time.Minute), false}, // no source time: processing order
	} {
		if got := staleState(c.alert, c.applied); got != c.want {
			t.Errorf("staleState(%v, %v) = %v, want %v", c.alert.StateAt, c.applied, got, c.want)
		}
	}
}

func TestEmailVerifiedClaim(t *testing.T) {
	custom := Auth0Config{EmailVerifiedClaim: "https://acme.example/ev"}
	for i, c := range []struct {
		cfg    Auth0Config
		claims auth0.Claims
		want   bool
	}{
		{Auth0Config{}, auth0.Claims{}, false},
		{Auth0Config{}, auth0.Claims{"email_verified": true}, true},
		{Auth0Config{}, auth0.Claims{"https://nightfix.dev/email_verified": true}, true},
		{Auth0Config{}, auth0.Claims{"email_verified": false}, false},
		{Auth0Config{}, auth0.Claims{"email_verified": false, "https://nightfix.dev/email_verified": true}, false},
		{Auth0Config{}, auth0.Claims{"email_verified": "true"}, false},
		{custom, auth0.Claims{"https://acme.example/ev": true}, true},
		{custom, auth0.Claims{"email_verified": true}, false}, // the configured claim replaces the default
	} {
		if got := c.cfg.emailVerified(c.claims); got != c.want {
			t.Errorf("case %d: emailVerified(%v) = %v, want %v", i, c.claims, got, c.want)
		}
	}
}

// The e2e tests cover body and path; no route takes two methods on one path,
// so the method comparison is checked here.
func TestIdempotencyKeyReusedWithAnotherMethod(t *testing.T) {
	s := &Server{}
	h := sha256.Sum256(nil)
	w := httptest.NewRecorder()
	s.replayIdempotent(w, httptest.NewRequest("POST", "/v1/teams", nil), principal{},
		idempotencyRecord{Method: "PUT", Path: "/v1/teams", BodyHash: h[:], Status: sql.NullInt64{Int64: 200, Valid: true}}, h[:])
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", w.Code)
	}
}

// Alerts stored before dedup keys were scoped keep resolving and reopening:
// migration 0015 rewrites them to exactly what the new code computes.
func TestWebhookFingerprintMigration(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	org := e.a.OrgID
	runID, _ := ids.Decode("run", e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n"))
	intA, intB, intCW := ids.NewString(), ids.NewString(), ids.NewString()
	keys := []string{"alertname", "service", "instance"}
	newFP := func(integ string, body map[string]any) string {
		b, _ := json.Marshal(body)
		a, err := normalizeWebhook(integ, b, keys)
		if err != nil {
			t.Fatal(err)
		}
		return a.Fingerprint
	}
	hexKey := strings.Repeat("ab", 32) // a dedup_key that looks like a label hash
	labels := map[string]string{"alertname": "HighCPU", "service": "api"}
	labelFP := newFP(intA, map[string]any{"summary": "x", "labels": labels})

	type row struct{ id, integ, fp, status, want string }
	rows := []row{
		{ids.NewString(), intA, "wh:db-down", "firing", newFP(intA, map[string]any{"dedup_key": "db-down", "summary": "x"})},
		{ids.NewString(), intB, "wh:db-down", "resolved", newFP(intB, map[string]any{"dedup_key": "db-down", "summary": "x"})},
		{ids.NewString(), intA, "wh:" + hexKey, "firing", newFP(intA, map[string]any{"dedup_key": hexKey, "summary": "x"})},
		{ids.NewString(), intA, labelFP, "firing", labelFP}, // label hash: unchanged
		{ids.NewString(), intB, "wh:" + intB + ":ok", "firing", "wh:" + intB + ":ok"},
		{ids.NewString(), intCW, "cw:arn:aws:cloudwatch:us-east-1:123456789012:alarm:x", "firing", "cw:arn:aws:cloudwatch:us-east-1:123456789012:alarm:x"},
	}
	err := e.s.DB.WithOrg(ctx, org, func(tx *db.Tx) error {
		var svc string
		if err := tx.QueryRow(`SELECT id FROM services WHERE is_catch_all`).Scan(&svc); err != nil {
			return err
		}
		for id, typ := range map[string]string{intA: "webhook", intB: "webhook", intCW: "cloudwatch"} {
			if _, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id) VALUES ($1,$2,$3,$3,$4)`, id, org, typ, svc); err != nil {
				return err
			}
		}
		for _, r := range rows {
			lb, _ := json.Marshal(map[string]string{})
			if r.fp == labelFP {
				lb, _ = json.Marshal(labels)
			}
			if _, err := tx.Exec(`INSERT INTO alerts (id, org_id, fingerprint, integration_id, service_id, status, severity, summary, source,
					labels, first_seen_at, last_seen_at, resolved_at)
				VALUES ($1,$2,$3,$4,$5,$6,'high','x','webhook',$7,now(),now(), CASE WHEN $6 = 'resolved' THEN now() END)`,
				r.id, org, r.fp, r.integ, svc, r.status, string(lb)); err != nil {
				return err
			}
		}
		// The flap guard counts verified auto-fixes by fingerprint: a run
		// tied to a rewritten alert moves with it.
		incID := ids.NewString()
		if _, err := tx.Exec(`INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
			VALUES ($1,$2,1,$3,'catch-all','triggered','high','x')`, incID, org, svc); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO incident_alerts (org_id, incident_id, alert_id) VALUES ($1,$2,$3)`, org, incID, rows[0].id); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE runbook_runs SET fingerprint = 'wh:db-down', incident_id = $2 WHERE id = $1`, runID, incID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	sqlText, err := migrations.FS.ReadFile("0015_webhook_dedup_key_scope.sql")
	if err != nil {
		t.Fatal(err)
	}
	admin := adminForPool(t, e.s.DB)
	for i := 0; i < 2; i++ { // idempotent
		if _, err := admin.ExecContext(ctx, string(sqlText)); err != nil {
			t.Fatalf("migration run %d: %v", i+1, err)
		}
	}

	e.s.DB.WithOrg(ctx, org, func(tx *db.Tx) error {
		for _, r := range rows {
			var fp string
			if err := tx.QueryRow(`SELECT fingerprint FROM alerts WHERE id = $1`, r.id).Scan(&fp); err != nil {
				t.Fatal(err)
			}
			if fp != r.want {
				t.Errorf("alert %s (%s): fingerprint %q, want %q", r.fp, r.status, fp, r.want)
			}
		}
		var runFP string
		tx.QueryRow(`SELECT fingerprint FROM runbook_runs WHERE id = $1`, runID).Scan(&runFP)
		if runFP != rows[0].want {
			t.Errorf("run fingerprint %q, want %q", runFP, rows[0].want)
		}
		return nil
	})
}

// adminForPool connects as the test admin to the pool's database.
func adminForPool(t *testing.T, pool *db.DB) *sql.DB {
	t.Helper()
	var name string
	if err := pool.QueryRowContext(context.Background(), `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	return admin
}
