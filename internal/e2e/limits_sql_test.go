package e2e_test

// Limits review (shared-service capacity): queries on hot paths whose cost
// grows with one org's backlog or history. Each test builds a realistic
// volume directly in the database, then times the query the workers run.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// ownerConn is a dedicated admin connection acting as nfx_owner, which sees
// every org (tenant_owner policy), for building test volume.
func ownerConn(t *testing.T, app *db.DB) *sql.Conn {
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
	t.Cleanup(func() { a.Close() })
	c, err := a.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	mustExec(t, c, `SET ROLE nfx_owner`)
	return c
}

func mustExec(t *testing.T, c interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, q string, args ...any) {
	t.Helper()
	if _, err := c.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// One org's backlog of unprocessed alert events (an alarm storm, or an
// integration posting in a loop) while one of its events is being processed:
// every other worker's claim walks that backlog before reaching anyone
// else's event, so the claim gets slower with the size of one tenant's
// backlog, for every tenant.
func TestLimitsAlertClaimCostGrowsWithOneOrgsBacklog(t *testing.T) {
	knownLimit(t) // measurement of a known limit (deploy/README.md "Known gaps"); not a CI check
	pool := testdb.New(t)
	ctx := context.Background()
	noisy := testdb.CreateOrg(t, pool, "noisy")
	quiet := testdb.CreateOrg(t, pool, "quiet")
	own := ownerConn(t, pool)
	took := map[int]time.Duration{}
	for _, n := range []int{10_000, 100_000} {
		mustExec(t, own, `TRUNCATE alert_events`)
		mustExec(t, own, `INSERT INTO alert_events (id, org_id, integration_id, raw, received_at)
			SELECT gen_random_uuid(), $1, gen_random_uuid(), '{}', now() - interval '30 minutes' + i * interval '1 millisecond'
			FROM generate_series(1, $2) i`, noisy, n)
		mustExec(t, own, `INSERT INTO alert_events (id, org_id, integration_id, raw, received_at) VALUES (gen_random_uuid(), $1, gen_random_uuid(), '{}', now())`, quiet)
		mustExec(t, own, `ANALYZE alert_events`)

		// Worker 1 is processing the noisy org's oldest event.
		tx1, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var org1, id1 string
		if err := tx1.QueryRow(`SELECT org_id, id FROM nfx_claim_alert_event()`).Scan(&org1, &id1); err != nil || org1 != noisy {
			t.Fatalf("first claim: org %s err %v", org1, err)
		}
		// Worker 2 claims the next event: the quiet org's.
		best := time.Hour
		for range 3 {
			tx2, err := pool.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var org2, id2 string
			start := time.Now()
			err = tx2.QueryRow(`SELECT org_id, id FROM nfx_claim_alert_event()`).Scan(&org2, &id2)
			d := time.Since(start)
			tx2.Rollback()
			if err != nil || org2 != quiet {
				t.Fatalf("second claim: org %s err %v", org2, err)
			}
			best = min(best, d)
		}
		tx1.Rollback()
		took[n] = best
		t.Logf("noisy backlog %7d events: a claim for the quiet org's event took %v", n, best.Round(time.Millisecond))
	}
	if took[100_000] > 100*time.Millisecond {
		t.Errorf("claiming another org's event costs %v with one org's 100k-event backlog (%v at 10k): the claim walks the backlog, "+
			"and each worker runs it once per event", took[100_000].Round(time.Millisecond), took[10_000].Round(time.Millisecond))
	}
}

// A storm of distinct alerts in one org, each opening its own incident and
// paging (grouping by host), leaves a big pending outbox. The org is capped
// at NotifyWorkers/4 in flight, but every claim by every worker still
// evaluates and sorts the whole pending set: ORDER BY kind, next_attempt_at
// has no index, and the per-org in-flight count runs per candidate row.
func TestLimitsNotificationClaimCostGrowsWithOneOrgsPendingBacklog(t *testing.T) {
	knownLimit(t) // measurement of a known limit (deploy/README.md "Known gaps"); not a CI check
	pool := testdb.New(t)
	ctx := context.Background()
	noisy := testdb.CreateOrg(t, pool, "noisy")
	quiet := testdb.CreateOrg(t, pool, "quiet")
	own := ownerConn(t, pool)
	for _, org := range []string{noisy, quiet} {
		mustExec(t, own, `INSERT INTO services (id, org_id, name) VALUES (gen_random_uuid(), $1, 'web')`, org)
		mustExec(t, own, `INSERT INTO escalation_targets (id, org_id, service_id, type, credential)
			SELECT gen_random_uuid(), $1, id, 'pagerduty', '\x00' FROM services WHERE org_id = $1`, org)
	}
	addPages := func(org string, from, n int) {
		mustExec(t, own, `INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
			SELECT gen_random_uuid(), $1, i, s.id, 'web/h' || i, 'triggered', 'high', 'host down'
			FROM generate_series($2::int, $3::int) i, services s WHERE s.org_id = $1`, org, from, from+n-1)
		mustExec(t, own, `INSERT INTO notifications (id, org_id, incident_id, target_id, kind, payload, next_attempt_at)
			SELECT gen_random_uuid(), $1, i.id, t.id, 'page', '{}', now() - interval '1 minute'
			FROM incidents i, escalation_targets t WHERE i.org_id = $1 AND t.org_id = $1 AND i.number BETWEEN $2 AND $3`, org, from, from+n-1)
	}
	addPages(quiet, 1, 1)
	took := map[int]time.Duration{}
	have := 0
	for _, n := range []int{5_000, 50_000} {
		addPages(noisy, have+1, n-have)
		have = n
		mustExec(t, own, `UPDATE notifications SET lease_until = NULL, lease_id = NULL`)
		mustExec(t, own, `ANALYZE notifications`)
		// The noisy org has its 2 (NotifyWorkers/4) pages in flight.
		mustExec(t, own, `UPDATE notifications SET lease_until = now() + interval '1 minute', lease_id = gen_random_uuid()
			WHERE id IN (SELECT id FROM notifications WHERE org_id = $1 LIMIT 2)`, noisy)
		best := time.Hour
		for range 3 {
			tx, err := pool.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var org, id string
			start := time.Now()
			err = tx.QueryRow(`SELECT org_id, id FROM nfx_claim_notification('1 minute', gen_random_uuid(), 2)`).Scan(&org, &id)
			d := time.Since(start)
			tx.Rollback()
			if err != nil || org != quiet {
				t.Fatalf("claim: org %s err %v", org, err)
			}
			best = min(best, d)
		}
		took[n] = best
		t.Logf("noisy org with %6d pending pages: claiming the quiet org's page took %v", n, best.Round(time.Millisecond))
	}
	if took[50_000] > 100*time.Millisecond {
		t.Errorf("a notification claim costs %v with one org's 50k pending pages (%v at 5k); every worker on every instance runs it per notification",
			took[50_000].Round(time.Millisecond), took[5_000].Round(time.Millisecond))
	}
}

// incident_alerts has no index on alert_id. The reopen lookup (a re-fire
// within the reopen window) and the resolve/repeat-firing lookups filter on
// alert_id, so they scan the org's whole incident_alerts history.
func TestLimitsIncidentAlertsLookupByAlertScansHistory(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	org := testdb.CreateOrg(t, pool, "acme")
	own := ownerConn(t, pool)
	mustExec(t, own, `INSERT INTO services (id, org_id, name) VALUES (gen_random_uuid(), $1, 'web')`, org)
	mustExec(t, own, `INSERT INTO integrations (id, org_id, type, name, default_service_id)
		SELECT gen_random_uuid(), $1, 'webhook', 'wh', id FROM services WHERE org_id = $1`, org)
	took := map[int]time.Duration{}
	have := 0
	for _, n := range []int{2_000, 200_000} {
		// A year of history: n resolved incidents, one alert each.
		mustExec(t, own, `INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title, resolved_at, resolution)
			SELECT gen_random_uuid(), $1, i, s.id, 'g#' || i, 'resolved', 'high', 't', now() - interval '1 day', 'alerts_resolved'
			FROM generate_series($2::int, $3::int) i, services s WHERE s.org_id = $1`, org, have+1, n)
		mustExec(t, own, `INSERT INTO alerts (id, org_id, fingerprint, integration_id, service_id, status, severity, summary, source,
				first_seen_at, last_seen_at, resolved_at)
			SELECT gen_random_uuid(), $1, 'wh:fp' || i, g.id, s.id, 'resolved', 'high', 's', 'webhook', now() - interval '1 day', now(), now() - interval '1 day'
			FROM generate_series($2::int, $3::int) i, services s, integrations g WHERE s.org_id = $1 AND g.org_id = $1`, org, have+1, n)
		mustExec(t, own, `INSERT INTO incident_alerts (org_id, incident_id, alert_id)
			SELECT $1, i.id, a.id FROM incidents i JOIN alerts a ON a.org_id = i.org_id AND a.fingerprint = 'wh:fp' || i.number
			WHERE i.org_id = $1 AND i.number BETWEEN $2 AND $3`, org, have+1, n)
		have = n
		mustExec(t, own, `ANALYZE incidents; ANALYZE alerts; ANALYZE incident_alerts`)
		// The reopen lookup from alertFiring, for an alert that just resolved.
		var alertID string
		if err := own.QueryRowContext(ctx, `SELECT id FROM alerts WHERE org_id = $1 AND fingerprint = 'wh:fp1'`, org).Scan(&alertID); err != nil {
			t.Fatal(err)
		}
		mustExec(t, own, `UPDATE alerts SET resolved_at = now() WHERE id = $1`, alertID)
		best := time.Hour
		var plan string
		for range 3 {
			err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
				start := time.Now()
				var id string
				var inc sql.NullString
				var st sql.NullTime
				err := tx.QueryRow(`
					SELECT a.id, ia.incident_id, a.state_at FROM alerts a
					LEFT JOIN LATERAL (
						SELECT incident_id FROM incident_alerts WHERE alert_id = a.id ORDER BY attached_at DESC LIMIT 1
					) ia ON true
					WHERE a.fingerprint = $1 AND a.status = 'resolved' AND a.resolved_at > now() - $2::interval
					ORDER BY a.resolved_at DESC LIMIT 1 FOR UPDATE OF a`, "wh:fp1", "15 minutes").Scan(&id, &inc, &st)
				best = min(best, time.Since(start))
				if err != nil {
					return err
				}
				rows, err := tx.Query(`EXPLAIN (ANALYZE, COSTS OFF) SELECT incident_id FROM incident_alerts WHERE alert_id = $1 ORDER BY attached_at DESC LIMIT 1`, alertID)
				if err != nil {
					return err
				}
				defer rows.Close()
				plan = ""
				for rows.Next() {
					var l string
					rows.Scan(&l)
					plan += "\n    " + l
				}
				return rows.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		took[n] = best
		t.Logf("%6d incident_alerts rows: reopen lookup took %v; plan of the alert_id lookup:%s", n, best.Round(10*time.Microsecond), plan)
		// The lookups every repeat firing (alertFiring) and every resolve
		// (alertResolved) run.
		for _, q := range []string{
			`SELECT EXISTS (SELECT 1 FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id
				WHERE ia.alert_id = $1 AND ia.detached_at IS NULL AND i.status <> 'resolved')::text`,
			`SELECT coalesce((SELECT ia.incident_id::text FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id
				WHERE ia.alert_id = $1 AND ia.detached_at IS NULL AND i.status <> 'resolved'), '')`,
		} {
			qbest := time.Hour
			for range 3 {
				pool.WithOrg(ctx, org, func(tx *db.Tx) error {
					start := time.Now()
					var s string
					err := tx.QueryRow(q, alertID).Scan(&s)
					qbest = min(qbest, time.Since(start))
					return err
				})
			}
			t.Logf("%6d incident_alerts rows: %.60s… took %v", n, strings.Join(strings.Fields(q), " "), qbest.Round(10*time.Microsecond))
		}
	}
	if took[200_000] > 5*time.Millisecond {
		t.Errorf("the reopen lookup costs %v at 200k incident_alerts rows vs %v at 2k: it scans the org's history (no index on alert_id)",
			took[200_000].Round(time.Millisecond), took[2_000].Round(time.Microsecond))
	}
}

// POST /agent/v1/enroll/challenge is unauthenticated (it needs only an org
// id) and unthrottled. Each call inserts a challenge that lives 5 minutes and
// first deletes expired ones with a sequential scan (enrollment_challenges
// has no index on expires_at), so the per-call cost grows with the call rate.
func TestLimitsEnrollChallengeCostGrowsWithCallRate(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	org := testdb.CreateOrg(t, pool, "acme")
	own := ownerConn(t, pool)
	took := map[int]time.Duration{}
	for _, n := range []int{1_000, 150_000} { // 5 minutes at ~3/s and at 500/s
		mustExec(t, own, `TRUNCATE enrollment_challenges`)
		mustExec(t, own, `INSERT INTO enrollment_challenges (nonce_hash, org_id, expires_at)
			SELECT sha256(i::text::bytea), $1, now() + interval '5 minutes' FROM generate_series(1, $2) i`, org, n)
		mustExec(t, own, `ANALYZE enrollment_challenges`)
		best := time.Hour
		for i := range 5 {
			start := time.Now()
			if _, err := pool.ExecContext(ctx, `SELECT nfx_create_enroll_challenge($1, $2, '5 minutes')`, org, []byte(fmt.Sprint("probe", n, i))); err != nil {
				t.Fatal(err)
			}
			best = min(best, time.Since(start))
		}
		took[n] = best
		t.Logf("%6d live challenges: one unauthenticated challenge call took %v", n, best.Round(10*time.Microsecond))
	}
	if took[150_000] > 2*time.Millisecond {
		t.Errorf("an unauthenticated challenge costs %v of database time with 150k live challenges (%v with 1k)",
			took[150_000].Round(10*time.Microsecond), took[1_000].Round(10*time.Microsecond))
	}
}

// GET /v1/audit-events re-verifies the org's whole hash chain on every call,
// so its cost is proportional to the org's audit history, which is never
// dropped (audit_events isn't partitioned).
func TestLimitsAuditVerificationCostGrowsWithHistory(t *testing.T) {
	knownLimit(t) // measurement of a known limit (deploy/README.md "Known gaps"); not a CI check
	pool := testdb.New(t)
	ctx := context.Background()
	org := testdb.CreateOrg(t, pool, "acme")
	took := map[int]time.Duration{}
	have := 0
	for _, n := range []int{10_000, 100_000} {
		// Typical rows: run.start / run.finish / agent.renew sized data. In
		// batches: one transaction updating the org's audit counter many
		// times is slow for reasons unrelated to production (one event per
		// transaction there).
		for from := have + 1; from <= n; from += 2000 {
			if err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
				_, err := tx.Exec(`SELECT nfx_audit('system', 'control-plane', 'run.finish', 'run', gen_random_uuid()::text,
					jsonb_build_object('status', 'succeeded', 'error', '', 'runbook', 'ecs-service-restart', 'i', i))
					FROM generate_series($1::int, $2::int) i`, from, min(from+1999, n))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		have = n
		best := time.Hour
		for range 2 {
			if err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
				start := time.Now()
				var broken sql.NullInt64
				err := tx.QueryRow(`SELECT nfx_verify_audit_chain()`).Scan(&broken)
				best = min(best, time.Since(start))
				if broken.Valid {
					return fmt.Errorf("chain broken at %d", broken.Int64)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		took[n] = best
		t.Logf("%6d audit events: verification (run by every GET /v1/audit-events) took %v", n, best.Round(time.Millisecond))
	}
	if took[100_000] > 500*time.Millisecond {
		t.Errorf("verifying 100k audit events takes %v (%v for 10k); GET /v1/audit-events runs it on every call while holding a pool connection",
			took[100_000].Round(time.Millisecond), took[10_000].Round(time.Millisecond))
	}
}

// knownLimit skips a measurement of a known, documented limit unless
// NIGHTFIX_LIMITS=1.
func knownLimit(t *testing.T) {
	t.Helper()
	if os.Getenv("NIGHTFIX_LIMITS") == "" {
		t.Skip("measures a known limit; set NIGHTFIX_LIMITS=1 to run")
	}
}
