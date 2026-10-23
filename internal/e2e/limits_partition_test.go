package e2e_test

// Limits review: partition maintenance on the shared alert_events table.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Creating (and dropping) a partition takes an ACCESS EXCLUSIVE lock on
// alert_events. While maintenance waits for it behind any transaction that
// touches the table (an alert event being processed holds its row lock until
// it commits), every org's ingest queues behind maintenance and fails at its
// 5s lock_timeout; maintenance itself gives up after nfx_app's 10s
// lock_timeout and isn't retried for an hour. Partitions are made only 3
// days ahead, so a processing transaction that's always open (one org's slow
// events, see TestLimitsSlowRoutingRulesStallOtherOrgsAlertProcessing) stops
// partitions being created, and ingest for every org fails 3 days later.
func TestLimitsPartitionMaintenanceBlocksIngestBehindAnOpenTransaction(t *testing.T) {
	x := setupIngest(t, nil)
	quiet := x.newOtherOrg("quiet")
	ctx := context.Background()
	own := ownerConn(t, x.srv.DB)

	// Tomorrow+3's partition doesn't exist yet (as on the first maintenance
	// run after midnight UTC).
	var latest string
	if err := own.QueryRowContext(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'public.alert_events'::regclass ORDER BY nfx_partition_upper(c.oid) DESC LIMIT 1`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	mustExec(t, own, fmt.Sprintf(`DROP TABLE public.%q`, latest))

	// An alert event is being processed (its claim holds the event's row
	// lock until the processing transaction commits).
	if code := x.send(map[string]any{"dedup_key": "slow-1", "summary": "slow"}); code != 202 {
		t.Fatalf("ingest %d", code)
	}
	app := appConn(t, x.srv.DB)
	hold, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var org, id string
	if err := hold.QueryRow(`SELECT org_id, id FROM nfx_claim_alert_event()`).Scan(&org, &id); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	start := time.Now()
	var maintTook time.Duration
	go func() {
		_, err := x.srv.DB.ExecContext(ctx, `SELECT nfx_ensure_partitions(3)`)
		maintTook = time.Since(start)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	code, d := postSigned(quiet.ingest, quiet.secret, map[string]any{"dedup_key": "q-1", "summary": "quiet org alert", "delivery": 1}, 30*time.Second)
	merr := <-done
	hold.Rollback()
	t.Logf("partition maintenance: err=%v after %v; another org's ingest meanwhile: status %d after %v", merr, maintTook.Round(time.Millisecond), code, d.Round(time.Millisecond))
	if merr != nil || code != 202 || d > 2*time.Second {
		t.Errorf("one open alert-processing transaction made partition maintenance fail (%v) and another org's ingest return %d after %v",
			merr, code, d.Round(time.Millisecond))
	}
}
