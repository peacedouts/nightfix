package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// With several workers, an org's alert events must still be processed in
// arrival order (an alarm and its OK can't be handled out of order), while
// other orgs' events proceed in parallel.
func TestAlertEventsClaimInOrderPerOrg(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	event := func(org string) string {
		t.Helper()
		integ, id := ids.NewString(), ids.NewString()
		svc := addService(t, pool, org, "svc-"+id[len(id)-12:])
		err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
			if _, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id) VALUES ($1,$2,'webhook',$4,$3)`, integ, org, svc, "w-"+integ); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,'{}')`, id, org, integ)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // distinct received_at
		return id
	}
	a := testdb.CreateOrg(t, pool, "acme")
	b := testdb.CreateOrg(t, pool, "globex")
	a1 := event(a)
	a2 := event(a)
	b1 := event(b)

	claim := func() (*db.DB, func(), string) {
		t.Helper()
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var org, id string
		var at time.Time
		if err := tx.QueryRowContext(ctx, `SELECT org_id, id, received_at FROM nfx_claim_alert_event()`).Scan(&org, &id, &at); err != nil {
			id = ""
		}
		return pool, func() { tx.Rollback() }, id
	}
	_, release1, first := claim()
	defer release1()
	if first != a1 {
		t.Fatalf("first claim got %s, want acme's oldest event %s", first, a1)
	}
	// While acme's first event is in progress, a second worker must skip
	// acme's next event and take globex's instead.
	_, release2, second := claim()
	defer release2()
	if second != b1 {
		t.Fatalf("second claim got %s, want globex's event %s (acme's %s must wait)", second, b1, a2)
	}
	_, release3, third := claim()
	defer release3()
	if third != "" {
		t.Fatalf("third claim got %s; acme's next event must wait for the first", third)
	}
}
