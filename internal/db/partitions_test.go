package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// Partition maintenance runs as the app role from the worker, possibly in a
// different timezone from the migrator. It must keep creating partitions,
// with no overlaps (which used to abort it for good) and no gaps (where
// inserts fail), whatever the session TimeZone.
func TestPartitionMaintenance(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	org := testdb.CreateOrg(t, pool, "acme")
	svc := addService(t, pool, org, "checkout-api")
	integ := ids.NewString()
	if err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id) VALUES ($1,$2,'webhook','w',$3)`, integ, org, svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for i, tz := range []string{"America/New_York", "Europe/Berlin", "America/Los_Angeles", "UTC", "Pacific/Auckland"} {
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SET LOCAL TimeZone = '`+tz+`'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT nfx_ensure_partitions($1)`, 3+i); err != nil {
			tx.Rollback()
			t.Fatalf("ensure partitions in %s: %v", tz, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	// Every hour from now to 7 days out must have a partition.
	err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
		for h := 0; h <= 7*24; h++ {
			at := time.Now().Add(time.Duration(h) * time.Hour)
			if _, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw, received_at) VALUES ($1,$2,$3,'{}',$4)`,
				ids.NewString(), org, integ, at); err != nil {
				t.Fatalf("no partition for %s (+%dh): %v", at.UTC().Format(time.RFC3339), h, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Expiry drops whole past partitions and leaves current ones.
	var dropped int
	if err := pool.QueryRowContext(ctx, `SELECT nfx_drop_expired_partitions(0, 0)`).Scan(&dropped); err != nil {
		t.Fatalf("drop expired partitions: %v", err)
	}
	if dropped == 0 {
		t.Fatal("no expired partition dropped")
	}
	if err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,'{}')`, ids.NewString(), org, integ)
		return err
	}); err != nil {
		t.Fatalf("current partition dropped: %v", err)
	}
}

func TestAppRoleCannotCreateInPublic(t *testing.T) {
	pool := testdb.New(t)
	_, err := pool.ExecContext(context.Background(), `CREATE TABLE public.planted (x int)`)
	if err == nil {
		t.Fatal("the app role could create objects in schema public")
	}
}
