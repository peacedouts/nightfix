package db_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/testdb"

	_ "github.com/lib/pq"
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

	// Retention can't be shortened below the floors, even by nfx_app.
	var dropped int
	if err := pool.QueryRowContext(ctx, `SELECT nfx_drop_expired_partitions(-2, -2)`).Scan(&dropped); err != nil {
		t.Fatalf("drop expired partitions: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped %d recent partitions", dropped)
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

// Only nfx_app may call the SECURITY DEFINER functions; a role with no grants
// used to be able to drop every org's partitions or create orgs.
func TestOtherRolesCannotCallPrivilegedFunctions(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	admin := adminConn(t, pool)
	role := "nobody_" + strings.ReplaceAll(ids.NewString()[24:], "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'pw'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), `DROP ROLE IF EXISTS `+role) })
	nobody := asRole(t, pool, role, "pw")
	for _, q := range []string{`SELECT nfx_drop_expired_partitions(30, 90)`, `SELECT nfx_create_org(gen_random_uuid(), 'x', 'x')`, `SELECT * FROM nfx_route_api_key('\x00')`} {
		if _, err := nobody.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s as a role with no grants: %v", q, err)
		}
	}
}

func adminConn(t *testing.T, pool *db.DB) *sql.DB {
	t.Helper()
	return asRole(t, pool, "", "")
}

// asRole connects to the test database as role (or as the admin if empty).
func asRole(t *testing.T, pool *db.DB, role, password string) *sql.DB {
	t.Helper()
	var name string
	if err := pool.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(os.Getenv("NIGHTFIX_TEST_ADMIN_DSN"))
	u.Path = "/" + name
	if role != "" {
		u.User = url.UserPassword(role, password)
	}
	c, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
