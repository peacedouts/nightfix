package db_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/peacedouts/lightning_ir/internal/db"
	"github.com/peacedouts/lightning_ir/internal/ids"
	"github.com/peacedouts/lightning_ir/internal/testdb"
)

func addService(t *testing.T, pool *db.DB, org, name string) string {
	t.Helper()
	id := ids.NewString()
	err := pool.WithOrg(context.Background(), org, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO services (id, org_id, name) VALUES ($1, $2, $3)`, id, org, name)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRLSIsolatesOrgs(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	a := testdb.CreateOrg(t, pool, "acme")
	b := testdb.CreateOrg(t, pool, "globex")
	addService(t, pool, a, "checkout-api")
	addService(t, pool, b, "billing")

	// Each org sees only its own services.
	for org, want := range map[string]string{a: "checkout-api", b: "billing"} {
		var names []string
		err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
			rows, err := tx.Query(`SELECT name FROM services`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var n string
				rows.Scan(&n)
				names = append(names, n)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(names) != 1 || names[0] != want {
			t.Fatalf("org %s saw %v, want [%s]", org, names, want)
		}
	}
}

func TestRLSRejectsWritesIntoAnotherOrg(t *testing.T) {
	pool := testdb.New(t)
	a := testdb.CreateOrg(t, pool, "acme")
	b := testdb.CreateOrg(t, pool, "globex")

	err := pool.WithOrg(context.Background(), a, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO services (id, org_id, name) VALUES ($1, $2, 'sneaky')`, ids.NewString(), b)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("expected RLS violation, got %v", err)
	}
}

func TestQueriesFailClosedWithoutOrg(t *testing.T) {
	pool := testdb.New(t)
	testdb.CreateOrg(t, pool, "acme")
	var n int
	err := pool.QueryRow(`SELECT count(*) FROM services`).Scan(&n)
	if err == nil {
		t.Fatalf("query without app.org_id should fail, got count %d", n)
	}
}

func TestCompositeForeignKeysBlockCrossOrgLinks(t *testing.T) {
	pool := testdb.New(t)
	a := testdb.CreateOrg(t, pool, "acme")
	b := testdb.CreateOrg(t, pool, "globex")
	bService := addService(t, pool, b, "billing")

	// Even with the right org_id for the row, referencing another org's
	// service id fails the composite (org_id, id) foreign key.
	err := pool.WithOrg(context.Background(), a, func(tx *db.Tx) error {
		_, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id)
			VALUES ($1, $2, 'webhook', 'x', $3)`, ids.NewString(), a, bService)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("expected foreign key violation, got %v", err)
	}
}

func TestAuditIsAppendOnlyAndChained(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	a := testdb.CreateOrg(t, pool, "acme")

	err := pool.WithOrg(ctx, a, func(tx *db.Tx) error {
		for i := 0; i < 3; i++ {
			if err := tx.Audit(ctx, "user", "u1", "service.create", "service", "s1", map[string]int{"i": i}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The chain verifies.
	var broken sql.NullInt64
	pool.WithOrg(ctx, a, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT lir_verify_audit_chain()`).Scan(&broken)
	})
	if broken.Valid {
		t.Fatalf("audit chain broken at seq %d", broken.Int64)
	}

	// The app role cannot update or delete audit rows.
	for _, stmt := range []string{
		`UPDATE audit_events SET action = 'tampered' WHERE seq = 2`,
		`DELETE FROM audit_events WHERE seq = 2`,
	} {
		err := pool.WithOrg(ctx, a, func(tx *db.Tx) error {
			_, err := tx.Exec(stmt)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%q: expected permission denied, got %v", stmt, err)
		}
	}
}

func TestClaimScopesToClaimedOrg(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	a := testdb.CreateOrg(t, pool, "acme")
	svc := addService(t, pool, a, "checkout-api")
	integ := ids.NewString()
	pool.WithOrg(ctx, a, func(tx *db.Tx) error {
		if _, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id) VALUES ($1,$2,'webhook','w',$3)`, integ, a, svc); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,'{}')`, ids.NewString(), a, integ)
		return err
	})

	claimed, err := pool.Claim(ctx, "lir_claim_alert_event", func(tx *db.Tx, id string) error {
		if tx.OrgID != a {
			t.Fatalf("claimed under org %s, want %s", tx.OrgID, a)
		}
		_, err := tx.Exec(`UPDATE alert_events SET processed_at = now() WHERE id = $1`, id)
		return err
	})
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	again, _ := pool.Claim(ctx, "lir_claim_alert_event", func(*db.Tx, string) error { return nil })
	if again {
		t.Fatal("processed event was claimed twice")
	}
}
