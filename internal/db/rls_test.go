package db_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/testdb"
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
	org := testdb.CreateOrg(t, pool, "acme")
	// With a row present the policy must be evaluated, and without app.org_id
	// it errors. (On an empty table Postgres may never evaluate the policy and
	// simply return zero rows, which leaks nothing but proves nothing.)
	addService(t, pool, org, "checkout-api")
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
		return tx.QueryRow(`SELECT nfx_verify_audit_chain()`).Scan(&broken)
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

	claimed, err := pool.Claim(ctx, "nfx_claim_alert_event", func(tx *db.Tx, id string) error {
		if tx.OrgID != a {
			t.Fatalf("claimed under org %s, want %s", tx.OrgID, a)
		}
		_, err := tx.Exec(`UPDATE alert_events SET processed_at = now() WHERE id = $1`, id)
		return err
	})
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	again, _ := pool.Claim(ctx, "nfx_claim_alert_event", func(*db.Tx, string) error { return nil })
	if again {
		t.Fatal("processed event was claimed twice")
	}
}

// Managed Postgres has no superuser, so nfx_owner can't have BYPASSRLS.
// Every table with row-level security must have a policy, every tenant table
// one that admits nfx_owner (for the SECURITY DEFINER functions), and the
// app's policy must be the plain org condition (migration 0024: an OR in it
// keeps Postgres from using the org indexes).
func TestEveryRLSTableHasOwnerAwarePolicies(t *testing.T) {
	pool := testdb.New(t)
	rows, err := pool.QueryContext(context.Background(), `
		SELECT c.relname, coalesce(string_agg(array_to_string(p.roles, ',') || ': ' || p.qual || ' / ' || coalesce(p.with_check, ''), '; ' ORDER BY p.policyname), '')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_policies p ON p.schemaname = 'public' AND p.tablename = c.relname
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relrowsecurity
		GROUP BY c.relname ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var table, quals string
		if err := rows.Scan(&table, &quals); err != nil {
			t.Fatal(err)
		}
		n++
		if quals == "" {
			t.Errorf("%s has row-level security but no policy", table)
		} else if table == "enrollment_challenges" {
			continue // owner only: no tenant rows for the app
		} else if !strings.Contains(quals, "nfx_owner: true / true") {
			t.Errorf("%s: no policy admits nfx_owner to every row: %s", table, quals)
		} else if !strings.Contains(quals, "nfx_app: ") || strings.Contains(quals, " OR ") {
			t.Errorf("%s: the app's policy must be the plain org condition, for nfx_app only: %s", table, quals)
		}
	}
	if n < 20 {
		t.Fatalf("expected the tenant tables, found %d", n)
	}
	var bypass bool
	if err := pool.QueryRowContext(context.Background(), `SELECT rolbypassrls FROM pg_roles WHERE rolname = 'nfx_app'`).Scan(&bypass); err != nil || bypass {
		t.Fatalf("nfx_app must never bypass RLS (bypass=%v, err=%v)", bypass, err)
	}
}

// The audit-chain check runs as nfx_owner, where "no org" is NULL rather than
// an error; it must refuse rather than report an empty chain as intact.
func TestAuditChainCheckNeedsAnOrg(t *testing.T) {
	pool := testdb.New(t)
	var broken sql.NullInt64
	err := pool.QueryRowContext(context.Background(), `SELECT nfx_verify_audit_chain()`).Scan(&broken)
	if err == nil || !strings.Contains(err.Error(), "no org set") {
		t.Fatalf("expected a refusal without an org, got %v (%v)", err, broken)
	}
}

func TestSecurityDefinerFunctionsSearchTempLast(t *testing.T) {
	pool := testdb.New(t)
	var bad []string
	rows, err := pool.QueryContext(context.Background(), `
		SELECT p.proname, coalesce(array_to_string(p.proconfig, ','), '')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public' AND p.prosecdef`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, cfg string
		rows.Scan(&name, &cfg)
		if !strings.Contains(cfg, "search_path=pg_catalog, public, pg_temp") {
			bad = append(bad, name+" ("+cfg+")")
		}
	}
	if len(bad) > 0 {
		t.Fatalf("SECURITY DEFINER functions without pg_temp last in search_path: %v", bad)
	}
}

func TestAuditChainIgnoresSessionTimeZone(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	org := testdb.CreateOrg(t, pool, "acme")
	for _, tz := range []string{"America/New_York", "Asia/Kolkata"} {
		err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
			if _, err := tx.Exec(`SET LOCAL TimeZone = '` + tz + `'`); err != nil {
				return err
			}
			return tx.Audit(ctx, "user", "u", "test.action", "thing", "1", map[string]string{"tz": tz})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tz := range []string{"UTC", "Pacific/Auckland"} {
		var broken sql.NullInt64
		err := pool.WithOrg(ctx, org, func(tx *db.Tx) error {
			if _, err := tx.Exec(`SET LOCAL TimeZone = '` + tz + `'`); err != nil {
				return err
			}
			return tx.QueryRow(`SELECT nfx_verify_audit_chain()`).Scan(&broken)
		})
		if err != nil {
			t.Fatal(err)
		}
		if broken.Valid {
			t.Fatalf("verifying in %s reported the chain broken at seq %d", tz, broken.Int64)
		}
	}
}

// The partition worker calls nfx_ensure_partitions as the app role. It must
// create days that migrations didn't pre-create; with pg_catalog first on its
// search_path, an unqualified CREATE TABLE once failed with "permission
// denied for schema pg_catalog", which would have broken ingest days later.
func TestEnsurePartitionsCreatesNewDays(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	if _, err := pool.ExecContext(ctx, `SELECT nfx_ensure_partitions(10)`); err != nil {
		t.Fatalf("nfx_ensure_partitions: %v", err)
	}
	for _, table := range []string{"alert_events", "step_output_chunks"} {
		var name string
		err := pool.QueryRowContext(ctx, `SELECT format('%s_%s', $1::text, to_char(current_date + 10, 'YYYYMMDD'))`, table).Scan(&name)
		if err != nil {
			t.Fatal(err)
		}
		var schema, quals string
		err = pool.QueryRowContext(ctx, `SELECT n.nspname, coalesce((SELECT string_agg(array_to_string(p.roles, ',') || ': ' || p.qual, '; ' ORDER BY p.policyname)
			FROM pg_policies p WHERE p.tablename = c.relname), '')
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = $1`, name).Scan(&schema, &quals)
		if err != nil {
			t.Fatalf("partition %s wasn't created: %v", name, err)
		}
		if schema != "public" || !strings.Contains(quals, "nfx_app: (org_id = nfx_org())") || !strings.Contains(quals, "nfx_owner: true") {
			t.Fatalf("partition %s: schema %q, policy %q", name, schema, quals)
		}
	}
}
