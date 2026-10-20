// Package testdb creates a fresh, migrated Postgres database for a test.
//
// Set NIGHTFIX_TEST_ADMIN_DSN to a superuser DSN (scripts/dev-postgres.sh prints
// one). Tests that need Postgres are skipped when it isn't set.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

const appPassword = "nfx_app_test"

// New returns a pool connected as nfx_app to a new database, dropped at test end.
func New(t testing.TB) *db.DB {
	t.Helper()
	adminDSN := os.Getenv("NIGHTFIX_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("NIGHTFIX_TEST_ADMIN_DSN not set; skipping Postgres test")
	}
	ctx := context.Background()
	name := "nfx_test_" + strings.ReplaceAll(ids.NewString()[24:], "-", "")

	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})

	adminForDB := withDatabase(t, adminDSN, name, "")
	if err := db.Migrate(ctx, adminForDB, appPassword); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	appDSN := withDatabase(t, adminDSN, name, "nfx_app:"+appPassword)
	pool, err := db.Open(ctx, appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	adminDSNs.Store(pool, adminForDB)
	return pool
}

var adminDSNs sync.Map // *db.DB -> superuser DSN for the same database

// Admin returns a superuser connection to pool's database, for tests that
// need to set up state the app role can't reach (such as the global users
// table). Never use it to exercise application behavior.
func Admin(t testing.TB, pool *db.DB) *sql.DB {
	t.Helper()
	dsn, ok := adminDSNs.Load(pool)
	if !ok {
		t.Fatal("testdb.Admin: pool was not created by testdb.New")
	}
	c, err := sql.Open("postgres", dsn.(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// withDatabase rewrites a DSN URL to point at database name, optionally
// replacing the user:password.
func withDatabase(t testing.TB, dsn, name, userinfo string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("NIGHTFIX_TEST_ADMIN_DSN must be a URL: %v", err)
	}
	u.Path = "/" + name
	if userinfo != "" {
		user, pass, _ := strings.Cut(userinfo, ":")
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

// AppDSNFor exposes the same rewrite for callers that start servers.
func AppDSNFor(adminDSN, name string) string {
	u, _ := url.Parse(adminDSN)
	u.Path = "/" + name
	u.User = url.UserPassword("nfx_app", appPassword)
	return u.String()
}

// CreateOrg makes an org directly (bypassing the API) and returns its id.
func CreateOrg(t testing.TB, pool *db.DB, slug string) string {
	t.Helper()
	id := ids.NewString()
	if _, err := pool.ExecContext(context.Background(), "SELECT nfx_create_org($1,$2,$3)", id, slug, slug); err != nil {
		t.Fatalf("create org: %v", err)
	}
	return id
}

var _ = fmt.Sprintf
