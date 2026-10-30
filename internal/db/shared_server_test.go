package db_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// A second Nightfix database on the same Postgres server is refused: the
// roles are server-wide, so the deployments would share the app's login.
// And only the app (and the owner) may connect to a Nightfix database.
func TestOneNightfixDatabasePerServer(t *testing.T) {
	adminDSN := os.Getenv("NIGHTFIX_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("NIGHTFIX_TEST_ADMIN_DSN not set")
	}
	ctx := context.Background()
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	newDB := func() string {
		name := "nfx_shared_" + strings.ReplaceAll(ids.NewString()[24:], "-", "")
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
		u, _ := url.Parse(adminDSN)
		u.Path = "/" + name
		return u.String()
	}
	// Other tests share this server under db.AllowSharedServer; start this
	// one from a clean slate and leave it that way.
	// Migrate sets the server-wide nfx_app password, and other packages' tests
	// connect with testdb's, so use the same one.
	clear := func() { admin.ExecContext(context.Background(), `COMMENT ON ROLE nfx_app IS NULL`) }
	db.AllowSharedServer = false
	defer func() { db.AllowSharedServer = true; clear() }()
	clear()

	first, second := newDB(), newDB()
	if err := db.Migrate(ctx, first, testdb.AppPassword); err != nil {
		t.Fatalf("first database: %v", err)
	}
	if err := db.Migrate(ctx, first, testdb.AppPassword); err != nil {
		t.Fatalf("migrating the same database again: %v", err)
	}
	if err := db.Migrate(ctx, second, testdb.AppPassword); err == nil || !strings.Contains(err.Error(), "another Nightfix database") {
		t.Fatalf("second database on the server: %v", err)
	}

	var public bool
	u, _ := url.Parse(first)
	if err := admin.QueryRowContext(ctx, `SELECT has_database_privilege('public', $1, 'CONNECT')`, strings.TrimPrefix(u.Path, "/")).Scan(&public); err != nil {
		t.Fatal(err)
	}
	if public {
		t.Fatal("PUBLIC can still connect to the Nightfix database")
	}
}
