// Package db wraps Postgres access. All tenant data is reached through
// WithOrg, which opens a transaction and sets app.org_id so row-level security
// scopes every statement to one org.
package db

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq" // Postgres driver

	"github.com/peacedouts/nightfix/migrations"
)

// DB is the application's connection pool. It connects as nfx_app, which
// does not own any table, so RLS always applies.
type DB struct {
	*sql.DB
}

// Open connects and verifies the connection.
func Open(ctx context.Context, dsn string) (*DB, error) {
	sqldb, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(20)
	sqldb.SetMaxIdleConns(10)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sqldb.PingContext(pctx); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	return &DB{sqldb}, nil
}

// Tx is a transaction already scoped to one org.
type Tx struct {
	*sql.Tx
	OrgID string
}

// WithOrg runs fn in a transaction with app.org_id set to orgID. The org must
// come from an authenticated principal or a claimed job, never request input.
func (d *DB) WithOrg(ctx context.Context, orgID string, fn func(*Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := setOrg(ctx, tx, orgID); err != nil {
		tx.Rollback()
		return err
	}
	if err := fn(&Tx{Tx: tx, OrgID: orgID}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Claim runs a SECURITY DEFINER claim function that locks one due job and
// returns its org and id, then scopes the same transaction to that org and
// calls fn. Returns false if there was nothing to claim.
func (d *DB) Claim(ctx context.Context, claimFn string, fn func(tx *Tx, id string) error) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	var orgID, id string
	err = tx.QueryRowContext(ctx, "SELECT org_id, id FROM "+claimFn+"()").Scan(&orgID, &id)
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return false, nil
	}
	if err != nil {
		tx.Rollback()
		return false, err
	}
	if err := setOrg(ctx, tx, orgID); err != nil {
		tx.Rollback()
		return false, err
	}
	if err := fn(&Tx{Tx: tx, OrgID: orgID}, id); err != nil {
		tx.Rollback()
		return true, err
	}
	return true, tx.Commit()
}

func setOrg(ctx context.Context, tx *sql.Tx, orgID string) error {
	if orgID == "" {
		return errors.New("db: empty org id")
	}
	// set_config(..., true) is SET LOCAL: scoped to this transaction only.
	_, err := tx.ExecContext(ctx, "SELECT set_config('app.org_id', $1, true)", orgID)
	return err
}

// Audit appends a hash-chained audit event for the transaction's org.
func (t *Tx) Audit(ctx context.Context, actorType, actorID, action, resourceType, resourceID string, data any) error {
	js, err := jsonb(data)
	if err != nil {
		return err
	}
	_, err = t.ExecContext(ctx, "SELECT nfx_audit($1,$2,$3,$4,$5,$6)", actorType, actorID, action, resourceType, resourceID, js)
	return err
}

// NextCounter increments and returns a per-org counter (e.g. incident numbers).
func (t *Tx) NextCounter(ctx context.Context, name string) (int64, error) {
	var v int64
	err := t.QueryRowContext(ctx, `
		INSERT INTO org_counters (org_id, name, value) VALUES ($1, $2, 1)
		ON CONFLICT (org_id, name) DO UPDATE SET value = org_counters.value + 1
		RETURNING value`, t.OrgID, name).Scan(&v)
	return v, err
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Migrate applies pending migrations using an administrative connection
// (one that can create roles). It creates the nfx_owner and nfx_app roles if
// needed and sets nfx_app's password.
func Migrate(ctx context.Context, adminDSN, appPassword string) error {
	sqldb, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return err
	}
	defer sqldb.Close()
	if err := sqldb.PingContext(ctx); err != nil {
		return fmt.Errorf("connect (admin): %w", err)
	}

	conn, err := sqldb.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Serialize concurrent migrators.
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(7351001)"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(7351001)")

	var me string
	if err := conn.QueryRowContext(ctx, "SELECT current_user").Scan(&me); err != nil {
		return err
	}
	if !identRe.MatchString(me) {
		return fmt.Errorf("unexpected admin role name %q", me)
	}
	setup := []string{
		// Roles are cluster-wide, so migrators of different databases can race
		// here; a duplicate is fine.
		`DO $$ BEGIN
		   BEGIN CREATE ROLE nfx_owner NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
		   BEGIN CREATE ROLE nfx_app LOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
		 END $$`,
		"GRANT nfx_owner TO " + me,
		"GRANT USAGE, CREATE ON SCHEMA public TO nfx_owner",
		"GRANT USAGE ON SCHEMA public TO nfx_app",
		`CREATE TABLE IF NOT EXISTS schema_migrations (
		   name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`,
	}
	for _, s := range setup {
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			// "tuple concurrently updated" when another database's migrator
			// grants the same role at the same moment: retry.
			if _, err = conn.ExecContext(ctx, s); err == nil || !strings.Contains(err.Error(), "concurrently") {
				break
			}
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("migration setup: %w", err)
		}
	}
	if appPassword != "" {
		// Send a SCRAM verifier, not the password: if the statement ever
		// errors, Postgres logs its text, and RDS exports those logs.
		v, err := scramVerifier(appPassword)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "ALTER ROLE nfx_app PASSWORD "+quoteLiteral(v)); err != nil {
			return errors.New("set nfx_app password: " + strings.SplitN(err.Error(), "PASSWORD", 2)[0])
		}
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := conn.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)", name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES ($1)", name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint error.
func IsUniqueViolation(err error) bool {
	var pqErr interface{ SQLState() string }
	if errors.As(err, &pqErr) {
		return pqErr.SQLState() == "23505"
	}
	return false
}

// scramVerifier returns a SCRAM-SHA-256 verifier for password in the form
// Postgres stores (RFC 5802, RFC 7677), so the plaintext never reaches the server.
func scramVerifier(password string) (string, error) {
	const iterations = 4096
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(stored[:]), b64(mac(salted, "Server Key"))), nil
}
