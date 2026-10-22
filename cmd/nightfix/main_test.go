package main

import (
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The deployment builds database URLs from parts (ECS injects the RDS
// credentials from Secrets Manager); a password with URL metacharacters
// must survive, and TLS must verify the server unless told otherwise.
func TestDatabaseURLFromParts(t *testing.T) {
	t.Setenv("NIGHTFIX_DATABASE_URL", "")
	t.Setenv("NIGHTFIX_ADMIN_DATABASE_URL", "")
	t.Setenv("NIGHTFIX_DB_HOST", "db.example.internal")
	t.Setenv("NIGHTFIX_APP_DB_PASSWORD", "p@ss:w/rd?#&=%")
	t.Setenv("NIGHTFIX_DB_ADMIN_USER", "rds_admin")
	t.Setenv("NIGHTFIX_DB_ADMIN_PASSWORD", "admin pw")

	u, err := url.Parse(databaseURL(false))
	if err != nil {
		t.Fatal(err)
	}
	if pw, _ := u.User.Password(); u.User.Username() != "nfx_app" || pw != "p@ss:w/rd?#&=%" {
		t.Fatalf("app credentials: %v", u.User)
	}
	if u.Host != "db.example.internal:5432" || u.Path != "/nightfix" {
		t.Fatalf("location: %s %s", u.Host, u.Path)
	}
	if q := u.Query(); q.Get("sslmode") != "verify-full" || q.Get("sslrootcert") != "/etc/ssl/rds/global-bundle.pem" {
		t.Fatalf("TLS settings: %v", q)
	}

	a, _ := url.Parse(databaseURL(true))
	if pw, _ := a.User.Password(); a.User.Username() != "rds_admin" || pw != "admin pw" {
		t.Fatalf("admin credentials: %v", a.User)
	}

	t.Setenv("NIGHTFIX_DB_SSLMODE", "require")
	t.Setenv("NIGHTFIX_DB_PORT", "6432")
	t.Setenv("NIGHTFIX_DB_NAME", "nf")
	u, _ = url.Parse(databaseURL(false))
	if q := u.Query(); q.Get("sslmode") != "require" || q.Has("sslrootcert") || u.Host != "db.example.internal:6432" || u.Path != "/nf" {
		t.Fatalf("overrides: %s", u)
	}

	t.Setenv("NIGHTFIX_DATABASE_URL", "postgres://x@y/z")
	if got := databaseURL(false); got != "postgres://x@y/z" {
		t.Fatalf("a full URL must win: %s", got)
	}
}

func TestSealerKeySources(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NIGHTFIX_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("NIGHTFIX_MASTER_KEY", "")

	// First start: a key is generated, private to the process owner, and
	// reused afterwards (credentials sealed with it stay readable).
	s1, err := sealer()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state", "master.key")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	sealed, err := s1.Seal([]byte("secret"), "org")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sealer()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Open(sealed, "org"); err != nil || string(got) != "secret" {
		t.Fatalf("restart can't open what was sealed before: %q %v", got, err)
	}

	// NIGHTFIX_MASTER_KEY overrides the file, and a bad one is an error, not
	// a silently generated key.
	key := make([]byte, 32)
	t.Setenv("NIGHTFIX_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	if _, err := sealer(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		t.Setenv("NIGHTFIX_MASTER_KEY", bad)
		if _, err := sealer(); err == nil {
			t.Errorf("NIGHTFIX_MASTER_KEY=%q accepted", bad)
		}
	}

	// A corrupt key file is an error too.
	t.Setenv("NIGHTFIX_MASTER_KEY", "")
	os.WriteFile(path, []byte(strings.Repeat("!", 10)), 0o600)
	if _, err := sealer(); err == nil {
		t.Error("corrupt master.key accepted")
	}
}
