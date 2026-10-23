package db_test

import (
	"context"
	"testing"

	"github.com/peacedouts/nightfix/internal/testdb"
)

// The app's sessions get lock, statement and idle-in-transaction timeouts
// (migration 0027), so a stuck lock or an abandoned transaction fails instead
// of hanging a worker loop silently.
func TestAppSessionsHaveTimeouts(t *testing.T) {
	pool := testdb.New(t)
	for setting, want := range map[string]string{
		"lock_timeout":                        "10s",
		"statement_timeout":                   "1min",
		"idle_in_transaction_session_timeout": "5min",
	} {
		var got string
		if err := pool.QueryRowContext(context.Background(), "SHOW "+setting).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %q for the app, want %q", setting, got, want)
		}
	}
}
