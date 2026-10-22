package controlplane

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/peacedouts/nightfix/internal/db"
)

// workerTables maps each claim function to the table its ids come from, so a
// failure can be recorded on the row (migration 0018).
var workerTables = map[string]string{
	"nfx_claim_due_incident":  "incidents",
	"nfx_claim_expired_lease": "step_attempts",
	"nfx_claim_overdue_run":   "runbook_runs",
	"nfx_claim_expired_gate":  "approval_gates",
}

// drain claims and handles rows from claimFn until none are due.
//
// A handler error that isn't transient is recorded on the row (with a
// retry time that backs off to 10 minutes) and the loop moves on to the next
// row. Returning it instead would roll back, and the same row would be
// claimed first on every tick, stalling that queue for every org. Transient
// errors (connection, deadlock, shutdown) still end the loop and are retried
// next tick.
func (s *Server) drain(ctx context.Context, claimFn string, handle func(tx *db.Tx, id string) error) (int, error) {
	table := workerTables[claimFn]
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, claimFn, func(tx *db.Tx, id string) error {
			if _, err := tx.Exec(`SAVEPOINT worker_row`); err != nil {
				return err
			}
			herr := s.safely("worker "+claimFn, func() error { return handle(tx, id) })
			if herr == nil {
				_, err := tx.Exec(`UPDATE `+table+` SET worker_failures = 0, worker_retry_at = NULL, worker_error = NULL
					WHERE id = $1 AND worker_failures > 0`, id)
				return err
			}
			if isTransient(herr) {
				return herr
			}
			if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT worker_row`); err != nil {
				return err
			}
			s.Log.Error("background work failed; will retry later", "worker", claimFn, "id", id, "err", herr)
			_, err := tx.Exec(`UPDATE `+table+` SET worker_failures = worker_failures + 1,
				worker_retry_at = now() + least(interval '1 second' * power(2, least(worker_failures, 10)), interval '10 minutes'),
				worker_error = $2 WHERE id = $1`, id, truncate(cleanText(herr.Error()), 1000))
			return err
		})
		if err != nil {
			return n, err
		}
		if !claimed {
			return n, nil
		}
		n++
	}
}

// errPanic is a bug, not bad data: recorded on the row like any other
// non-transient failure, so the row is retried later instead of the panic
// crashing the process (and, since the same row is claimed first after a
// restart, crashing every instance in turn).
type errPanic struct{ v any }

func (e errPanic) Error() string { return fmt.Sprintf("internal error (panic: %v)", e.v) }

// safely runs fn, turning a panic into an errPanic and logging its stack.
func (s *Server) safely(what string, fn func() error) (err error) {
	defer func() {
		if v := recover(); v != nil {
			s.Log.Error("panic in "+what, "panic", v, "stack", string(debug.Stack()))
			err = errPanic{v}
		}
	}()
	return fn()
}
