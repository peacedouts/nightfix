package controlplane

import (
	"context"
	"encoding/base64"
	"time"
)

// RunWorkers runs the background loops until ctx is cancelled: alert
// processing, notification delivery, hold/verification deadlines, lease
// expiry, run timeouts, stale agents and partition maintenance. Every loop
// claims work with SKIP LOCKED, so any number of control-plane instances can
// run them concurrently.
func (s *Server) RunWorkers(ctx context.Context, tick time.Duration) {
	if tick == 0 {
		tick = 250 * time.Millisecond
	}
	loops := []struct {
		name string
		fn   func(context.Context) (int, error)
	}{
		{"alerts", s.ProcessAlertEvents},
		{"deadlines", s.ProcessDueIncidents},
		{"leases", s.ProcessExpiredLeases},
		{"run-timeouts", s.ProcessOverdueRuns},
		{"approval-expiry", s.ProcessExpiredGates},
	}
	// Notifications get several workers that claim independently, so one
	// slow endpoint can't hold up anyone else's pages.
	for range s.Cfg.NotifyWorkers {
		s.workers.Add(1)
		go s.notifyWorker(ctx, tick)
	}
	for _, l := range loops {
		go func(name string, fn func(context.Context) (int, error)) {
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				if _, err := fn(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error("worker", "loop", name, "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}(l.name, l.fn)
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		lastPartitions := time.Time{}
		for {
			s.DB.ExecContext(ctx, `SELECT nfx_mark_stale_agents()`)
			if time.Since(lastPartitions) > time.Hour {
				if _, err := s.DB.ExecContext(ctx, `SELECT nfx_ensure_partitions(3)`); err != nil && ctx.Err() == nil {
					s.Log.Error("partitions", "err", err)
				}
				s.DB.ExecContext(ctx, `SELECT nfx_drop_expired_partitions(30, 90)`)
				s.expireDedupRecords(ctx)
				lastPartitions = time.Now()
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// WaitWorkers waits, up to timeout, for RunWorkers' notification workers
// to finish what they claimed after its context is cancelled, so a page
// sent during shutdown is recorded rather than sent again by another
// instance.
func (s *Server) WaitWorkers(timeout time.Duration) {
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.Log.Warn("notification workers still busy at shutdown")
	}
}

// Tick runs every background loop once, synchronously. Tests use it to step
// the system deterministically.
func (s *Server) Tick(ctx context.Context) error {
	for _, fn := range []func(context.Context) (int, error){
		s.ProcessAlertEvents, s.DeliverNotifications, s.ProcessDueIncidents, s.ProcessExpiredLeases, s.ProcessOverdueRuns,
		s.ProcessExpiredGates,
	} {
		if _, err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

// expireDedupRecords deletes replay records that have outlived their window:
// SNS MessageIds and API idempotency keys.
func (s *Server) expireDedupRecords(ctx context.Context) {
	for _, fn := range []string{"nfx_expire_ingest_message_ids", "nfx_expire_idempotency_keys"} {
		if _, err := s.DB.ExecContext(ctx, `SELECT `+fn+`()`); err != nil && ctx.Err() == nil {
			s.Log.Error("expire records", "fn", fn, "err", err)
		}
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
