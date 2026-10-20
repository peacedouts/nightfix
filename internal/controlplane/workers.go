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
		{"notifications", s.DeliverNotifications},
		{"deadlines", s.ProcessDueIncidents},
		{"leases", s.ProcessExpiredLeases},
		{"run-timeouts", s.ProcessOverdueRuns},
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

// Tick runs every background loop once, synchronously. Tests use it to step
// the system deterministically.
func (s *Server) Tick(ctx context.Context) error {
	for _, fn := range []func(context.Context) (int, error){
		s.ProcessAlertEvents, s.DeliverNotifications, s.ProcessDueIncidents, s.ProcessExpiredLeases, s.ProcessOverdueRuns,
	} {
		if _, err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
