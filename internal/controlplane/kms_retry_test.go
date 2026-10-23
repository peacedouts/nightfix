package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
)

type scriptedKMS struct {
	errs  []error // returned in order; then success
	calls int
}

func (k *scriptedKMS) Call(_ context.Context, _, _ string, _ map[string]any) (map[string]any, error) {
	k.calls++
	if k.calls <= len(k.errs) {
		return nil, k.errs[k.calls-1]
	}
	return map[string]any{"Plaintext": "AAAA"}, nil
}

// KMS calls at startup retry what might pass next time (throttling, 5xx,
// the network) and fail at once on what won't (access denied, wrong key).
func TestKMSCallRetriesOnlyTransientFailures(t *testing.T) {
	ctx := context.Background()

	denied := &awscall.Error{Service: "kms", Action: "Decrypt", Code: "AccessDeniedException", Status: 400}
	k := &scriptedKMS{errs: []error{denied}}
	if _, err := kmsCall(ctx, k, "Decrypt", nil); !errors.Is(err, error(denied)) || k.calls != 1 {
		t.Fatalf("access denied: %v after %d calls, want it returned after 1", err, k.calls)
	}

	// KMS (a JSON-protocol service) reports throttling as HTTP 400.
	throttled := &awscall.Error{Service: "kms", Action: "Decrypt", Code: "ThrottlingException", Status: 400}
	k = &scriptedKMS{errs: []error{throttled, errors.New("connection reset")}}
	start := time.Now()
	if _, err := kmsCall(ctx, k, "Decrypt", nil); err != nil || k.calls != 3 {
		t.Fatalf("throttled then a network error: %v after %d calls, want success on the 3rd", err, k.calls)
	}
	if d := time.Since(start); d < 3*time.Second {
		t.Fatalf("retried without backing off (%v)", d)
	}

	// Shutdown during the backoff stops it.
	ctx2, cancel := context.WithCancel(ctx)
	k = &scriptedKMS{errs: []error{&awscall.Error{Status: 500}, &awscall.Error{Status: 500}}}
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := kmsCall(ctx2, k, "Decrypt", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled during backoff: %v", err)
	}
}

func TestSafelyTurnsPanicsIntoErrors(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := s.safely("test", func() error { var m map[string]int; m["x"] = 1; return nil })
	var p errPanic
	if !errors.As(err, &p) || isTransient(err) {
		t.Fatalf("panic became %v (transient=%v)", err, isTransient(err))
	}
	if err := s.safely("test", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
