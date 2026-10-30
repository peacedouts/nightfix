package auth0

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
)

// A key the provider withdraws stops being trusted at the next hourly
// refresh; a refresh that fails keeps the keys already loaded.
func TestJWKSRefreshesHourly(t *testing.T) {
	idp := auth0test.New(t)
	var mode atomic.Int32 // 0 serve keys, 1 serve none, 2 fail
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			w.Write([]byte(`{"keys": []}`))
		case 2:
			http.Error(w, "down", http.StatusServiceUnavailable)
		default:
			resp, err := http.Get(idp.Srv.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			buf := make([]byte, 1<<16)
			n, _ := resp.Body.Read(buf)
			w.Write(buf[:n])
		}
	}))
	defer srv.Close()
	v := &Verifier{Issuer: idp.Issuer, Audience: idp.Audience, JWKSURL: srv.URL}
	tok := idp.UserToken("u1", "u1@example.com", "org_x")
	verify := func() error { _, err := v.Verify(context.Background(), tok); return err }
	age := func() {
		v.mu.Lock()
		v.fetchedAt = time.Now().Add(-2 * time.Hour)
		v.lastTry = time.Now().Add(-2 * time.Hour)
		v.mu.Unlock()
	}

	if err := verify(); err != nil {
		t.Fatal(err)
	}
	mode.Store(2) // the provider is down at the refresh
	age()
	if err := verify(); err != nil {
		t.Fatalf("a failed refresh locked users out: %v", err)
	}
	mode.Store(1) // the provider withdrew the key
	age()
	if err := verify(); err == nil {
		t.Fatal("a withdrawn key is still trusted after the refresh")
	}
}
