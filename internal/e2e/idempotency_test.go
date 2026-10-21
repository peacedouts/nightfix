package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

type idemResponse struct {
	code     int
	body     string
	replayed bool
}

// idem makes an API call with an Idempotency-Key (none if key is "").
func (x *ingestHarness) idem(apiKey, method, path, key, body string) idemResponse {
	x.t.Helper()
	req, _ := http.NewRequest(method, x.api+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return idemResponse{resp.StatusCode, string(b), resp.Header.Get("Idempotent-Replayed") == "true"}
}

func (x *ingestHarness) exec(query string, args ...any) {
	x.t.Helper()
	if err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	}); err != nil {
		x.t.Fatal(err)
	}
}

func TestIdempotencyKeyOnAPIWrites(t *testing.T) {
	x := setupIngest(t, nil)
	team := `{"slug":"payments"}`

	first := x.idem(x.key, "POST", "/v1/teams", "k1", team)
	if first.code != 200 || first.replayed {
		t.Fatalf("first request: %+v", first)
	}
	// A retry gets the stored response and doesn't run again.
	again := x.idem(x.key, "POST", "/v1/teams", "k1", team)
	if again.code != 200 || again.body != first.body || !again.replayed {
		t.Fatalf("retry: %+v, want a replay of %+v", again, first)
	}
	if n := x.count(`SELECT count(*) FROM audit_events WHERE action = 'team.create'`); n != 1 {
		t.Fatalf("team.create ran %d times", n)
	}
	// The same key for a different request is refused. (No path takes both
	// POST and PUT, so a method-only change never reaches the key check; the
	// method is compared all the same.)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/teams", `{"slug":"billing"}`},   // body
		{"POST", "/v1/services", team},                // path
		{"PUT", "/v1/routing-rules", team},            // method and path
		{"POST", "/v1/teams", `{"slug": "payments"}`}, // bytes, not JSON meaning
	} {
		r := x.idem(x.key, c.method, c.path, "k1", c.body)
		if r.code != http.StatusUnprocessableEntity {
			t.Fatalf("key reused for %s %s %s: %+v, want 422", c.method, c.path, c.body, r)
		}
	}
	// Errors below 500 are kept too: retrying a bad request doesn't re-run it.
	if bad := x.idem(x.key, "POST", "/v1/teams", "k-bad", `{"slug":"Not A Slug"}`); bad.code != 400 {
		t.Fatalf("bad request: %+v", bad)
	}
	if bad := x.idem(x.key, "POST", "/v1/teams", "k-bad", `{"slug":"Not A Slug"}`); bad.code != 400 || !bad.replayed {
		t.Fatalf("bad request retry: %+v", bad)
	}
	if bad := x.idem(x.key, "POST", "/v1/teams", "bad key with spaces", team); bad.code != 400 {
		t.Fatalf("malformed key: %+v", bad)
	}

	// Keys belong to a principal: another API key in the org using "k1" runs
	// its own request (and finds the team already exists).
	second := "nfx_second-key-for-idempotency-test"
	sum := sha256.Sum256([]byte(second))
	x.exec(`INSERT INTO api_keys (id, org_id, name, prefix, hash, role) VALUES ($1,$2,'second','nfx_s',$3,'owner')`, ids.NewString(), x.orgID, sum[:])
	if other := x.idem(second, "POST", "/v1/teams", "k1", team); other.code != http.StatusConflict || other.replayed {
		t.Fatalf("other principal, same key: %+v, want its own execution (409 exists)", other)
	}

	// Only a hash of the request is kept, and the stored response is sealed.
	var hashLen int
	var response []byte
	x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT length(body_hash), response FROM idempotency_keys WHERE key = 'k1' AND principal LIKE 'key_%' ORDER BY created_at LIMIT 1`).
			Scan(&hashLen, &response)
	})
	if hashLen != 32 || bytes.Contains(response, []byte("payments")) || bytes.Contains(response, []byte("team_")) {
		t.Fatalf("stored hash length %d, response %q: want a SHA-256 and a sealed response", hashLen, response)
	}

	// After 24h the key is free again: the request runs (409, team exists).
	x.exec(`UPDATE idempotency_keys SET expires_at = now() - interval '1 second' WHERE key = 'k1'`)
	if late := x.idem(x.key, "POST", "/v1/teams", "k1", team); late.code != http.StatusConflict || late.replayed {
		t.Fatalf("expired key: %+v, want a fresh execution", late)
	}
	// And the worker deletes expired keys.
	x.exec(`UPDATE idempotency_keys SET expires_at = now() - interval '1 second'`)
	var expired int
	if err := x.srv.DB.QueryRow(`SELECT nfx_expire_idempotency_keys()`).Scan(&expired); err != nil || expired == 0 {
		t.Fatalf("expired %d keys (%v)", expired, err)
	}
	if n := x.count(`SELECT count(*) FROM idempotency_keys`); n != 0 {
		t.Fatalf("%d keys left after expiry", n)
	}

	// A request still in flight turns a duplicate away; one whose request
	// died (claim older than the lease) is taken over by an identical retry.
	var me map[string]any
	x.call("GET", "/v1/me", nil, &me)
	svc := `{"name":"ledger"}`
	svcHash := sha256.Sum256([]byte(svc))
	claim := `INSERT INTO idempotency_keys (org_id, principal, key, method, path, body_hash, request_id, created_at, expires_at)
		VALUES ($1,$2,$3,'POST','/v1/services',$4,$5, now() - $6::interval, now() + interval '1 day')`
	x.exec(claim, x.orgID, me["principal"], "k-inflight", svcHash[:], ids.NewString(), "1 second")
	if r := x.idem(x.key, "POST", "/v1/services", "k-inflight", svc); r.code != http.StatusConflict || !strings.Contains(r.body, "in progress") {
		t.Fatalf("in-flight duplicate: %+v", r)
	}
	x.exec(claim, x.orgID, me["principal"], "k-dead", svcHash[:], ids.NewString(), "10 minutes")
	if r := x.idem(x.key, "POST", "/v1/services", "k-dead", svc); r.code != 200 || r.replayed {
		t.Fatalf("abandoned claim: %+v, want the retry to run", r)
	}
}

// Concurrent duplicates: exactly one runs.
func TestIdempotencyKeyConcurrentDuplicatesRunOnce(t *testing.T) {
	x := setupIngest(t, nil)
	x.call("POST", "/v1/teams", map[string]string{"slug": "payments"}, nil)
	body := `{"subject_type":"team","subject":"payments","role":"viewer"}`
	const n = 20
	var wg sync.WaitGroup
	results := make([]idemResponse, n)
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = x.idem(x.key, "POST", "/v1/role-bindings", "k-concurrent", body)
		}(i)
	}
	close(start)
	wg.Wait()
	executed, seen := 0, map[string]bool{}
	for _, r := range results {
		switch {
		case r.code == 200:
			if !r.replayed {
				executed++
			}
			var out map[string]string
			json.Unmarshal([]byte(r.body), &out)
			seen[out["id"]] = true
		case r.code == http.StatusConflict && strings.Contains(r.body, "in progress"):
		default:
			t.Fatalf("unexpected response %+v", r)
		}
	}
	if executed != 1 || len(seen) != 1 {
		t.Fatalf("%d executions and %d distinct bindings returned; want exactly 1 and 1: %+v", executed, len(seen), results)
	}
	if got := x.count(`SELECT count(*) FROM role_bindings WHERE role = 'viewer'`); got != 1 {
		t.Fatalf("%d bindings created", got)
	}
}
