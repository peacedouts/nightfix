package e2e_test

// Independent review of fix/review-leftovers (PR #25). Each test fails on
// that branch and shows one bug.

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// lastOwnerCheck counts any owner binding to a team as "another way in as an
// owner", even a team with no members (and, in an org without Auth0, there
// can never be members). So the org's only owner key can be revoked, after
// which nobody can mint owner/admin keys or revoke admin keys: exactly the
// lockout the check is meant to prevent.
func TestReviewEmptyTeamOwnerBindingLetsLastOwnerKeyBeRevoked(t *testing.T) {
	do, owner := newKeyAPI(t)
	code, out := do(owner, "POST", "/v1/api-keys", map[string]string{"name": "ci", "role": "admin"})
	admin, _ := out["key"].(string)
	if code != 200 || admin == "" {
		t.Fatalf("mint admin key: %d %v", code, out)
	}
	var ownerID string
	_, list := do(owner, "GET", "/v1/api-keys", nil)
	for _, k := range list["keys"].([]any) {
		if m := k.(map[string]any); m["role"] == "owner" {
			ownerID = m["id"].(string)
		}
	}
	// A team nobody is (or, without Auth0, can be) a member of, bound as owner.
	if code, out := do(owner, "POST", "/v1/teams", map[string]string{"slug": "ghost"}); code != 200 {
		t.Fatalf("create team: %d %v", code, out)
	}
	if code, out := do(owner, "POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "ghost", "role": "owner"}); code != 200 {
		t.Fatalf("bind owner to team: %d %v", code, out)
	}
	code, out = do(owner, "POST", "/v1/api-keys/"+ownerID+"/revoke", nil)
	if code == 200 {
		// What's left: an admin key that can't mint an owner or admin key.
		c2, o2 := do(admin, "POST", "/v1/api-keys", map[string]string{"name": "new owner", "role": "owner"})
		t.Fatalf("the org's only owner key was revoked although the only other owner 'credential' is a team with no members "+
			"(revoke: %d %v); afterwards the remaining admin key minting an owner key gets %d %v: the org has no owner left",
			code, out, c2, o2)
	}
}

// The revoke endpoint judges a key only by its own role column. A key whose
// owner powers come from a role binding (POST /v1/role-bindings with an
// api_key subject, which the README documents) is treated as a viewer: an
// admin can revoke it, and lastOwnerCheck isn't run for it.
func TestReviewAdminCanRevokeKeyThatIsOwnerThroughBinding(t *testing.T) {
	do, owner := newKeyAPI(t)
	code, out := do(owner, "POST", "/v1/api-keys", map[string]string{"name": "ci", "role": "admin"})
	admin, _ := out["key"].(string)
	if code != 200 {
		t.Fatalf("mint admin key: %d %v", code, out)
	}
	code, out = do(owner, "POST", "/v1/api-keys", map[string]string{"name": "break-glass", "role": "viewer"})
	bgKey, _ := out["key"].(string)
	bgID, _ := out["id"].(string)
	if code != 200 {
		t.Fatalf("mint viewer key: %d %v", code, out)
	}
	if code, out := do(owner, "POST", "/v1/role-bindings", map[string]any{"subject_type": "api_key", "subject": bgID, "role": "owner"}); code != 200 {
		t.Fatalf("bind owner to key: %d %v", code, out)
	}
	// It is an owner: it can mint an owner key.
	if code, out := do(bgKey, "POST", "/v1/api-keys", map[string]string{"name": "probe", "role": "owner"}); code != 200 {
		t.Fatalf("the key with an owner binding should act as an owner: %d %v", code, out)
	}
	code, out = do(admin, "POST", "/v1/api-keys/"+bgID+"/revoke", nil)
	if code == 200 {
		t.Fatalf("an admin key revoked a key that holds an org-wide owner binding (%d %v); only an owner may revoke an owner credential", code, out)
	}
}

// Deleting a role binding is the other way to remove an owner: the org's
// last usable owner credential can't go that way either.
func TestLastOwnerBindingCantBeDeleted(t *testing.T) {
	do, owner := newKeyAPI(t)
	code, out := do(owner, "POST", "/v1/api-keys", map[string]string{"name": "break-glass", "role": "viewer"})
	bgKey, _ := out["key"].(string)
	bgID, _ := out["id"].(string)
	if code != 200 {
		t.Fatalf("mint viewer key: %d %v", code, out)
	}
	var bind map[string]any
	code, bind = do(owner, "POST", "/v1/role-bindings", map[string]any{"subject_type": "api_key", "subject": bgID, "role": "owner"})
	if code != 200 {
		t.Fatalf("bind owner to key: %d %v", code, bind)
	}
	// Rotate the bootstrap owner key out using the bound key.
	var ownerID string
	_, list := do(owner, "GET", "/v1/api-keys", nil)
	for _, k := range list["keys"].([]any) {
		if m := k.(map[string]any); m["role"] == "owner" {
			ownerID = m["id"].(string)
		}
	}
	if code, out := do(bgKey, "POST", "/v1/api-keys/"+ownerID+"/revoke", nil); code != 200 {
		t.Fatalf("revoking the bootstrap key while the bound key is an owner: %d %v", code, out)
	}
	// Now the binding is the last owner credential.
	if code, out := do(bgKey, "DELETE", "/v1/role-bindings/"+bind["id"].(string), nil); code != 409 {
		t.Fatalf("deleting the last owner binding: %d %v, want 409", code, out)
	}
	if code, out := do(bgKey, "DELETE", "/v1/role-bindings/rb_nonsense", nil); code != 404 {
		t.Fatalf("deleting a malformed binding id: %d %v, want 404", code, out)
	}
}

func newKeyAPI(t *testing.T) (func(tok, method, path string, body any) (int, map[string]any), string) {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{}, log)
	api := httptest.NewServer(srv.APIHandler())
	t.Cleanup(api.Close)
	org, err := srv.CreateOrg(context.Background(), "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	do := func(tok, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, api.URL+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		json.Unmarshal(raw, &out)
		if len(out) == 0 {
			out = map[string]any{"raw": string(raw)}
		}
		return resp.StatusCode, out
	}
	return do, org.APIKey
}

// Migration 0026 takes the org's nfx_ingest lock at session level and
// releases it in an EXCEPTION WHEN OTHERS handler. OTHERS doesn't catch
// QUERY_CANCELED, so a statement_timeout (now 60s for nfx_app, migration
// 0027) or a pg_cancel_backend landing between pg_try_advisory_lock and
// pg_advisory_unlock leaves the lock held by the pooled connection after the
// transaction rolls back. Every other connection's ingest for that org then
// waits 5s on pg_advisory_xact_lock_shared and fails, and every other claim
// skips the org, until that connection is closed.
func TestReviewCancelledClaimLeaksIngestLock(t *testing.T) {
	x := setupIngest(t, nil)
	ctx := context.Background()
	if code := x.send(map[string]any{"dedup_key": "A", "summary": "A down"}); code != 202 {
		t.Fatalf("ingest: %d", code)
	}
	app := appConn(t, x.srv.DB)
	target, err := app.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	killer, err := app.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer killer.Close()
	var pid int
	if err := target.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}

	// How long one claim takes, to aim the cancels.
	start := time.Now()
	for i := 0; i < 50; i++ {
		target.ExecContext(ctx, `BEGIN`)
		target.ExecContext(ctx, `SELECT * FROM nfx_claim_alert_event()`)
		target.ExecContext(ctx, `ROLLBACK`)
	}
	per := time.Since(start) / 150

	held := func() int {
		var n int
		for i := 0; i < 5; i++ {
			if err := target.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()`).Scan(&n); err == nil {
				return n
			}
		}
		t.Fatal("pg_locks check kept failing")
		return 0
	}
	rng := mrand.New(mrand.NewSource(1))
	cancels := 0
	for i := 0; i < 4000; i++ {
		if _, err := target.ExecContext(ctx, `BEGIN`); err != nil {
			target.ExecContext(ctx, `ROLLBACK`)
			continue
		}
		delay := time.Duration(rng.Int63n(int64(3 * per)))
		done := make(chan struct{})
		go func() {
			defer close(done)
			t0 := time.Now()
			for time.Since(t0) < delay {
			}
			killer.ExecContext(ctx, `SELECT pg_cancel_backend($1)`, pid)
		}()
		_, cerr := target.ExecContext(ctx, `SELECT * FROM nfx_claim_alert_event()`)
		<-done
		for j := 0; j < 5; j++ {
			if _, err := target.ExecContext(ctx, `ROLLBACK`); err == nil {
				break
			}
		}
		if cerr != nil {
			cancels++
		}
		if n := held(); n > 0 {
			// Show the impact: this org's ingest on any other connection fails.
			code, took := postSigned(x.ingest, x.secret, map[string]any{"dedup_key": "B", "summary": "B down"}, 15*time.Second)
			var stuck sql.NullString
			app.QueryRowContext(ctx, `SELECT state FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&stuck)
			t.Fatalf("after %d attempts (%d claims cancelled), the claim's connection (pid %d, now %q, no transaction open) still holds %d advisory lock(s): "+
				"the org's nfx_ingest lock leaked. An ingest for the org then returns %d after %v",
				i+1, cancels, pid, stuck.String, n, code, took.Round(time.Millisecond))
		}
	}
	t.Logf("no leak seen in 4000 attempts (%d claims cancelled, ~%v per claim)", cancels, per)
}

// Not a bug (passes): with 0026, several claimers and concurrent ingest never
// process one org's events concurrently or out of (received_at, id) order.
func TestReviewClaimKeepsPerOrgOrderUnderConcurrentIngest(t *testing.T) {
	x := setupIngest(t, nil)
	ctx := context.Background()
	app := appConn(t, x.srv.DB)
	stop := make(chan struct{})
	ingDone := make(chan struct{})
	go func() {
		defer close(ingDone)
		sem := make(chan struct{}, 6)
		for i := 0; ; i++ {
			select {
			case <-stop:
				for j := 0; j < cap(sem); j++ {
					sem <- struct{}{}
				}
				return
			case sem <- struct{}{}:
			}
			go func(i int) {
				defer func() { <-sem }()
				postSigned(x.ingest, x.secret, map[string]any{"dedup_key": "k", "summary": "s", "n": i}, 10*time.Second)
			}(i)
		}
	}()
	type span struct {
		id         string
		start, end time.Time
	}
	results := make(chan []span, 3)
	for w := 0; w < 3; w++ {
		go func() {
			var mine []span
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) || len(mine) == 0 {
				tx, err := app.BeginTx(ctx, nil)
				if err != nil {
					continue
				}
				var org, id string
				var at time.Time
				if err := tx.QueryRow(`SELECT org_id, id, received_at FROM nfx_claim_alert_event()`).Scan(&org, &id, &at); err != nil {
					tx.Rollback()
					time.Sleep(time.Millisecond)
					continue
				}
				s := span{id: id, start: time.Now()}
				tx.Exec(`SELECT set_config('app.org_id', $1, true)`, org)
				time.Sleep(time.Duration(mrand.Intn(3)) * time.Millisecond)
				if _, err := tx.Exec(`UPDATE alert_events SET processed_at = clock_timestamp() WHERE id = $1`, id); err != nil {
					tx.Rollback()
					continue
				}
				s.end = time.Now()
				if tx.Commit() == nil {
					mine = append(mine, s)
				}
			}
			results <- mine
		}()
	}
	var all []span
	for w := 0; w < 3; w++ {
		all = append(all, <-results...)
	}
	close(stop)
	<-ingDone
	// Overlap check (wall clock, conservative: commit happens after end).
	for i := range all {
		for j := range all {
			if i != j && all[i].start.Before(all[j].start) && all[j].start.Before(all[i].end) {
				t.Errorf("events %s and %s of one org were processed concurrently", all[i].id, all[j].id)
			}
		}
	}
	admin := adminDB(t, x.srv.DB)
	var bad, n int
	admin.QueryRow(`SET ROLE nfx_owner`)
	if err := admin.QueryRow(`WITH p AS (SELECT id, processed_at, row_number() OVER (ORDER BY received_at, id) AS r_recv,
			row_number() OVER (ORDER BY processed_at) AS r_proc FROM alert_events WHERE processed_at IS NOT NULL)
		SELECT count(*) FILTER (WHERE r_recv <> r_proc), count(*) FROM p`).Scan(&bad, &n); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events processed by 3 claimers during concurrent ingest; %d out of order", n, bad)
	if bad > 0 {
		t.Fatalf("%d of %d events were processed out of received order", bad, n)
	}
}

// Measurement: how often the claim's try-lock finds no ingest of the org in
// progress while that org is being ingested continuously.
func TestReviewClaimUnderSustainedIngest(t *testing.T) {
	x := setupIngest(t, nil)
	ctx := context.Background()
	app := appConn(t, x.srv.DB)
	if os.Getenv("REVIEW_CLAIM_0023") != "" {
		// Compare with main: put back 0023's claim (lock held until commit).
		raw, err := os.ReadFile("../../migrations/0023_alert_event_ordering.sql")
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		fn := src[strings.Index(src, "CREATE OR REPLACE FUNCTION nfx_claim_alert_event()"):]
		fn = fn[:strings.Index(fn, "END $$;")+len("END $$;")]
		admin := adminDB(t, x.srv.DB)
		if _, err := admin.Exec("SET ROLE nfx_owner; " + fn); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 50; i++ { // backlog
		x.send(map[string]any{"dedup_key": "k", "summary": "s", "b": i})
	}
	stop := make(chan struct{})
	ingDone := make(chan int)
	go func() {
		n, seq := 0, 0
		res := make(chan int, 16)
		running := 0
		for {
			select {
			case <-stop:
				for ; running > 0; running-- {
					n += <-res
				}
				ingDone <- n
				return
			default:
			}
			if running < 16 {
				running++
				seq++
				go func(seq int) {
					c, _ := postSigned(x.ingest, x.secret, map[string]any{"dedup_key": "k", "summary": "s", "n": seq}, 10*time.Second)
					if c == 202 {
						res <- 1
					} else {
						res <- 0
					}
				}(seq)
			} else {
				n += <-res
				running--
			}
		}
	}()
	claimed, empty := 0, 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tx, _ := app.BeginTx(ctx, nil)
		var org, id string
		var at time.Time
		if err := tx.QueryRow(`SELECT org_id, id, received_at FROM nfx_claim_alert_event()`).Scan(&org, &id, &at); err != nil {
			tx.Rollback()
			empty++
			continue
		}
		tx.Exec(`SELECT set_config('app.org_id', $1, true)`, org)
		tx.Exec(`UPDATE alert_events SET processed_at = clock_timestamp() WHERE id = $1`, id)
		tx.Commit()
		claimed++
	}
	close(stop)
	ingested := <-ingDone
	t.Logf("during 3s of ingest (%d stored): %d events claimed, %d claim calls returned nothing although >= 50 events were waiting",
		ingested, claimed, empty)
	// The claim must keep up with a continuously ingested org (it used to
	// claim almost nothing: its try-lock lost to the stream of ingests).
	if claimed < 50 {
		t.Fatalf("only %d events claimed in 3s while the org was ingested continuously", claimed)
	}
}
