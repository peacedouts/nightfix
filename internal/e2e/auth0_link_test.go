package e2e_test

// Linking an Auth0 Organization is an operator step, not an owner's API
// call. Auth0 Organization ids aren't secret (they're in every member's
// access token and in login links), so if an org's owner could claim any
// unlinked id, org B could link org A's Auth0 Organization first and A's
// people would sign in to B.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

func TestAuth0OrganizationCannotBeClaimedByAnotherOrg(t *testing.T) {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	idp := auth0test.New(t)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{Auth0: controlplane.Auth0Config{Verifier: &auth0.Verifier{
		Issuer: idp.Issuer, Audience: idp.Audience, JWKSURL: idp.Srv.URL}}}, log)
	api := httptest.NewServer(srv.APIHandler())
	defer api.Close()
	victim, _ := srv.CreateOrg(context.Background(), "Victim", "victim")
	attacker, _ := srv.CreateOrg(context.Background(), "Attacker", "attacker")
	do := func(tok, method, path string, body any) (int, string) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, api.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}

	// The attacker's owner key tries to claim the victim's Auth0 Organization:
	// linking through the API is off in production.
	code, out := do(attacker.APIKey, "PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_victimAuth0"})
	if code != 403 {
		t.Fatalf("an org owner linked an Auth0 organization through the API: %d %s", code, out)
	}
	alice := idp.UserToken("auth0|alice", "alice@victim.example", "org_victimAuth0", "victim-sre-oncall")
	if code, me := do(alice, "GET", "/v1/me", nil); code != 401 {
		t.Fatalf("a user of an unlinked Auth0 organization signed in: %d %s", code, me)
	}

	// The operator links it for the victim; the victim's people land there.
	if err := srv.LinkAuth0(context.Background(), victim.OrgID, "org_victimAuth0", "operator", "cli"); err != nil {
		t.Fatal(err)
	}
	code, me := do(alice, "GET", "/v1/me", nil)
	if code != 200 || !strings.Contains(me, "org_"+strings.ReplaceAll(victim.OrgID, "-", "")) {
		t.Fatalf("after the operator linked it: %d %s", code, me)
	}
	if err := srv.LinkAuth0(context.Background(), attacker.OrgID, "org_victimAuth0", "operator", "cli"); err == nil {
		t.Fatal("one Auth0 organization was linked to two orgs")
	}
}
