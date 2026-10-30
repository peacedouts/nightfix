package e2e_test

// Generic OpenID Connect sign-in for a self-hosted deployment: keys come from
// the issuer's discovery document, every user of the issuer maps to one org,
// required claims keep out accounts that aren't the client's, and subjects
// are namespaced by issuer.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// oidcProvider serves a discovery document and JWKS over TLS, like a real
// provider, and mints tokens with auth0test's key.
func oidcProvider(t *testing.T) (*auth0test.Issuer, *httptest.Server) {
	idp := auth0test.New(t)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": idp.Kid, "use": "sig", "alg": "RS256",
				"n": b64url(idp.Key.N.Bytes()), "e": b64url(big.NewInt(int64(idp.Key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	idp.Issuer = srv.URL
	idp.Audience = "nightfix-client-id"
	return idp, srv
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestOIDCSignInMapsToOneOrg(t *testing.T) {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	idp, provider := oidcProvider(t)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Built before the server so the org id can go into its config.
	bootstrap := controlplane.New(pool, sealer, ca, controlplane.Config{}, log)
	org, err := bootstrap.CreateOrg(context.Background(), "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := bootstrap.CreateOrg(context.Background(), "Other", "other")

	verifier := auth0.NewOIDC(idp.Issuer, idp.Audience)
	verifier.Client = provider.Client()
	login := controlplane.Auth0Config{
		Verifier: verifier, EmailClaim: "email", GroupsClaim: "groups",
		OIDCOrgID: org.OrgID, RequiredClaims: map[string]string{"hd": "acme.example"}, SubjectPrefix: idp.Issuer,
		ClientIDs: []string{"nightfix-app"}, AllowedGroups: []string{"sre"},
	}
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{Auth0: login}, log)
	api := httptest.NewServer(srv.APIHandler())
	defer api.Close()

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
		out := map[string]any{}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	claims := func(sub, email string, extra map[string]any) map[string]any {
		c := map[string]any{"iss": idp.Issuer, "aud": idp.Audience, "azp": "nightfix-app", "sub": sub, "email": email, "email_verified": true,
			"hd": "acme.example", "exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"sre"}}
		for k, v := range extra {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		return c
	}
	mint := func(c map[string]any) string { return idp.Mint("RS256", c) }
	wantOrg := func(code int, me map[string]any, id string) {
		t.Helper()
		if code != 200 || !strings.Contains(stringify(me), "org_"+strings.ReplaceAll(id, "-", "")) {
			t.Fatalf("sign-in: %d %v, want org %s", code, me, id)
		}
	}

	// A user of the client's domain signs in, into the configured org, even
	// with a claim naming some other org.
	alice := mint(claims("1001", "alice@acme.example", map[string]any{"org_id": "org_" + strings.ReplaceAll(other.OrgID, "-", "")}))
	code, me := do(alice, "GET", "/v1/me", nil)
	wantOrg(code, me, org.OrgID)
	// Okta names the client in cid rather than azp.
	code, me = do(mint(claims("1002", "frank@acme.example", map[string]any{"azp": nil, "cid": "nightfix-app"})), "GET", "/v1/me", nil)
	wantOrg(code, me, org.OrgID)

	// Accounts outside the client: another Workspace domain, no domain at
	// all, the wrong audience, another issuer.
	for name, c := range map[string]map[string]any{
		"other domain":   claims("2001", "mallory@evil.example", map[string]any{"hd": "evil.example"}),
		"no domain":      claims("2002", "mallory@gmail.example", map[string]any{"hd": nil}),
		"wrong audience": claims("2003", "alice@acme.example", map[string]any{"aud": "some-other-app"}),
		"wrong issuer":   claims("2004", "alice@acme.example", map[string]any{"iss": "https://accounts.google.com"}),
		"unverified":     claims("2005", "bob@acme.example", map[string]any{"email_verified": false}),
		"no verify flag": claims("2006", "bob@acme.example", map[string]any{"email_verified": nil}),
		// Another application on the same authorization server, with the
		// same audience, replaying a user's token.
		"other client":         claims("2007", "alice@acme.example", map[string]any{"azp": "third-party-saas"}),
		"other client (cid)":   claims("2008", "alice@acme.example", map[string]any{"azp": nil, "cid": "third-party-saas"}),
		"no client claim":      claims("2009", "alice@acme.example", map[string]any{"azp": nil}),
		"two audiences no azp": claims("2010", "alice@acme.example", map[string]any{"aud": []string{idp.Audience, "other"}, "azp": nil, "cid": "nightfix-app"}),
		// Signed up at the IdP but in none of the allowed groups.
		"not in an allowed group": claims("2011", "eve@acme.example", map[string]any{"groups": []string{"contractors"}}),
	} {
		if code, out := do(mint(c), "GET", "/v1/me", nil); code != 401 {
			t.Errorf("%s: %d %v, want 401", name, code, out)
		}
	}

	// Subjects are namespaced by issuer, so another provider's "1001" could
	// never become alice.
	own := ownerConn(t, pool)
	var stored string
	if err := own.QueryRowContext(context.Background(), `SELECT auth0_sub FROM users WHERE email = 'alice@acme.example'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != idp.Issuer+"|1001" {
		t.Fatalf("stored subject %q, want it namespaced by the issuer", stored)
	}

	// With TrustEmail (an Entra ID tenant sends no email_verified), a token
	// without the claim signs in; one that says false still doesn't.
	trusting := login
	trusting.TrustEmail = true
	srv2 := controlplane.New(pool, sealer, ca, controlplane.Config{Auth0: trusting}, log)
	api2 := httptest.NewServer(srv2.APIHandler())
	defer api2.Close()
	api.Close()
	api = api2
	code, me = do(mint(claims("3001", "carol@acme.example", map[string]any{"email_verified": nil})), "GET", "/v1/me", nil)
	wantOrg(code, me, org.OrgID)
	if code, out := do(mint(claims("3002", "dan@acme.example", map[string]any{"email_verified": false})), "GET", "/v1/me", nil); code != 401 {
		t.Errorf("email_verified false with TrustEmail: %d %v, want 401", code, out)
	}

	// Members of the OIDC org can sign in, so an owner binding to one is a
	// usable owner credential: the bootstrap owner key can then be revoked.
	// In an org they can't sign in to, it isn't.
	if code, out := do(org.APIKey, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "alice@acme.example", "role": "owner"}); code != 200 {
		t.Fatalf("binding alice as owner: %d %v", code, out)
	}
	_, keys := do(org.APIKey, "GET", "/v1/api-keys", nil)
	keyID := keys["keys"].([]any)[0].(map[string]any)["id"].(string)
	if code, out := do(org.APIKey, "POST", "/v1/api-keys/"+keyID+"/revoke", nil); code != 200 {
		t.Fatalf("revoking the owner key with a signed-in owner in place: %d %v", code, out)
	}
	_, okeys := do(other.APIKey, "GET", "/v1/api-keys", nil)
	okeyID := okeys["keys"].([]any)[0].(map[string]any)["id"].(string)
	if code, out := do(other.APIKey, "POST", "/v1/api-keys/"+okeyID+"/revoke", nil); code != 409 {
		t.Fatalf("revoking the other org's last owner key: %d %v, want 409", code, out)
	}
}

func stringify(v any) string { b, _ := json.Marshal(v); return string(b) }
