package auth0_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
)

func TestVerify(t *testing.T) {
	is := auth0test.New(t)
	v := &auth0.Verifier{Issuer: is.Issuer, Audience: is.Audience, JWKSURL: is.Srv.URL}
	base := func() map[string]any {
		return map[string]any{"iss": "https://tenant.example/", "aud": []string{"https://api.nightfix.dev", "other"},
			"sub": "auth0|u1", "exp": time.Now().Add(time.Hour).Unix(), "org_id": "org_abc"}
	}
	ctx := context.Background()
	c, err := v.Verify(ctx, is.Mint("RS256", base()))
	if err != nil || c.String("org_id") != "org_abc" {
		t.Fatalf("valid token rejected: %v", err)
	}

	cases := map[string]func(map[string]any) map[string]any{
		"expired":      func(m map[string]any) map[string]any { m["exp"] = time.Now().Add(-time.Hour).Unix(); return m },
		"wrong issuer": func(m map[string]any) map[string]any { m["iss"] = "https://evil.example/"; return m },
		"wrong aud":    func(m map[string]any) map[string]any { m["aud"] = "https://other.api"; return m },
		"no exp":       func(m map[string]any) map[string]any { delete(m, "exp"); return m },
		"no sub":       func(m map[string]any) map[string]any { delete(m, "sub"); return m },
	}
	for name, mut := range cases {
		if _, err := v.Verify(ctx, is.Mint("RS256", mut(base()))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// alg confusion and tampering
	if _, err := v.Verify(ctx, is.Mint("HS256", base())); err == nil {
		t.Error("HS256 accepted")
	}
	tok := is.Mint("RS256", base())
	parts := strings.Split(tok, ".")
	none := parts[0][:0] + base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	if _, err := v.Verify(ctx, none); err == nil {
		t.Error("alg none accepted")
	}
	tampered := base()
	tampered["org_id"] = "org_other"
	p, _ := json.Marshal(tampered)
	if _, err := v.Verify(ctx, parts[0]+"."+base64.RawURLEncoding.EncodeToString(p)+"."+parts[2]); err == nil {
		t.Error("tampered payload accepted")
	}
	// A token signed by a different key with the same kid.
	other := auth0test.New(t)
	if _, err := v.Verify(ctx, other.Mint("RS256", base())); err == nil {
		t.Error("foreign key accepted")
	}
}

// Unknown kids are attacker-controlled (they're read before the signature is
// checked), so they must not turn into a JWKS fetch per request — not when
// many arrive at once, and not while Auth0 is failing.
func TestJWKSFetchesAreBounded(t *testing.T) {
	var fetches atomic.Int32
	failing := atomic.Bool{}
	is := auth0test.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		resp, err := http.Get(is.Srv.URL)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	v := &auth0.Verifier{Issuer: is.Issuer, Audience: is.Audience, JWKSURL: proxy.URL}
	claims := map[string]any{"iss": is.Issuer, "aud": is.Audience, "sub": "auth0|u1", "exp": time.Now().Add(time.Hour).Unix()}
	ctx := context.Background()
	if _, err := v.Verify(ctx, is.Mint("RS256", claims)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	// 50 concurrent tokens with an unknown kid: one refetch at most.
	other := auth0test.New(t)
	fetches.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v.Verify(ctx, other.Mint("RS256", claims)) }()
	}
	wg.Wait()
	if n := fetches.Load(); n > 1 {
		t.Fatalf("%d JWKS fetches for 50 unknown-kid tokens, want at most 1", n)
	}

	// A fresh verifier while Auth0 is down: repeated requests don't each fetch.
	failing.Store(true)
	fetches.Store(0)
	down := &auth0.Verifier{Issuer: is.Issuer, Audience: is.Audience, JWKSURL: proxy.URL}
	for i := 0; i < 20; i++ {
		if _, err := down.Verify(ctx, is.Mint("RS256", claims)); err == nil {
			t.Fatal("token accepted with no keys")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d JWKS fetches during an outage, want 1", n)
	}
}

// OIDC discovery: keys come from the issuer's own discovery document, which
// must name the issuer exactly and point at HTTPS keys.
func TestOIDCDiscovery(t *testing.T) {
	idp := auth0test.New(t)
	var doc map[string]string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(doc)
		case "/keys":
			resp, err := http.Get(idp.Srv.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		}
	}))
	defer srv.Close()
	token := func() string {
		return idp.Mint("RS256", map[string]any{"iss": srv.URL, "aud": "client", "sub": "u1", "exp": time.Now().Add(time.Hour).Unix()})
	}
	verify := func() error {
		v := auth0.NewOIDC(srv.URL, "client")
		v.Client = srv.Client()
		_, err := v.Verify(context.Background(), token())
		return err
	}

	doc = map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"}
	if err := verify(); err != nil {
		t.Fatalf("valid discovery: %v", err)
	}
	for name, d := range map[string]map[string]string{
		"another issuer's document":    {"issuer": "https://evil.example", "jwks_uri": srv.URL + "/keys"},
		"issuer with a trailing slash": {"issuer": srv.URL + "/", "jwks_uri": srv.URL + "/keys"},
		"keys over plain http":         {"issuer": srv.URL, "jwks_uri": idp.Srv.URL},
		"no jwks_uri":                  {"issuer": srv.URL},
	} {
		doc = d
		if err := verify(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
