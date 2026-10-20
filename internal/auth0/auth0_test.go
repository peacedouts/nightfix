package auth0_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
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
