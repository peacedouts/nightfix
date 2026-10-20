// Package auth0test is a fake Auth0 tenant for tests: it serves a JWKS and
// mints RS256 access tokens.
package auth0test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// Issuer is a fake tenant.
type Issuer struct {
	Key      *rsa.PrivateKey
	Kid      string
	Srv      *httptest.Server
	Issuer   string
	Audience string
}

// New starts a fake tenant whose JWKS is served at Srv.URL.
func New(t testing.TB) *Issuer {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	is := &Issuer{Key: key, Kid: "test-key-1", Issuer: "https://tenant.example/", Audience: "https://api.lightning.ir"}
	is.Srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": is.Kid, "use": "sig", "alg": "RS256",
			"n": b64.EncodeToString(is.Key.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(is.Key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(is.Srv.Close)
	return is
}

// Mint signs claims with the given alg header (always RS256-signed).
func (is *Issuer) Mint(alg string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": is.Kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, is.Key, crypto.SHA256, sum[:])
	return signing + "." + b64.EncodeToString(sig)
}

// UserToken mints a typical access token for a user in an Auth0 Organization.
func (is *Issuer) UserToken(sub, email, auth0Org string, groups ...string) string {
	return is.Mint("RS256", map[string]any{
		"iss": is.Issuer, "aud": []string{is.Audience}, "sub": sub, "org_id": auth0Org,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"https://lightning.ir/email": email, "https://lightning.ir/groups": groups,
	})
}
