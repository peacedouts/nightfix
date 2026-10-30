// Package auth0 verifies sign-in tokens (RS256 JWTs) from Auth0 or any
// OpenID Connect provider (Okta, Google, Entra ID, Keycloak…) against the
// issuer's JWKS. The identity provider handles authentication only;
// authorization is evaluated in the control plane (see docs/design/data-model.md §5,
// RBAC). The package keeps its first provider's name.
package auth0

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verifier checks tokens for one audience from one issuer.
type Verifier struct {
	Issuer   string // exactly as tokens carry it, e.g. https://<tenant>.us.auth0.com/
	Audience string // the API identifier or OIDC client ID
	JWKSURL  string // Auth0: defaults to <issuer>.well-known/jwks.json
	// Discover finds the JWKS through the issuer's OpenID Connect discovery
	// document (<issuer>/.well-known/openid-configuration), whose issuer
	// must match Issuer exactly. JWKSURL, if set, takes precedence.
	Discover bool
	Client   *http.Client
	Leeway   time.Duration

	discovered string // jwks_uri from discovery, once fetched

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time // last fetch attempt, successful or not
	lastErr   error

	fetchMu sync.Mutex // one JWKS fetch at a time
}

// JWKS refetch limits. The kid is read before the signature is checked, so
// anyone can send tokens with made-up kids; these bound how often that can
// make us call Auth0, including while Auth0 is failing.
const (
	jwksRefetchInterval = 30 * time.Second
	jwksRetryWithoutKey = 5 * time.Second // when no keys have ever loaded
)

// New builds a verifier for an Auth0 domain like "acme.us.auth0.com".
func New(domain, audience string) *Verifier {
	iss := "https://" + strings.TrimSuffix(strings.TrimPrefix(domain, "https://"), "/") + "/"
	return &Verifier{Issuer: iss, Audience: audience}
}

// NewOIDC builds a verifier for an OpenID Connect issuer, given exactly as
// its tokens' iss claim (e.g. https://accounts.google.com,
// https://acme.okta.com/oauth2/default,
// https://login.microsoftonline.com/<tenant>/v2.0).
func NewOIDC(issuer, audience string) *Verifier {
	return &Verifier{Issuer: issuer, Audience: audience, Discover: true}
}

// Claims are the verified token's claims.
type Claims map[string]any

// String returns a string claim or "".
func (c Claims) String(k string) string {
	s, _ := c[k].(string)
	return s
}

// Strings returns a string-array claim (or a single string as one element).
func (c Claims) Strings(k string) []string {
	switch v := c[k].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// LooksLikeJWT is a cheap pre-check for routing a bearer token.
func LooksLikeJWT(tok string) bool {
	return strings.Count(tok, ".") == 2 && strings.HasPrefix(tok, "eyJ")
}

var b64 = base64.RawURLEncoding

// Verify checks the signature, issuer, audience and time claims.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("malformed token header")
	}
	// Only RS256: never "none", never HMAC with a public key as the secret.
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("token algorithm %q is not accepted", hdr.Alg)
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed token signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("token signature is invalid")
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed token payload")
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, errors.New("malformed token payload")
	}
	if c.String("iss") != v.Issuer {
		return nil, errors.New("token issuer is not trusted")
	}
	audOK := false
	for _, a := range c.Strings("aud") {
		if a == v.Audience {
			audOK = true
		}
	}
	if !audOK {
		return nil, errors.New("token audience does not match this API")
	}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = time.Minute
	}
	now := time.Now()
	exp, ok := numClaim(c, "exp")
	if !ok {
		return nil, errors.New("token has no expiry")
	}
	if now.After(time.Unix(exp, 0).Add(leeway)) {
		return nil, errors.New("token expired")
	}
	if nbf, ok := numClaim(c, "nbf"); ok && now.Add(leeway).Before(time.Unix(nbf, 0)) {
		return nil, errors.New("token not valid yet")
	}
	if c.String("sub") == "" {
		return nil, errors.New("token has no subject")
	}
	return c, nil
}

func numClaim(c Claims, k string) (int64, bool) {
	n, ok := c[k].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil {
			return 0, false
		}
		i = int64(f)
	}
	return i, true
}

// key returns the signing key for kid. The JWKS is fetched again when an
// unknown kid appears (key rotation), and at least hourly, so a key the
// provider has withdrawn stops being trusted; both at most every 30 seconds.
// If a scheduled refresh fails, the keys already loaded keep working.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if k, ok, stale, err := v.cached(kid); (ok && !stale) || err != nil {
		return k, err
	}
	// Serialize fetches: concurrent requests with unknown kids share one.
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	old, ok, stale, err := v.cached(kid)
	if (ok && !stale) || err != nil {
		return old, err
	}
	v.mu.Lock()
	v.lastTry = time.Now()
	v.mu.Unlock()
	keys, err := v.fetch(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		v.lastErr = err
		if ok {
			return old, nil // a scheduled refresh failed: keep the keys we have
		}
		return nil, err
	}
	v.keys, v.fetchedAt, v.lastErr = keys, time.Now(), nil
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("token signed with an unknown key")
}

// jwksMaxAge is how long a fetched JWKS is used before it's fetched again.
const jwksMaxAge = time.Hour

// cached returns the key for kid if known, and whether the key set is due a
// refresh. ok=false with a nil error means a fetch is due; a non-nil error
// means one was tried too recently.
func (v *Verifier) cached(kid string) (key *rsa.PublicKey, ok, stale bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	recent := !v.lastTry.IsZero() && time.Since(v.lastTry) < jwksRefetchInterval
	if k, found := v.keys[kid]; found {
		return k, true, time.Since(v.fetchedAt) > jwksMaxAge && !recent, nil
	}
	wait := jwksRefetchInterval
	if v.keys == nil {
		wait = jwksRetryWithoutKey
	}
	if !v.lastTry.IsZero() && time.Since(v.lastTry) < wait {
		if v.lastErr != nil && v.keys == nil {
			return nil, false, false, v.lastErr
		}
		return nil, false, false, errors.New("token signed with an unknown key")
	}
	return nil, false, false, nil
}

func (v *Verifier) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: httpsOnly}
}

// httpsOnly refuses redirects off HTTPS (discovery and keys are fetched
// over HTTPS only).
func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("refusing a redirect to a non-https URL")
	}
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	return nil
}

// jwksURL returns where the keys are: JWKSURL, or the discovery document's
// jwks_uri (fetched once, under fetchMu), or Auth0's fixed path.
func (v *Verifier) jwksURL(ctx context.Context) (string, error) {
	switch {
	case v.JWKSURL != "":
		return v.JWKSURL, nil
	case !v.Discover:
		return v.Issuer + ".well-known/jwks.json", nil
	}
	v.mu.Lock()
	u := v.discovered
	v.mu.Unlock()
	if u != "" {
		return u, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(v.Issuer, "/")+"/.well-known/openid-configuration", nil)
	resp, err := v.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch OIDC discovery document: status %d", resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	// The document must be the issuer's own (OpenID Connect Discovery §4.3),
	// and keys only come over HTTPS.
	if doc.Issuer != v.Issuer {
		return "", fmt.Errorf("OIDC discovery document is for issuer %q, not %q", doc.Issuer, v.Issuer)
	}
	if !strings.HasPrefix(doc.JWKSURI, "https://") {
		return "", fmt.Errorf("OIDC discovery document's jwks_uri %q is not an https URL", doc.JWKSURI)
	}
	v.mu.Lock()
	v.discovered = doc.JWKSURI
	v.mu.Unlock()
	return doc.JWKSURI, nil
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	u, err := v.jwksURL(ctx)
	if err != nil {
		return nil, err
	}
	c := v.client()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nb, err1 := b64.DecodeString(k.N)
		eb, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() < 3 {
			continue
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	}
	return out, nil
}
