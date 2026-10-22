package agent

// Certificate lifecycle on the agent: renewal at 2/3 of the lifetime, what
// happens when renewal fails or is refused, expiry, re-enrollment, and the
// identity file. The tests run the agent against tlsGateway, a fake gateway
// that verifies client certificates the way the control plane does
// (VerifyClientCertIfGiven against its CA, then the handler checks the chain).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
)

type tlsGateway struct {
	t     *testing.T
	srv   *httptest.Server
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	caPEM []byte // the server's certificate, for the agent's CAPEM
	agent atomic.Int32
	seq   atomic.Int64

	mu       sync.Mutex
	calls    map[string]int
	serials  map[string][]string // per path: the client certificate serial of each call ("" for none)
	lifetime time.Duration       // of certificates issued by enroll and renew
	// hook handles a request first; it returns true if it wrote a response.
	hook func(w http.ResponseWriter, r *http.Request, n int) bool
}

func newTLSGateway(t *testing.T) *tlsGateway {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test agent CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	g := &tlsGateway{t: t, ca: ca, caKey: key, calls: map[string]int{}, serials: map[string][]string{}, lifetime: 24 * time.Hour}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	g.srv = httptest.NewUnstartedServer(g)
	g.srv.TLS = &tls.Config{ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	g.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.srv.Certificate().Raw})
	return g
}

// issue signs a client certificate for pub valid from notBefore to notAfter.
func (g *tlsGateway) issue(pub any, agentID string, notBefore, notAfter time.Time) string {
	g.t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(g.seq.Add(1) + 100), Subject: pkix.Name{CommonName: agentID},
		NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.ca, pub, g.caKey)
	if err != nil {
		g.t.Error(err)
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (g *tlsGateway) issueForCSR(csrPEM, agentID string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		g.t.Error("no CSR")
		return ""
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		g.t.Errorf("bad CSR: %v", err)
		return ""
	}
	g.mu.Lock()
	life := g.lifetime
	g.mu.Unlock()
	now := time.Now()
	return g.issue(csr.PublicKey, agentID, now.Add(-time.Second), now.Add(life))
}

// identity enrolls an identity out of band: a key and a certificate for it
// valid from notBefore to notAfter.
func (g *tlsGateway) identity(agentID string, notBefore, notAfter time.Time) *identity {
	g.t.Helper()
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		g.t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	return &identity{AgentID: agentID, OrgID: "org_x", Labels: map[string]string{"env": "prod"},
		CertPEM: g.issue(csr.PublicKey, agentID, notBefore, notAfter), KeyPEM: keyPEM}
}

func (g *tlsGateway) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[path]
}

func (g *tlsGateway) lastSerial(path string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.serials[path]
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func (g *tlsGateway) setHook(h func(w http.ResponseWriter, r *http.Request, n int) bool) {
	g.mu.Lock()
	g.hook = h
	g.mu.Unlock()
}

func (g *tlsGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var leaf *x509.Certificate
	if len(r.TLS.VerifiedChains) > 0 {
		leaf = r.TLS.VerifiedChains[0][0]
	}
	serial := ""
	if leaf != nil {
		serial = leaf.SerialNumber.String()
	}
	g.mu.Lock()
	g.calls[r.URL.Path]++
	n := g.calls[r.URL.Path]
	g.serials[r.URL.Path] = append(g.serials[r.URL.Path], serial)
	hook := g.hook
	g.mu.Unlock()
	if hook != nil && hook(w, r, n) {
		return
	}
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/agent/v1/enroll/challenge":
		reply(agentapi.ChallengeResponse{Nonce: "nonce"})
		return
	case "/agent/v1/enroll":
		var req agentapi.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		id := fmt.Sprintf("agent-%d", g.agent.Add(1)+1) // agent-1 is the tests' out-of-band identity
		reply(agentapi.EnrollResponse{AgentID: id, OrgID: "org_x", CertPEM: g.issueForCSR(req.CSRPEM, id),
			Labels: map[string]string{"env": "prod"}})
		return
	}
	if leaf == nil {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/agent/v1/renew":
		var req agentapi.RenewRequest
		json.NewDecoder(r.Body).Decode(&req)
		reply(agentapi.RenewResponse{CertPEM: g.issueForCSR(req.CSRPEM, leaf.Subject.CommonName)})
	case "/agent/v1/hello":
		reply(agentapi.Welcome{AgentID: leaf.Subject.CommonName, Labels: map[string]string{"env": "prod"}})
	case "/agent/v1/poll":
		time.Sleep(20 * time.Millisecond) // a (very) short long-poll
		reply(agentapi.PollResponse{})
	default:
		w.Write([]byte("{}"))
	}
}

// fastRenewChecks makes renewLoop look at the certificate every d.
func fastRenewChecks(t *testing.T, d time.Duration) {
	old := renewCheckInterval
	renewCheckInterval = d
	t.Cleanup(func() { renewCheckInterval = old })
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testLog logs through t (shown for failing tests, and with -v).
func testLog(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(tWriter{t}, nil))
}

type tWriter struct{ t *testing.T }

func (w tWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// startAgent runs an IAM agent whose state dir holds id until the test ends.
func (g *tlsGateway) startAgent(t *testing.T, id *identity, method string) (*Agent, string, <-chan error) {
	t.Helper()
	dir := t.TempDir()
	if id != nil {
		if err := saveIdentity(dir, id); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{Endpoint: g.srv.URL, CAPEM: g.caPEM, EnrollMethod: method, OrgID: "org_x", IAM: fakeIAM{}, StateDir: dir, Log: testLog(t)}
	if method == "token" {
		cfg.EnrollToken = "nfxenroll_x"
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, stopped := make(chan error, 1), make(chan struct{})
	go func() { done <- a.Run(ctx); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return a, dir, done
}

func certSerial(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber.String()
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRenewDue(t *testing.T) {
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(24 * time.Hour)
	for _, c := range []struct {
		now  time.Duration // after issued
		want bool
	}{
		{0, false}, {time.Hour, false}, {16*time.Hour - time.Second, false},
		{16 * time.Hour, true}, {20 * time.Hour, true}, {25 * time.Hour, true},
		{-time.Hour, false}, // clock behind NotBefore
	} {
		if got := renewDue(issued, expires, issued.Add(c.now)); got != c.want {
			t.Errorf("renewDue at +%v = %v, want %v", c.now, got, c.want)
		}
	}
	if renewDue(time.Time{}, time.Time{}, time.Now()) {
		t.Error("renewal due without a certificate")
	}
}

func TestCertExpiry(t *testing.T) {
	c, err := newClient("https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if issued, expires := c.certExpiry(); !issued.IsZero() || !expires.IsZero() {
		t.Fatalf("no certificate yet, got %v %v", issued, expires)
	}
	if c.certExpired(time.Now()) {
		t.Fatal("no certificate is not an expired one")
	}
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	cert, key := certPair(t, notAfter)
	if err := c.setCert(cert, key); err != nil {
		t.Fatal(err)
	}
	issued, expires := c.certExpiry()
	if !expires.Equal(notAfter) || !issued.Equal(notAfter.Add(-24*time.Hour)) {
		t.Fatalf("got %v – %v, want %v – %v", issued, expires, notAfter.Add(-24*time.Hour), notAfter)
	}
	if c.certExpired(time.Now()) || !c.certExpired(notAfter.Add(time.Second)) {
		t.Fatal("certExpired is wrong")
	}
	if err := c.setCert(cert, "not a key"); err == nil {
		t.Fatal("a mismatched key was accepted")
	}
	if _, e := c.certExpiry(); !e.Equal(notAfter) {
		t.Fatal("a failed setCert replaced the certificate")
	}
}

// renew sends a fresh CSR, and the certificate that comes back goes with
// the new key, not the old one.
func TestRenewUsesANewKey(t *testing.T) {
	g := newTLSGateway(t)
	id := g.identity("agent-1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	c, err := newClient(g.srv.URL, g.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.setCert(id.CertPEM, id.KeyPEM); err != nil {
		t.Fatal(err)
	}
	cert, key, err := c.renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if key == id.KeyPEM {
		t.Fatal("renewal reused the private key")
	}
	if err := c.setCert(cert, key); err != nil {
		t.Fatalf("renewed certificate doesn't match the new key: %v", err)
	}
	if g.lastSerial("/agent/v1/renew") != certSerial(t, id.CertPEM) {
		t.Fatal("renewal wasn't authenticated with the current certificate")
	}

	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		http.Error(w, `{"error":"the enrollment rule for this agent has been revoked"}`, http.StatusForbidden)
		return true
	})
	_, _, err = c.renew(context.Background())
	var se *statusError
	if !errors.As(err, &se) || se.Code != http.StatusForbidden || !strings.Contains(se.Msg, "revoked") {
		t.Fatalf("got %v, want the 403 with its message", err)
	}
}

func TestRenewLoopRenewsAtTwoThirds(t *testing.T) {
	fastRenewChecks(t, 20*time.Millisecond)
	g := newTLSGateway(t)
	now := time.Now()
	old := g.identity("agent-1", now.Add(-17*time.Hour), now.Add(7*time.Hour)) // 17h of 24h gone
	a, dir, _ := g.startAgent(t, old, "iam")

	waitFor(t, 5*time.Second, "a renewal", func() bool { return g.count("/agent/v1/renew") > 0 })
	waitFor(t, 5*time.Second, "the renewed certificate on disk", func() bool {
		id, err := loadIdentity(dir)
		return err == nil && id.CertPEM != old.CertPEM
	})
	saved, _ := loadIdentity(dir)
	if saved.KeyPEM == old.KeyPEM || saved.AgentID != "agent-1" {
		t.Fatalf("saved identity: agent %s, key changed %v", saved.AgentID, saved.KeyPEM != old.KeyPEM)
	}
	assertPrivate(t, filepath.Join(dir, "identity.json"))
	newSerial := certSerial(t, saved.CertPEM)
	waitFor(t, 5*time.Second, "a poll with the new certificate", func() bool { return g.lastSerial("/agent/v1/poll") == newSerial })
	// The new certificate is fresh: no more renewals.
	n := g.count("/agent/v1/renew")
	time.Sleep(200 * time.Millisecond)
	if g.count("/agent/v1/renew") != n || n != 1 {
		t.Fatalf("%d renewals, want 1", g.count("/agent/v1/renew"))
	}
	if g.count("/agent/v1/enroll") != 0 || a.ID() != "agent-1" {
		t.Fatalf("renewal re-enrolled (agent %s)", a.ID())
	}
}

// Like the control plane, the gateway retires the old certificate the first
// time it sees the renewed one. A kept-alive connection that was busy (a
// long poll) during the renewal must not carry requests with the old
// certificate afterwards: they'd be refused, and the agent would take that
// as a revoked identity and re-enroll (or, enrolled by token, stop).
func TestRenewedCertificateIsUsedOnEveryConnection(t *testing.T) {
	fastRenewChecks(t, 50*time.Millisecond)
	g := newTLSGateway(t)
	var mu sync.Mutex
	newest := map[string]int64{} // agent -> newest serial seen
	var stale atomic.Int32
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if len(r.TLS.VerifiedChains) == 0 {
			return false
		}
		leaf := r.TLS.VerifiedChains[0][0]
		cn, serial := leaf.Subject.CommonName, leaf.SerialNumber.Int64()
		mu.Lock()
		if serial > newest[cn] {
			newest[cn] = serial
		}
		retired := serial < newest[cn]
		mu.Unlock()
		if retired {
			stale.Add(1)
			http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
			return true
		}
		if r.URL.Path == "/agent/v1/poll" {
			time.Sleep(300 * time.Millisecond) // long poll: the connection is busy during renewal
		}
		return false
	})
	now := time.Now()
	a, dir, _ := g.startAgent(t, g.identity("agent-1", now.Add(-20*time.Hour), now.Add(4*time.Hour)), "iam")
	waitFor(t, 5*time.Second, "a renewal", func() bool {
		id, err := loadIdentity(dir)
		return err == nil && g.count("/agent/v1/renew") > 0 && certSerial(t, id.CertPEM) != "101"
	})
	// Heartbeats (every 10s in production) run alongside the long poll, so
	// one goes out on a new connection: with the renewed certificate, which
	// retires the old one. Send a few, then let the polls continue.
	for i := 0; i < 5; i++ {
		if err := a.c.post(context.Background(), "/agent/v1/heartbeat", agentapi.Heartbeat{}, nil); err != nil {
			t.Logf("heartbeat: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(time.Second) // several more polls
	if n := stale.Load(); n > 0 {
		t.Errorf("%d requests were sent with the replaced certificate", n)
	}
	if a.ID() != "agent-1" || g.count("/agent/v1/enroll") != 0 {
		t.Fatalf("renewal led to re-enrollment (agent %s, %d enrollments)", a.ID(), g.count("/agent/v1/enroll"))
	}
}

func TestRenewLoopWaitsUntilTwoThirds(t *testing.T) {
	fastRenewChecks(t, 10*time.Millisecond)
	g := newTLSGateway(t)
	now := time.Now()
	g.startAgent(t, g.identity("agent-1", now.Add(-15*time.Hour), now.Add(9*time.Hour)), "iam") // 15h of 24h
	waitFor(t, 5*time.Second, "polling", func() bool { return g.count("/agent/v1/poll") > 2 })
	time.Sleep(200 * time.Millisecond)
	if n := g.count("/agent/v1/renew"); n != 0 {
		t.Fatalf("renewed %d times before 2/3 of the lifetime", n)
	}
}

// A failed renewal is retried at the check interval, not in a loop, and the
// agent keeps working with its current certificate meanwhile.
func TestRenewalFailureIsRetried(t *testing.T) {
	interval := 50 * time.Millisecond
	fastRenewChecks(t, interval)
	g := newTLSGateway(t)
	var times []time.Time
	var mu sync.Mutex
	g.setHook(func(w http.ResponseWriter, r *http.Request, n int) bool {
		if r.URL.Path != "/agent/v1/renew" {
			return false
		}
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		if n <= 3 {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return true
		}
		return false
	})
	now := time.Now()
	old := g.identity("agent-1", now.Add(-20*time.Hour), now.Add(4*time.Hour))
	_, dir, _ := g.startAgent(t, old, "iam")
	waitFor(t, 5*time.Second, "the renewed certificate on disk", func() bool {
		id, err := loadIdentity(dir)
		return err == nil && id.CertPEM != old.CertPEM
	})
	mu.Lock()
	defer mu.Unlock()
	if len(times) != 4 {
		t.Fatalf("%d renewal attempts, want 4 (3 failures, then success)", len(times))
	}
	for i := 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap < interval/2 {
			t.Errorf("retry %d came %v after the previous one; the check interval is %v", i, gap, interval)
		}
	}
	if g.count("/agent/v1/enroll") != 0 {
		t.Fatal("a failed renewal made the agent re-enroll")
	}
}

// The control plane refuses renewal (403) once the agent's enrollment rule is
// revoked. The agent keeps retrying at the check interval while its
// certificate is valid, then re-enrolls when it expires: the gateway only
// checks certificates when a connection opens, so the agent must notice the
// expiry itself rather than keep using a kept-alive connection.
func TestRefusedRenewalReenrollsAtExpiry(t *testing.T) {
	interval := 100 * time.Millisecond
	fastRenewChecks(t, interval)
	g := newTLSGateway(t)
	var refused atomic.Int32
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path == "/agent/v1/renew" && len(r.TLS.VerifiedChains) > 0 && r.TLS.VerifiedChains[0][0].Subject.CommonName == "agent-1" {
			refused.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"the enrollment rule for this agent has been revoked; re-enroll it under an active rule"}`))
			return true
		}
		return false
	})
	now := time.Now()
	expiry := now.Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
	old := g.identity("agent-1", now.Add(-10*time.Second), expiry)
	a, dir, _ := g.startAgent(t, old, "iam")

	waitFor(t, 10*time.Second, "re-enrollment after expiry", func() bool { return a.ID() == "agent-2" })
	if time.Now().Before(expiry) {
		t.Fatalf("re-enrolled before the certificate expired")
	}
	// Retried at the interval while valid (about 3s / 100ms), not in a loop.
	if n := refused.Load(); n < 3 || n > 60 {
		t.Errorf("%d refused renewals before expiry; want one per check interval", n)
	}
	time.Sleep(300 * time.Millisecond)
	if n := g.count("/agent/v1/enroll"); n != 1 {
		t.Fatalf("enrolled %d times, want once", n)
	}
	saved, err := loadIdentity(dir)
	if err != nil || saved.AgentID != "agent-2" || saved.expired(time.Now()) {
		t.Fatalf("saved identity after re-enrollment: %+v, %v", saved, err)
	}
	if s := g.lastSerial("/agent/v1/poll"); s != certSerial(t, saved.CertPEM) {
		t.Fatalf("still polling with serial %s", s)
	}
}

// A token-enrolled agent can't re-enroll itself: at expiry it stops.
func TestTokenAgentStopsAtExpiry(t *testing.T) {
	fastRenewChecks(t, 100*time.Millisecond)
	g := newTLSGateway(t)
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path == "/agent/v1/renew" {
			http.Error(w, `{"error":"the enrollment rule for this agent has been revoked"}`, http.StatusForbidden)
			return true
		}
		return false
	})
	now := time.Now()
	_, _, done := g.startAgent(t, g.identity("agent-1", now.Add(-10*time.Second), now.Add(1500*time.Millisecond)), "token")
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "new token") || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("got %v, want a clear re-enroll error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("token agent kept running past its certificate's expiry")
	}
	if g.count("/agent/v1/enroll") != 0 {
		t.Fatal("token agent tried to enroll again")
	}
}

// If the identity the agent just enrolled is rejected too (a misconfigured
// gateway, or an enrollment that's revoked at once), the agent must back off
// instead of enrolling, and using up an agent slot, in a tight loop.
func TestRejectedAfterReenrollmentBacksOff(t *testing.T) {
	g := newTLSGateway(t)
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path == "/agent/v1/hello" {
			http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
			return true
		}
		return false
	})
	now := time.Now()
	a, _, _ := g.startAgent(t, g.identity("agent-1", now.Add(-time.Hour), now.Add(time.Hour)), "iam")
	// ID is read while Run replaces the identity (run with -race).
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				a.ID()
			}
		}
	}()
	time.Sleep(3 * time.Second)
	close(stop)
	// Backoff 0.5–1s, 1–2s, …: at most 4 enrollments in 3s.
	if n := g.count("/agent/v1/enroll"); n == 0 || n > 4 {
		t.Fatalf("%d enrollments in 3s", n)
	}
}

// A revoked agent's polls are refused (403) while hello may still work.
// Retrying must back off rather than hello+poll every second forever.
func TestRefusedPollsBackOff(t *testing.T) {
	g := newTLSGateway(t)
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path == "/agent/v1/poll" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"agent revoked"}`))
			return true
		}
		return false
	})
	now := time.Now()
	g.startAgent(t, g.identity("agent-1", now.Add(-time.Hour), now.Add(time.Hour)), "iam")
	time.Sleep(4 * time.Second)
	// Sleeps of 0.5–1s, 1–2s, 2–4s: at most 4 polls in 4s. Without backoff
	// (reset by every successful hello) it was one every 0.5–1s.
	if n := g.count("/agent/v1/poll"); n == 0 || n > 4 {
		t.Fatalf("%d polls in 4s", n)
	}
}

// A renewal that finishes after the agent re-enrolled belongs to the old
// identity and must not replace the new identity's certificate.
func TestLateRenewalAfterReenrollmentIsDiscarded(t *testing.T) {
	fastRenewChecks(t, 20*time.Millisecond)
	g := newTLSGateway(t)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock) // before the gateway closes: it waits for blocked handlers
	renewing := make(chan struct{}, 1)
	var reject atomic.Bool
	g.setHook(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		cn := r.TLS.VerifiedChains
		switch {
		case r.URL.Path == "/agent/v1/renew" && len(cn) > 0 && cn[0][0].Subject.CommonName == "agent-1":
			select {
			case renewing <- struct{}{}:
			default:
			}
			<-release
			return false // issue the (now stale) certificate for agent-1
		case r.URL.Path == "/agent/v1/poll" && reject.Load() && len(cn) > 0 && cn[0][0].Subject.CommonName == "agent-1":
			http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
			return true
		case r.URL.Path == "/agent/v1/hello" && reject.Load() && len(cn) > 0 && cn[0][0].Subject.CommonName == "agent-1":
			http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
			return true
		}
		return false
	})
	now := time.Now()
	a, dir, _ := g.startAgent(t, g.identity("agent-1", now.Add(-20*time.Hour), now.Add(4*time.Hour)), "iam")
	select {
	case <-renewing:
	case <-time.After(5 * time.Second):
		t.Fatal("no renewal")
	}
	reject.Store(true) // agent-1 is revoked while its renewal is in flight
	waitFor(t, 10*time.Second, "re-enrollment", func() bool { return a.ID() == "agent-2" })
	unblock()
	time.Sleep(300 * time.Millisecond)
	if a.ID() != "agent-2" {
		t.Fatalf("agent is %s", a.ID())
	}
	saved, _ := loadIdentity(dir)
	_, exp := a.c.certExpiry()
	block, _ := pem.Decode([]byte(saved.CertPEM))
	savedCert, _ := x509.ParseCertificate(block.Bytes)
	a.mu.Lock()
	inMemory := a.id.CertPEM
	a.mu.Unlock()
	if savedCert.Subject.CommonName != "agent-2" || inMemory != saved.CertPEM || !exp.Equal(savedCert.NotAfter) {
		t.Fatalf("the old identity's renewed certificate replaced agent-2's (saved for %s)", savedCert.Subject.CommonName)
	}
	if s := g.lastSerial("/agent/v1/poll"); s != savedCert.SerialNumber.String() {
		t.Fatalf("polling with serial %s, want agent-2's %s", s, savedCert.SerialNumber)
	}
}

// identityRejected must tell "this certificate is no good" from an outage,
// including the TLS alerts a gateway sends for a certificate it won't take.
func TestIdentityRejected(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&statusError{401, "unknown or revoked agent certificate"}, true},
		{fmt.Errorf("enroll: %w", &statusError{401, "x"}), true},
		{errCertExpired, true},
		{fmt.Errorf("hello: %w", errCertExpired), true},
		{&statusError{403, "agent revoked"}, false},
		{&statusError{500, "internal error"}, false},
		{&statusError{503, ""}, false},
		{errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), false},
		{context.DeadlineExceeded, false},
		{errors.New("remote error: tls: expired certificate"), true},
		{errors.New("remote error: tls: bad certificate"), true},
		{errors.New("remote error: tls: unknown certificate authority"), true},
		{errors.New("remote error: tls: certificate required"), true},
		{errors.New("remote error: tls: internal error"), false},
	} {
		if got := identityRejected(c.err); got != c.want {
			t.Errorf("identityRejected(%v) = %v, want %v", c.err, got, c.want)
		}
	}

	// The alerts a real TLS 1.3 gateway sends.
	g := newTLSGateway(t)
	other := newTLSGateway(t) // a different CA
	now := time.Now()
	for name, id := range map[string]*identity{
		"expired":    g.identity("a", now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not yet":    g.identity("a", now.Add(time.Hour), now.Add(2*time.Hour)),
		"foreign CA": other.identity("a", now.Add(-time.Hour), now.Add(time.Hour)),
	} {
		c, err := newClient(g.srv.URL, g.caPEM)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.setCert(id.CertPEM, id.KeyPEM); err != nil {
			t.Fatal(err)
		}
		err = c.post(context.Background(), "/agent/v1/hello", agentapi.Hello{}, nil)
		if err == nil || !identityRejected(err) {
			t.Errorf("%s certificate: error %v not recognised as a rejected identity", name, err)
		}
	}
	// No certificate at all: the gateway answers 401.
	c, _ := newClient(g.srv.URL, g.caPEM)
	if err := c.post(context.Background(), "/agent/v1/hello", agentapi.Hello{}, nil); !identityRejected(err) {
		t.Errorf("no certificate: %v", err)
	}
	// The gateway's own certificate untrusted: an outage, not a rejected
	// identity. (httptest servers share one certificate, so trust another.)
	stranger, _ := certPair(t, now.Add(time.Hour))
	c, _ = newClient(g.srv.URL, []byte(stranger))
	if err := c.post(context.Background(), "/agent/v1/hello", agentapi.Hello{}, nil); err == nil || identityRejected(err) {
		t.Errorf("untrusted gateway: %v", err)
	}
}

// Enrollment presents no client certificate. One the gateway rejects at the
// TLS layer (expired, foreign CA) would otherwise fail the enrollment
// handshake too, and the agent could never recover.
func TestEnrollPresentsNoCertificate(t *testing.T) {
	g := newTLSGateway(t)
	a, err := New(Config{Endpoint: g.srv.URL, CAPEM: g.caPEM, EnrollMethod: "iam", OrgID: "org_x", IAM: fakeIAM{},
		StateDir: t.TempDir(), Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := g.identity("agent-0", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := a.useIdentity(old); err != nil {
		t.Fatal(err)
	}
	id, err := a.enroll(context.Background())
	if err != nil {
		t.Fatalf("enrolling with an expired certificate loaded: %v", err)
	}
	if id.AgentID != "agent-2" || id.expired(time.Now()) {
		t.Fatalf("enrolled %+v", id)
	}
	if s := g.lastSerial("/agent/v1/enroll"); s != "" {
		t.Fatalf("enrollment presented certificate %s", s)
	}
}

func TestAgentID(t *testing.T) {
	a := &Agent{}
	if a.ID() != "" {
		t.Fatal("ID before enrolling")
	}
	a.id = &identity{AgentID: "agent-7"}
	if a.ID() != "agent-7" {
		t.Fatalf("ID = %q", a.ID())
	}
}

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s has mode %v, want 0600", path, fi.Mode().Perm())
	}
}

// The identity file holds the private key: written 0600 by a rename, so a
// reader never sees half a file and nothing is left behind.
func TestSaveIdentity(t *testing.T) {
	if err := saveIdentity("", &identity{AgentID: "a"}); err != nil {
		t.Fatalf("no state dir: %v", err)
	}
	base := t.TempDir()
	dir := filepath.Join(base, "state", "nested")
	cert, key := certPair(t, time.Now().Add(time.Hour))
	want := &identity{AgentID: "agent-1", OrgID: "org_x", Labels: map[string]string{"env": "prod"}, CertPEM: cert, KeyPEM: key, CAPEM: "ca"}
	if err := saveIdentity(dir, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	path := filepath.Join(dir, "identity.json")
	assertPrivate(t, path)
	got, err := loadIdentity(dir)
	if err != nil || got.KeyPEM != key || got.CertPEM != cert || got.Labels["env"] != "prod" || got.CAPEM != "ca" {
		t.Fatalf("round trip: %+v, %v", got, err)
	}

	// Replacing a file that was readable by others leaves it 0600.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveIdentity(dir, want); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, path)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("state dir holds %v; temp files were left behind", names)
	}

	// Concurrent readers only ever see a whole identity.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				id, err := loadIdentity(dir)
				if err != nil || id.KeyPEM == "" {
					t.Errorf("reader saw a partial identity: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		big := *want
		big.Labels = map[string]string{"pad": strings.Repeat("x", 64<<10+i)}
		if err := saveIdentity(dir, &big); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()

	// A failed rename (identity.json is a directory here) leaves no copy of
	// the key behind.
	odd := filepath.Join(base, "odd")
	os.MkdirAll(filepath.Join(odd, "identity.json", "x"), 0o700)
	if err := saveIdentity(odd, want); err == nil {
		t.Fatal("saved over a directory")
	}
	if left, _ := filepath.Glob(filepath.Join(odd, "identity-*.tmp")); len(left) > 0 {
		t.Fatalf("a failed save left %v behind", left)
	}

	// A state dir that can't be created fails.
	blocker := filepath.Join(base, "file")
	os.WriteFile(blocker, nil, 0o600)
	if err := saveIdentity(filepath.Join(blocker, "state"), want); err == nil {
		t.Fatal("saved under a regular file")
	}
	if _, err := loadIdentity(filepath.Join(base, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing identity: %v", err)
	}
	os.WriteFile(filepath.Join(base, "identity.json"), []byte("{not json"), 0o600)
	if _, err := loadIdentity(base); err == nil {
		t.Fatal("corrupt identity file accepted")
	}
}

// The state dir's umask can't widen the identity file.
func TestSaveIdentityIgnoresPermissiveDir(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	if err := saveIdentity(dir, &identity{AgentID: "a", KeyPEM: "k"}); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, filepath.Join(dir, "identity.json"))
}
