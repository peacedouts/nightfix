package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// sink is a fake control plane that records uploaded output chunks.
type sink struct {
	mu     sync.Mutex
	chunks []agentapi.OutputChunk
}

func (s *sink) all() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, c := range s.chunks {
		b.WriteString(c.Data)
	}
	return b.String()
}

func newTestAgent(t *testing.T, s *sink) *Agent {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b agentapi.OutputBatch
		json.NewDecoder(r.Body).Decode(&b)
		s.mu.Lock()
		s.chunks = append(s.chunks, b.Chunks...)
		s.mu.Unlock()
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, c: c, id: &identity{},
		inflight: map[string]context.CancelFunc{}, seen: map[string]time.Time{}}
}

// stream writes each piece to a fresh streamer and returns what was uploaded.
func stream(t *testing.T, secrets []string, pieces ...string) string {
	t.Helper()
	s := &sink{}
	st := newStreamer(newTestAgent(t, s), "att")
	st.red = newRedactor(secrets)
	w := st.writer("stdout")
	for _, p := range pieces {
		w.Write([]byte(p))
	}
	st.close()
	return s.all()
}

func TestStreamRedactsSecretSplitAtEveryPosition(t *testing.T) {
	secret := "SuperSecretValue123"
	line := strings.Repeat("x", 40) + secret + strings.Repeat("y", 40)
	for i := 0; i <= len(line); i++ {
		got := stream(t, []string{secret}, line[:i], line[i:])
		if strings.Contains(got, "SecretValue") || strings.Contains(got, "Super") {
			t.Fatalf("split at %d leaked the secret: %q", i, got)
		}
		if want := strings.Repeat("x", 40) + Redacted + strings.Repeat("y", 40); got != want {
			t.Fatalf("split at %d: got %q, want %q", i, got, want)
		}
	}
}

func TestStreamRedactsSecretInsideLongLine(t *testing.T) {
	secret := "SuperSecretValue123"
	// Straddles where the old code cut long lines (16 KiB + hold).
	long := strings.Repeat("x", agentapi.MaxChunkBytes/2) + secret + strings.Repeat("y", 100)
	got := stream(t, []string{secret}, long, "\n")
	if strings.Contains(got, "ecretValue") {
		t.Fatalf("secret leaked from a long line")
	}
}

func TestStreamRedactsMultilineSecret(t *testing.T) {
	secret := "-----BEGIN KEY-----\nABCDEFGHIJKLMNOP\n-----END KEY-----"
	got := stream(t, []string{secret}, "key: -----BEGIN KEY-----\nABCDEFGH", "IJKLMNOP\n-----END KEY-----\n")
	if strings.Contains(got, "ABCDEFGH") || strings.Contains(got, "IJKLMNOP") {
		t.Fatalf("multi-line secret leaked: %q", got)
	}
}

func TestStreamChunkSizeAndCap(t *testing.T) {
	s := &sink{}
	st := newStreamer(newTestAgent(t, s), "att")
	w := st.writer("stdout")
	w.Write([]byte(strings.Repeat("b", 48<<10) + "\n")) // one write bigger than a chunk
	for i := 0; i < 40; i++ {
		w.Write([]byte(strings.Repeat("c", 64<<10)))
	}
	st.close()
	total := 0
	for _, c := range s.chunks {
		if len(c.Data) > agentapi.MaxChunkBytes {
			t.Errorf("chunk %d is %d bytes, over %d", c.Seq, len(c.Data), agentapi.MaxChunkBytes)
		}
		if c.Stream != "log" {
			total += len(c.Data)
		}
	}
	if total > agentapi.MaxOutputBytes {
		t.Errorf("streamed %d bytes, over the %d cap", total, agentapi.MaxOutputBytes)
	}
	if !strings.Contains(s.all(), "output truncated") {
		t.Errorf("no truncation marker")
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncateUTF8("aé", 2); got != "a" {
		t.Errorf("cut inside a rune: %q", got)
	}
	if got := truncateUTF8("abc", 5); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func shellStep(run, timeout string) *verified {
	return &verified{env: signing.Envelope{AttemptID: "att"}, rb: &runbook.Runbook{},
		step: runbook.Step{ID: "s", Type: "shell", Run: run, Timeout: timeout}}
}

func TestShellBackgroundChildDoesNotHoldStep(t *testing.T) {
	a := newTestAgent(t, &sink{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	res := a.execute(ctx, shellStep("sleep 30 & echo started", "10s"))
	if res.Status != "succeeded" {
		t.Fatalf("script exited 0 but status is %s (%s)", res.Status, res.Error)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("step took %v; a background child held it open", d)
	}
}

func TestShellChildThatLeftProcessGroupDoesNotHang(t *testing.T) {
	a := newTestAgent(t, &sink{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan agentapi.Result, 1)
	go func() { done <- a.execute(ctx, shellStep("setsid sleep 40 & echo started; sleep 30", "2s")) }()
	select {
	case r := <-done:
		if r.Status != "timed_out" {
			t.Errorf("status %s, want timed_out", r.Status)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("execute still blocked well after the step timeout")
	}
}

func TestShellNonZeroExitFails(t *testing.T) {
	a := newTestAgent(t, &sink{})
	res := a.execute(context.Background(), shellStep("exit 3", "5s"))
	if res.Status != "failed" || res.ExitCode == nil || *res.ExitCode != 3 {
		t.Fatalf("got status %s exit %v", res.Status, res.ExitCode)
	}
}

func TestAllowlistModeIsValidated(t *testing.T) {
	for _, mode := range []string{"Enforce", "enforced", "on"} {
		if _, err := New(Config{Endpoint: "https://127.0.0.1:1", AllowlistMode: mode}); err == nil {
			t.Errorf("mode %q accepted", mode)
		}
	}
}

func TestAllowlistMatching(t *testing.T) {
	var al allowlist
	al.Runbooks = append(al.Runbooks,
		struct {
			Name    string `yaml:"name"`
			Digest  string `yaml:"digest"`
			Version string `yaml:"version"`
		}{Name: "pinned", Digest: "sha256:aa"},
		struct {
			Name    string `yaml:"name"`
			Digest  string `yaml:"digest"`
			Version string `yaml:"version"`
		}{Name: "v3", Version: "3"},
		struct {
			Name    string `yaml:"name"`
			Digest  string `yaml:"digest"`
			Version string `yaml:"version"`
		}{Name: "any", Version: "*"},
	)
	cases := []struct {
		name, digest string
		version      int
		want         bool
	}{
		{"pinned", "sha256:aa", 1, true},
		{"pinned", "sha256:bb", 1, false},
		{"v3", "sha256:cc", 3, true},
		{"v3", "sha256:cc", 4, false},
		{"any", "sha256:dd", 9, true},
		{"other", "sha256:aa", 1, false},
	}
	for _, c := range cases {
		if got := al.allows(c.name, c.digest, c.version); got != c.want {
			t.Errorf("allows(%s, %s, %d) = %v, want %v", c.name, c.digest, c.version, got, c.want)
		}
	}
}

func TestPinnedKeyOverridesControlPlaneKey(t *testing.T) {
	realPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fakePub, _, _ := ed25519.GenerateKey(rand.Reader)
	pinned := base64.StdEncoding.EncodeToString(realPub)
	a := newTestAgent(t, &sink{})
	a.cfg.RequiredSigners = []string{"acme-ci"}
	a.cfg.PinnedKeys = map[string]string{"acme-ci": pinned}
	// A compromised control plane pairs the pinned id with its own key.
	a.id.Trust = signing.TrustConfig{Keys: map[string]string{"acme-ci": base64.StdEncoding.EncodeToString(fakePub)}}
	tc, _ := a.trust()
	if tc.Keys["acme-ci"] != pinned {
		t.Fatal("control plane's key for a pinned signer was used")
	}
	if a.id.Trust.Keys["acme-ci"] == pinned {
		t.Fatal("trust() mutated the stored trust config")
	}
}

func TestPinnedKeysAreValidated(t *testing.T) {
	_, err := New(Config{Endpoint: "https://127.0.0.1:1", RequiredSigners: []string{"a"}, PinnedKeys: map[string]string{"a": "not-a-key"}})
	if err == nil {
		t.Error("malformed pinned key accepted")
	}
	_, err = New(Config{Endpoint: "https://127.0.0.1:1", PinnedKeys: map[string]string{"b": base64.StdEncoding.EncodeToString(make([]byte, 32))}})
	if err == nil {
		t.Error("pinned key for a signer that isn't required was accepted")
	}
}

func certPair(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

// An agent whose stored identity expired (down more than 24h) or was revoked
// must enroll again instead of retrying hello forever.
func TestRejectedIdentityReenrolls(t *testing.T) {
	for _, tc := range []struct {
		name     string
		notAfter time.Duration
	}{{"expired", -time.Hour}, {"revoked", 12 * time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			var hellos, enrolls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/agent/v1/hello":
					hellos.Add(1)
					http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
				case "/agent/v1/enroll/challenge", "/agent/v1/enroll":
					enrolls.Add(1)
					http.Error(w, "not in this test", http.StatusServiceUnavailable)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			cert, key := certPair(t, time.Now().Add(tc.notAfter))
			if err := saveIdentity(dir, &identity{AgentID: "a", OrgID: "o", CertPEM: cert, KeyPEM: key}); err != nil {
				t.Fatal(err)
			}
			a, err := New(Config{Endpoint: srv.URL, EnrollMethod: "iam", OrgID: "org_x", IAM: fakeIAM{}, StateDir: dir,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			a.Run(ctx)
			if enrolls.Load() == 0 {
				t.Fatalf("no re-enrollment after %d rejected hellos", hellos.Load())
			}
		})
	}
}

// A token-enrolled agent can't re-enroll by itself: it must stop with a
// clear error rather than retry forever.
func TestRejectedTokenIdentityStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown or revoked agent certificate", http.StatusUnauthorized)
	}))
	defer srv.Close()
	dir := t.TempDir()
	cert, key := certPair(t, time.Now().Add(12*time.Hour))
	saveIdentity(dir, &identity{AgentID: "a", OrgID: "o", CertPEM: cert, KeyPEM: key})
	a, _ := New(Config{Endpoint: srv.URL, EnrollMethod: "token", EnrollToken: "nfxenroll_x", StateDir: dir,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := a.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "new token") {
		t.Fatalf("got %v, want a clear re-enroll error", err)
	}
}

func TestUnwritableStateDirFailsBeforeEnrolling(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if err := checkStateDir(dir); err == nil {
		t.Fatal("unwritable state dir accepted")
	}
}

func TestNoCAFileUsesSystemRoots(t *testing.T) {
	c, err := newClient("https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs != nil {
		t.Fatal("an empty CA pool trusts nothing; without --ca-file the system roots should be used")
	}
}

func TestConcurrentIdentitySaves(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := saveIdentity(dir, &identity{AgentID: strings.Repeat("a", 1000+i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	id, err := loadIdentity(dir)
	if err != nil || !strings.HasPrefix(id.AgentID, "aaaa") {
		t.Fatalf("identity corrupted by concurrent saves: %v", err)
	}
}

type fakeIAM struct{}

func (fakeIAM) Region() string { return "us-east-1" }
func (fakeIAM) SignGetCallerIdentity(context.Context, string, map[string]string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

// streamAll feeds writes through split the way streamWriter does.
func streamAll(r *redactor, writes ...string) string {
	var out, tail string
	for _, w := range writes {
		e, k := r.split(tail + w)
		out += e
		tail = k
	}
	return out + r.apply(tail)
}

// Overlapping secrets, where one's end is another's start: no write split
// may leak more than redacting the whole output at once would.
func TestStreamRedactsOverlappingSecrets(t *testing.T) {
	cases := []struct {
		secrets    []string
		full, leak string
	}{
		{[]string{"zzzzab", "abcdefghijk"}, "hello zzzzabcdefghijk bye", "cdefghij"},
		{[]string{"abcabcXYZ123", "qqqqab"}, "...qqqqabcabcXYZ123...", "XYZ"},
		{[]string{strings.Repeat("z", 20) + "ab", "ab" + "cdefghijklmnopqrstuvwxyz0123"},
			strings.Repeat(".", 50) + strings.Repeat("z", 20) + "abcdefghijklmnopqrstuvwxyz0123" + strings.Repeat(".", 50), "mnopqrst"},
	}
	for _, c := range cases {
		r := newRedactor(c.secrets)
		for i := 1; i < len(c.full); i++ {
			if got := streamAll(r, c.full[:i], c.full[i:]); strings.Contains(got, c.leak) {
				t.Fatalf("secrets %v, split at %d leaked %q: %q", c.secrets, i, c.leak, got)
			}
		}
	}
}

// Randomized: whatever the secrets and however the output is split into
// writes, streaming never shows a secret that redacting all at once hides.
func TestStreamRedactionMatchesWholeOutput(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "abcz"[rng.Intn(4)]
		}
		return string(b)
	}
	for iter := 0; iter < 3000; iter++ {
		var secrets []string
		for i := 0; i < 1+rng.Intn(3); i++ {
			secrets = append(secrets, word(4+rng.Intn(8)))
		}
		r := newRedactor(secrets)
		full := word(10 + rng.Intn(60))
		for i := 0; i < 1+rng.Intn(3); i++ {
			at := rng.Intn(len(full))
			full = full[:at] + secrets[rng.Intn(len(secrets))] + full[at:]
		}
		var writes []string
		for rest := full; rest != ""; {
			n := 1 + rng.Intn(len(rest))
			writes, rest = append(writes, rest[:n]), rest[n:]
		}
		whole, got := r.apply(full), streamAll(r, writes...)
		for _, s := range secrets {
			if !strings.Contains(whole, s) && strings.Contains(got, s) {
				t.Fatalf("secrets %q, writes %q: stream leaked %q: %q (whole: %q)", secrets, writes, s, got, whole)
			}
		}
	}
}

func TestStreamNeverSplitsACharacter(t *testing.T) {
	r := newRedactor([]string{"supersecretvalue"})
	text := strings.Repeat("ünïcödé ", 20)
	for i := 1; i < len(text); i++ {
		if e, _ := r.split(text[:i]); !utf8.ValidString(e) {
			t.Fatalf("write of %d bytes emitted a chunk ending mid-character", i)
		}
	}
}

// Captured output over the limit: a secret cut off at the limit must not
// survive as a fragment, even after earlier replacements shorten the text.
func TestResultTextDropsPartialSecretAtLimit(t *testing.T) {
	sec := strings.Repeat("S", 90) + "TAILSECRET"
	r := newRedactor([]string{sec})
	extra := r.maxNeedle()
	var b strings.Builder
	b.WriteString("token=" + sec + "\nagain=" + sec + "\n")
	for b.Len() < agentapi.MaxOutputBytes+extra-50 {
		b.WriteString("x")
	}
	b.WriteString(sec)
	raw := b.String()[:agentapi.MaxOutputBytes+extra] // what the capture buffer keeps
	got := resultText(r, raw)
	if len(got) > agentapi.MaxOutputBytes {
		t.Fatalf("result is %d bytes", len(got))
	}
	if tail := got[len(got)-200:]; strings.Contains(tail, "SSSSSSSSSS") {
		t.Fatalf("result ends with part of the secret: ...%q", tail[len(tail)-40:])
	}
}
