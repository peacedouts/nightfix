package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
