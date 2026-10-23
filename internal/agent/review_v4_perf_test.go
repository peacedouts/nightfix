package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	filepathGlob = filepath.Glob
	readFile     = os.ReadFile
	hexEncode    = hex.EncodeToString
)

// False positives: ordinary output (this repo's Go, docs and SQL, ~MBs, plus
// typical base64/hex-heavy output) against many random 7-64 byte secrets.
func TestVerify4FalsePositives(t *testing.T) {
	var corpus strings.Builder
	files, _ := filepathGlob("../../internal/*/*.go")
	more, _ := filepathGlob("../../docs/design/*.md")
	more2, _ := filepathGlob("../../migrations/*.sql")
	for _, f := range append(append(files, more...), more2...) {
		b, err := readFile(f)
		if err == nil {
			corpus.WriteString(string(b))
		}
	}
	// base64 / hex noise, like `aws kms encrypt`, `openssl rand -hex`
	noise := make([]byte, 200000)
	rand.Read(noise)
	corpus.WriteString(wrapLines(base64.StdEncoding.EncodeToString(noise), 76))
	corpus.WriteString(hexEncode(noise))
	text := corpus.String()
	var secrets []string
	for i := 0; i < 300; i++ {
		b := make([]byte, 7+i%58)
		rand.Read(b)
		if i%2 == 0 {
			const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			for j := range b {
				b[j] = a[int(b[j])%len(a)]
			}
		}
		secrets = append(secrets, string(b))
	}
	start := time.Now()
	got := newRedactor(secrets).apply(text)
	n := strings.Count(got, Redacted) - strings.Count(text, Redacted)
	t.Logf("%d bytes of ordinary output, %d random secrets: %d markers (%v)", len(text), len(secrets), n, time.Since(start).Round(time.Millisecond))
	if n > 0 {
		t.Errorf("%d false-positive redactions", n)
	}
}

// Streaming cost with a large secret (a PEM key, a service-account JSON):
// every Write copies and keeps the held-back tail (max-1 bytes), and max is
// now ~3x the longest base64 needle.
func TestVerify4StreamCostLargeSecret(t *testing.T) {
	for _, size := range []int{256, 3243, 16 << 10} {
		raw := make([]byte, size)
		rand.Read(raw)
		secret := "-----BEGIN PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END PRIVATE KEY-----\n"
		r := newRedactor([]string{secret})
		line := strings.Repeat("x", 63) + "\n"
		st := &scanState{}
		tail := ""
		start := time.Now()
		for i := 0; i < (1<<20)/len(line); i++ {
			_, keep := r.scan(st, tail+line, false)
			tail = keep
		}
		t.Logf("secret %6d bytes: max (hold-back) %7d bytes; 1 MiB in 64-byte writes took %v", len(secret), r.max, time.Since(start).Round(time.Millisecond))
	}
}
