package agent

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// streamRedact feeds s through scan in the given chunk sizes, the way
// streamWriter.Write + close do.
func streamRedact(r *redactor, s string, rng *rand.Rand) string {
	st := &scanState{}
	var out strings.Builder
	tail := ""
	for len(s) > 0 {
		n := 1 + rng.Intn(min(len(s), 40))
		emit, keep := r.scan(st, tail+s[:n], false)
		out.WriteString(emit)
		tail = keep
		s = s[n:]
	}
	if tail != "" {
		emit, _ := r.scan(st, tail, true)
		out.WriteString(emit)
	}
	return out.String()
}

func recoverable(out, secret string) bool {
	// Any run of base64 in out that decodes to something containing secret.
	for _, line := range strings.Fields(strings.NewReplacer("[REDACTED]", " ", ":", " ").Replace(out)) {
		_ = line
	}
	joined := strings.ReplaceAll(strings.ReplaceAll(out, "\r", ""), "\n", "")
	for _, f := range strings.FieldsFunc(joined, func(r rune) bool { return strings.IndexRune(b64Alphabet, r) < 0 }) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			t := strings.TrimRight(f, "=")
			if enc == base64.StdEncoding || enc == base64.URLEncoding {
				t = f
			}
			if d, err := enc.DecodeString(t); err == nil && strings.Contains(string(d), secret) {
				return true
			}
		}
	}
	return false
}

// Base64 at offset 0 followed by a byte other than \n or \r: Basic auth with
// the API key as the username ("sk_live_...:" as Stripe uses), or
// base64("secret:x"). len(secret)%3 != 0, so the last char of RawStd(secret)
// differs and no needle matches at all.
func TestBase64Offset0FollowedByData(t *testing.T) {
	for _, c := range []struct{ secret, suffix string }{
		{"xk_live_4eC39HqLyjWDarjtT1zdp7dc", ":"},      // 32 bytes, %3 = 2
		{"hunter2-Secret!", ":"},                       // 15 bytes, %3 = 0 (control)
		{"tok_A1b2C3d4E5F6g7", ":x"},                   // 18 bytes %3=0 control
		{"tok_A1b2C3d4E5F6g7h", ":x"},                  // 19 bytes %3=1
		{"p@ssw0rd-Correct-Horse", `","next":"value"`}, // 22 bytes %3=1
	} {
		enc := base64.StdEncoding.EncodeToString([]byte(c.secret + c.suffix))
		out := newRedactor([]string{c.secret}).apply("> Authorization: Basic " + enc + "\n")
		if recoverable(out, c.secret) {
			t.Errorf("secret %q (len %d) recoverable from %q", c.secret, len(c.secret), out)
		}
	}
}

// Property: streaming in random chunks must equal apply (the doc comment on
// redactor promises it), and the secret mustn't be recoverable, for secret
// encodings wrapped with a line break at random places.
func TestStreamEqualsApplyWrapped(t *testing.T) {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	secret := "hunter2-Secret!xyz"
	r := newRedactor([]string{secret})
	fails := 0
	for iter := 0; iter < 3000 && fails < 3; iter++ {
		prefix := []string{"", "u:", "user:", "ab:"}[rng.Intn(4)]
		enc := base64.StdEncoding.EncodeToString([]byte(prefix + secret + "\n"))
		var b strings.Builder
		b.WriteString("noise line\n")
		for i := 0; i < len(enc); i++ {
			b.WriteByte(enc[i])
			if rng.Intn(6) == 0 {
				// One line break between characters, as wrapping tools
				// produce (any width). Several in a row is deliberate
				// obfuscation, which redaction doesn't claim to defeat;
				// those inputs only have to stream the same as apply.
				b.WriteString([]string{"\n", "\r\n"}[rng.Intn(2)])
			}
		}
		b.WriteString("\ntrailer\n")
		in := b.String()
		a := r.apply(in)
		s := streamRedact(r, in, rng)
		if a != s {
			fails++
			t.Errorf("seed %d: stream != apply\n in=%q\n apply=%q\nstream=%q", seed, in, a, s)
		}
		if recoverable(s, secret) {
			fails++
			t.Errorf("seed %d: secret recoverable from streamed %q (input %q)", seed, s, in)
		}
	}
}

// A match spanning more than r.max bytes (dense line breaks) diverges between
// apply and streaming.
func TestHoldBackTooSmallForDenseBreaks(t *testing.T) {
	secret := "hunter2-Secret!xyz"
	r := newRedactor([]string{secret})
	enc := base64.RawStdEncoding.EncodeToString([]byte(secret))
	var b strings.Builder
	for i := 0; i < len(enc); i++ {
		b.WriteByte(enc[i])
		b.WriteString("\r\n")
	}
	in := "x " + b.String() + strings.Repeat("y", 200)
	a := r.apply(in)
	rng := rand.New(rand.NewSource(1))
	s := streamRedact(r, in, rng)
	t.Logf("r.max=%d match span=%d", r.max, len(b.String()))
	if a != s {
		t.Errorf("stream != apply\napply=%q\nstream=%q", a, s)
	}
}

// Performance: many secrets sharing a prefix, output dense with that prefix.
func TestPerfManySecrets(t *testing.T) {
	var secrets []string
	for i := 0; i < 200; i++ {
		secrets = append(secrets, fmt.Sprintf("sk_live_%040d", i*7919))
	}
	r := newRedactor(secrets)
	t.Logf("needles=%d max=%d", len(r.needles), r.max)
	// 1 MiB of hex-ish digits "736b5f" prefix of hex(sk_) repeating, plus base64 "c2tf".
	unit := "736b5f6c697665 c2tfbGl2ZV 0123456789\n"
	in := strings.Repeat(unit, (1<<20)/len(unit))
	start := time.Now()
	_ = r.apply(in)
	el := time.Since(start)
	start = time.Now()
	_ = streamRedact(r, in, rand.New(rand.NewSource(2)))
	el2 := time.Since(start)
	t.Logf("apply 1MiB: %v, stream: %v", el, el2)
}

// Realistic wrapping (one LF or CRLF at most every 8 chars, including right
// after the first char), std and url alphabets, prefixes giving offsets 0-2,
// trailing newline: streaming must equal apply and nothing decodable remains.
func TestStreamEqualsApplyRealisticWrap(t *testing.T) {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	secrets := []string{"hunter2-Secret!xyz", "p4ssw0rd!", "a-much-longer-secret-value-for-wrapping-tests-0123456789-abcdefghijklmnop"}
	r := newRedactor(secrets)
	fails := 0
	for iter := 0; iter < 4000 && fails < 3; iter++ {
		secret := secrets[rng.Intn(len(secrets))]
		prefix := []string{"", "u:", "user:", "ab:", "abc"}[rng.Intn(5)]
		suffix := []string{"\n", "\r\n", ""}[rng.Intn(3)]
		enc := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding}[rng.Intn(3)].EncodeToString([]byte(prefix + secret + suffix))
		var b strings.Builder
		b.WriteString("noise line\n")
		next := 1 + rng.Intn(8)
		if rng.Intn(4) == 0 {
			next = len(prefix)*4/3 + 2 // right after the first char of the secret's run
		}
		for i := 0; i < len(enc); i++ {
			b.WriteByte(enc[i])
			if i+1 == next {
				b.WriteString([]string{"\n", "\r\n"}[rng.Intn(2)])
				next = i + 1 + 8 + rng.Intn(70)
			}
		}
		b.WriteString("\ntrailer\n")
		in := b.String()
		a := r.apply(in)
		s := streamRedact(r, in, rng)
		if a != s {
			fails++
			t.Errorf("seed %d: stream != apply\n in=%q\n apply=%q\nstream=%q", seed, in, a, s)
		}
		if recoverable(s, secret) {
			fails++
			t.Errorf("seed %d: secret %q recoverable from %q (input %q)", seed, secret, s, in)
		}
	}
}

// False positives: ordinary text across line breaks.
func TestWrapFalsePositives(t *testing.T) {
	r := newRedactor([]string{"password", "12345678"})
	for _, in := range []string{
		"enter your pass\nword below\n",
		"order 1234\n5678 shipped\n",
		"total: 1234\r\n\r\n\r\n5678\n",
	} {
		t.Logf("%q -> %q", in, r.apply(in))
	}
}
