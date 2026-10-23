package agent

import (
	"math/rand"
	"strings"
	"testing"
)

// FuzzRedact: a secret placed in arbitrary output never survives verbatim,
// and redacting in streamed chunks gives exactly what redacting at once does.
func FuzzRedact(f *testing.F) {
	f.Add("hunter2-hunter2", "before ", " after", int64(1))
	f.Add("AKIAIOSFODNN7EXAMPLE", "key=", "\n", int64(2))
	f.Add("p@ss w/rd+&=?", "url: https://x/?a=", "&b=1", int64(3))
	f.Add("aaaaaaaa", "aaaaaaa", "aaaaaaaaa", int64(4))
	f.Fuzz(func(t *testing.T, secret, pre, post string, seed int64) {
		// Secrets are matched without surrounding whitespace, and values
		// shorter than minNeedle aren't redacted at all (by design).
		if len(strings.TrimSpace(secret)) < minNeedle || len(secret) > 256 || len(pre)+len(post) > 4096 {
			return
		}
		r := newRedactor([]string{secret})
		in := pre + secret + post
		out := r.apply(in)
		if strings.Contains(out, secret) {
			t.Fatalf("secret survived: %q -> %q", in, out)
		}
		if got := streamRedact(r, in, rand.New(rand.NewSource(seed))); got != out {
			t.Fatalf("stream differs from apply:\n%q\n%q", got, out)
		}
	})
}
