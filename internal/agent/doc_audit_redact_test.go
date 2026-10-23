package agent

import (
	"encoding/base64"
	"strings"
	"testing"
)

// README "Agent": secrets are "redacted from output ... in plain, hex, base64
// (at any offset, wrapped or not)". Each case base64-encodes a prefix plus
// the secret the way a script would (Basic auth "user:secret", GNU base64's
// 76-column wrapping) and checks the secret can't be decoded back out of the
// redacted output.
func TestDocAuditBase64AnyOffsetWrappedOrNot(t *testing.T) {
	wrap := func(s string, n int) string {
		var b strings.Builder
		for len(s) > n {
			b.WriteString(s[:n] + "\n")
			s = s[n:]
		}
		b.WriteString(s)
		return b.String()
	}
	long := "tok_" + strings.Repeat("A1b2C3d4E5", 9) // 94 bytes: its base64 wraps at 76
	cases := []struct {
		name, secret, prefix string
		wrapAt               int
	}{
		{"control_offset0_short", "hunter2x9", "", 0},
		{"control_offset_long_unwrapped", "hunter2-Secret!", "svc:", 0},
		{"short_secret_offset1", "hunter2x9", "svc:", 0},    // 9 bytes at offset 4 (mod 3 = 1)
		{"short_secret_offset2", "hunter2x9", "root:", 0},   // offset 5 (mod 3 = 2)
		{"long_secret_offset_wrapped76", long, "user:", 76}, // printf 'user:%s' "$S" | base64
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := base64.StdEncoding.EncodeToString([]byte(c.prefix + c.secret))
			if c.wrapAt > 0 {
				enc = wrap(enc, c.wrapAt)
			}
			out := newRedactor([]string{c.secret}).apply("out: " + enc + "\n")
			// Whatever survived, decoded, must not contain the secret.
			rest := strings.TrimSpace(strings.ReplaceAll(strings.TrimPrefix(out, "out: "), "\n", ""))
			dec, err := base64.StdEncoding.DecodeString(rest)
			if err == nil && strings.Contains(string(dec), c.secret) {
				t.Errorf("secret %q recoverable: output %q decodes to %q", c.secret, out, dec)
			}
		})
	}
}
