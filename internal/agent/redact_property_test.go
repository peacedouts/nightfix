package agent

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// Decoders: every way a human would try to get a secret back out of output.
// ---------------------------------------------------------------------------

var v4b64 = func() [256]int {
	var t [256]int
	for i := range t {
		t[i] = -1
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" {
		t[c] = i
	}
	t['+'], t['-'], t['/'], t['_'] = 62, 62, 63, 63
	return t
}()

// v4b64decode decodes s (either alphabet, no padding) leniently.
func v4b64decode(s string) []byte {
	var out []byte
	var acc, bits uint
	for i := 0; i < len(s); i++ {
		v := v4b64[s[i]]
		if v < 0 {
			break
		}
		acc = acc<<6 | uint(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	return out
}

func v4hexdecode(s string) []byte {
	var out []byte
	for i := 0; i+1 < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			break
		}
		out = append(out, byte(b))
	}
	return out
}

func v4runs(s string, in func(byte) bool) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && in(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	return out
}

func v4percentDecode(s string, plus bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		if plus && s[i] == '+' {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func v4jsonDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case '"', '\\', '/':
			b.WriteByte(c)
		case 'u':
			if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
					r := rune(v)
					i += 4
					if utf16.IsSurrogate(r) && i+7 < len(s) && s[i+2] == '\\' && s[i+3] == 'u' {
						if v2, err := strconv.ParseUint(s[i+4:i+8], 16, 16); err == nil {
							r = utf16.DecodeRune(r, rune(v2))
							i += 6
						}
					}
					b.WriteRune(r)
					break
				}
			}
			b.WriteByte('\\')
			b.WriteByte('u')
		default:
			b.WriteByte('\\')
			b.WriteByte(c)
		}
		i++
	}
	return b.String()
}

// v4leak reports how secret can be recovered from out, or "".
func v4leak(out, secret string) string {
	if strings.Contains(out, secret) {
		return "plain"
	}
	flat := strings.NewReplacer("\r", "", "\n", "").Replace(out)
	if strings.Contains(flat, secret) && !strings.ContainsAny(secret, "\r\n") {
		return "plain, line breaks removed"
	}
	for _, s := range []string{out, flat} {
		for _, r := range v4runs(s, func(c byte) bool { return v4b64[c] >= 0 }) {
			for off := 0; off < 4 && off < len(r); off++ {
				if strings.Contains(string(v4b64decode(r[off:])), secret) {
					return "base64"
				}
			}
		}
		for _, r := range v4runs(s, func(c byte) bool { return strings.IndexByte("0123456789abcdefABCDEF", c) >= 0 }) {
			for off := 0; off < 2 && off < len(r); off++ {
				if strings.Contains(string(v4hexdecode(r[off:])), secret) {
					return "hex"
				}
			}
		}
		for _, plus := range []bool{false, true} {
			if strings.Contains(v4percentDecode(s, plus), secret) {
				return "url"
			}
		}
		if strings.Contains(v4jsonDecode(s), secret) {
			return "json"
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

const v4printable = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
const v4alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func v4from(rng *rand.Rand, n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// v4secret: 7..64 bytes, a mix of kinds. Plain and text-escaped forms need
// text; binary secrets are only used with byte encodings.
func v4secret(rng *rand.Rand) (s string, binary bool) {
	n := 7 + rng.Intn(58)
	switch rng.Intn(6) {
	case 0:
		b := make([]byte, n)
		rng.Read(b)
		return string(b), true
	case 1:
		return v4from(rng, n, v4alnum), false
	case 2:
		return v4from(rng, n, v4alnum+"+/="), false // AWS-secret-key-like
	case 3:
		// newline inside (multi-line secret), never at the ends
		s := []byte(v4from(rng, n, v4printable))
		s[1+rng.Intn(n-2)] = '\n'
		return string(s), false
	default:
		return v4from(rng, n, v4printable), false
	}
}

func v4text(rng *rand.Rand) string {
	if rng.Intn(4) == 0 {
		return ""
	}
	words := []string{"ok", "INFO", "starting", "deploy", "2026-10-22T01:02:03Z", "{\"status\":\"ok\"}", "\n", "\r\n", " ", "=", ":", "Basic ", "Authorization: ", "user=", "id=42", "\t", "--", "https://example.com/a?b=c", "[x]"}
	var b strings.Builder
	for i, n := 0, rng.Intn(12); i < n; i++ {
		b.WriteString(words[rng.Intn(len(words))])
	}
	return b.String()
}

// v4wrap wraps s at width w, the first line shorter by col, with LF or CRLF.
func v4wrap(s string, w, col int, eol string) string {
	var b strings.Builder
	first := max(1, w-col)
	for len(s) > first {
		b.WriteString(s[:first])
		b.WriteString(eol)
		s = s[first:]
		first = w
	}
	b.WriteString(s)
	return b.String()
}

func v4maybeWrap(rng *rand.Rand, s string) string {
	if rng.Intn(3) == 0 {
		return s
	}
	eol := "\n"
	if rng.Intn(2) == 0 {
		eol = "\r\n"
	}
	w := 1 + rng.Intn(100)
	if rng.Intn(3) == 0 {
		w = []int{76, 64, 60, 1, 2, 3}[rng.Intn(6)]
	}
	return v4wrap(s, w, rng.Intn(w), eol)
}

var v4encs = []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}

// v4encode returns secret in one in-scope printed form, and its name.
func v4encode(rng *rand.Rand, secret string, binary bool) (string, string) {
	b := []byte(secret)
	k := rng.Intn(10)
	if binary && k < 4 {
		k += 6
	}
	switch k {
	case 0:
		return secret, "plain"
	case 1:
		v := []string{url.QueryEscape(secret), strings.ReplaceAll(url.QueryEscape(secret), "+", "%20"), url.PathEscape(secret)}[rng.Intn(3)]
		if rng.Intn(2) == 0 {
			v = lowerPercent(v)
		}
		return v, "url"
	case 2:
		var sb strings.Builder
		e := json.NewEncoder(&sb)
		e.SetEscapeHTML(rng.Intn(2) == 0)
		e.Encode(secret)
		v := strings.TrimSuffix(sb.String(), "\n")
		v = v[1 : len(v)-1]
		if rng.Intn(3) == 0 {
			v = jsonASCII(v)
		}
		return v, "json"
	case 3:
		return secret, "plain"
	case 4, 5:
		h := hex.EncodeToString(b)
		if rng.Intn(2) == 0 {
			h = strings.ToUpper(h)
		}
		return v4maybeWrap(rng, h), "hex"
	default:
		off := rng.Intn(3) + 3*rng.Intn(3)
		pre := make([]byte, off)
		rng.Read(pre)
		suf := make([]byte, []int{0, 0, 1, 2, 3, rng.Intn(40)}[rng.Intn(6)])
		rng.Read(suf)
		if len(suf) > 0 && rng.Intn(3) == 0 {
			suf[0] = ':'
		}
		enc := v4encs[rng.Intn(4)]
		data := append(append(pre, b...), suf...)
		return v4maybeWrap(rng, enc.EncodeToString(data)), fmt.Sprintf("base64(off=%d,suf=%d)", off, len(suf))
	}
}

func v4stream(r *redactor, s string, rng *rand.Rand) string {
	st := &scanState{}
	var out strings.Builder
	tail := ""
	maxChunk := []int{1, 2, 3, 7, 40, 500, 1 << 16}[rng.Intn(7)]
	for len(s) > 0 {
		n := 1 + rng.Intn(min(len(s), maxChunk))
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

// ---------------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------------

func TestRedactProperty(t *testing.T) {
	seed := time.Now().UnixNano()
	if s := os.Getenv("V4_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	dur := 3 * time.Second // V4_DUR=30s or more for a longer search
	if s := os.Getenv("V4_DUR"); s != "" {
		dur, _ = time.ParseDuration(s)
	}
	rng := rand.New(rand.NewSource(seed))
	t.Logf("seed %d", seed)
	cases, leaks, mismatches := 0, 0, 0
	for start := time.Now(); time.Since(start) < dur; cases++ {
		secret, binary := v4secret(rng)
		secrets := []string{secret}
		switch rng.Intn(6) {
		case 0: // another secret that is a prefix of this one
			secrets = append(secrets, secret[:4+rng.Intn(len(secret)-4)])
		case 1: // one this is a prefix of
			secrets = append(secrets, secret+v4from(rng, 1+rng.Intn(8), v4alnum))
		case 2: // the secret as a JSON leaf
			if !binary {
				j, _ := json.Marshal(map[string]string{"username": "svc-user", "password": secret})
				secrets = []string{string(j)}
			}
		}
		form, how := v4encode(rng, secret, binary)
		out := v4text(rng) + form + v4text(rng)
		if rng.Intn(4) == 0 {
			f2, _ := v4encode(rng, secret, binary)
			out += f2 + v4text(rng)
		}
		r := newRedactor(secrets)
		got := r.apply(out)
		if leak := v4leak(got, secret); leak != "" {
			leaks++
			if leaks <= 5 {
				t.Errorf("leak (%s, recovered as %s): secret %q (secrets %q)\n  out %q\n  got %q", how, leak, secret, secrets, out, got)
			}
		}
		if s := v4stream(r, out, rng); s != got {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("stream != apply: secret %q\n  out %q\n  apply  %q\n  stream %q", secret, out, got, s)
			}
		}
	}
	t.Logf("%d cases, %d leaks, %d stream/apply mismatches", cases, leaks, mismatches)
}

// The decoders find every generated form when nothing is redacted (so a pass
// above means something).
func TestDetectorSanity(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	none := newRedactor(nil)
	missed := 0
	for i := 0; i < 20000; i++ {
		secret, binary := v4secret(rng)
		form, how := v4encode(rng, secret, binary)
		out := v4text(rng) + form + v4text(rng)
		if v4leak(none.apply(out), secret) == "" {
			missed++
			if missed < 5 {
				t.Errorf("detector missed %s: %q in %q", how, secret, out)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// URL escaping as the two most common URL encoders other than Go's print it
// ---------------------------------------------------------------------------

// Scope-dependent: line-break-tolerant matching applies only to needles made
// entirely of base64-alphabet characters, so a secret with punctuation (and
// its URL/JSON-escaped forms) folded by a single LF is not matched.
func TestWrappedNonBase64Forms(t *testing.T) {
	// Out of scope, by decision: tools wrap encoded output (base64, hex), not
	// a plain secret, and matching plain text across line breaks would hide
	// ordinary lines that happen to join into a secret. Kept to document it.
	t.Skip("plain and escaped forms broken by a line break are out of redaction's scope (README)")
	secret := "P@ss!w0rd-2026#prod"
	for _, printed := range []string{
		v4wrap(secret, 10, 0, "\n"),
		v4wrap(url.QueryEscape(secret), 10, 0, "\n"),
		v4wrap(jsEscapeForTest(secret), 10, 0, "\r\n"),
	} {
		got := newRedactor([]string{secret}).apply("value:\n" + printed + "\n")
		if leak := v4leak(got, secret); leak != "" {
			t.Errorf("wrapped form %q recoverable (%s): %q", printed, leak, got)
		}
	}
}

func jsEscapeForTest(s string) string { return jsonEscape(s+"\"", false) }

// pyQuote is Python's urllib.parse.quote(s) (safe="/"), also what requests
// and many shell one-liners use.
func pyQuote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(v4alnum+"_.-~/", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// jsEncodeURIComponent is JavaScript's encodeURIComponent (ASCII input).
func jsEncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(v4alnum+"-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func TestURLEscapedByCommonTools(t *testing.T) {
	for _, c := range []struct{ tool, secret, printed string }{
		// An AWS secret access key (40 chars of [A-Za-z0-9+/]) through
		// python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))'
		{"python urllib.parse.quote", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY+", ""},
		{"python urllib.parse.quote", "p@ss/word-2026", ""},
		// node -e 'console.log(encodeURIComponent(process.argv[1]))'
		{"js encodeURIComponent", "Hunter2!Secret@2026", ""},
		{"js encodeURIComponent", "my pass(word)*", ""},
	} {
		if c.tool == "python urllib.parse.quote" {
			c.printed = pyQuote(c.secret)
		} else {
			c.printed = jsEncodeURIComponent(c.secret)
		}
		out := "curl -d 'password=" + c.printed + "' https://api.example.com\n"
		got := newRedactor([]string{c.secret}).apply(out)
		if leak := v4leak(got, c.secret); leak != "" {
			t.Errorf("%s: secret %q printed as %q is recoverable (%s) from %q", c.tool, c.secret, c.printed, leak, got)
		}
	}
}
