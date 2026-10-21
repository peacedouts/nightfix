package agent

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Redacted replaces secret values in output.
const Redacted = "[REDACTED]"

// minNeedle: shorter values are too short to redact without mangling normal
// output. minB64Core: shortest base64 run kept for a value at a non-zero
// offset inside a longer encoded string (shorter runs match by chance).
const (
	minNeedle  = 4
	minB64Core = 12
)

// redactor scrubs every resolved secret value, and the encodings a script
// commonly prints it in, before output leaves the agent.
//
// Matching is by coverage: every byte that belongs to any occurrence of any
// needle is hidden, and each maximal run of hidden bytes becomes one marker.
// That result depends only on the text, so streaming (scan with state) and
// redacting all at once (apply) produce the same output.
type redactor struct {
	needles []string            // longest first
	index   map[uint16][]string // by first two bytes, longest first
	max     int
}

func newRedactor(secrets []string) *redactor {
	set := map[string]bool{}
	for _, s := range secrets {
		for _, f := range secretForms(s) {
			for _, v := range encodings(f) {
				if len(v) >= minNeedle {
					set[v] = true
				}
			}
		}
	}
	r := &redactor{index: map[uint16][]string{}}
	for n := range set {
		r.needles = append(r.needles, n)
	}
	sort.Slice(r.needles, func(i, j int) bool {
		if len(r.needles[i]) != len(r.needles[j]) {
			return len(r.needles[i]) > len(r.needles[j])
		}
		return r.needles[i] < r.needles[j]
	})
	for _, n := range r.needles {
		k := uint16(n[0])<<8 | uint16(n[1])
		r.index[k] = append(r.index[k], n)
	}
	if len(r.needles) > 0 {
		r.max = len(r.needles[0])
	}
	return r
}

// secretForms: the value, the value without trailing line endings, with CRLF
// normalized, and, for a JSON document, each string leaf.
func secretForms(s string) []string {
	forms := []string{s}
	if t := strings.TrimRight(s, "\r\n"); t != s {
		forms = append(forms, t)
	}
	if t := strings.TrimSpace(s); t != s {
		forms = append(forms, t)
	}
	if t := strings.ReplaceAll(s, "\r\n", "\n"); t != s {
		forms = append(forms, t, strings.TrimRight(t, "\n"))
	}
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var doc any
		if json.Unmarshal([]byte(t), &doc) == nil {
			walkJSONLeaves(doc, "", func(key, leaf string) {
				if len(leaf) >= minNeedle && !connectionFields[strings.ToLower(key)] {
					forms = append(forms, leaf)
				}
			})
		}
	}
	return forms
}

// connectionFields are the non-secret fields of the JSON secrets AWS creates
// for databases (RDS, Redshift, DocumentDB). Redacting their values would
// blank out every "postgres" or hostname in step output.
var connectionFields = map[string]bool{
	"engine": true, "host": true, "port": true, "dbname": true, "region": true,
	"dbinstanceidentifier": true, "dbclusteridentifier": true, "proxyname": true,
}

func walkJSONLeaves(v any, key string, fn func(key, leaf string)) {
	switch x := v.(type) {
	case string:
		fn(key, x)
	case map[string]any:
		for k, e := range x {
			walkJSONLeaves(e, k, fn)
		}
	case []any:
		for _, e := range x {
			walkJSONLeaves(e, key, fn)
		}
	}
}

func encodings(s string) []string {
	if len(s) < minNeedle {
		return nil
	}
	b := []byte(s)
	q := url.QueryEscape(s)
	comp := strings.ReplaceAll(q, "+", "%20")
	out := []string{
		s,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b), // also a prefix of base64(s+"\n") and base64(s+"\r\n")
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		q, lowerPercent(q), comp, lowerPercent(comp),
		url.PathEscape(s), lowerPercent(url.PathEscape(s)),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
	}
	j := jsonEscape(s, false)
	out = append(out, j, jsonEscape(s, true), jsonASCII(j), strings.ReplaceAll(j, "/", `\/`))
	// GNU base64 wraps at 76 columns, openssl/PEM at 64.
	raw := base64.RawStdEncoding.EncodeToString(b)
	for _, w := range []int{76, 64} {
		if len(raw) > w {
			out = append(out, wrapLines(raw, w))
		}
	}
	// The value at offset 1 or 2 inside a longer base64 string ("user:pass").
	for off := 1; off <= 2; off++ {
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			e := enc.EncodeToString(append(make([]byte, off), b...))
			lo, hi := (8*off+5)/6, 8*(off+len(b))/6
			if hi-lo >= minB64Core {
				out = append(out, e[lo:hi])
			}
		}
	}
	return out
}

func jsonEscape(s string, html bool) string {
	var sb strings.Builder
	e := json.NewEncoder(&sb)
	e.SetEscapeHTML(html)
	e.Encode(s)
	t := strings.TrimSuffix(sb.String(), "\n")
	return t[1 : len(t)-1]
}

func jsonASCII(j string) string {
	var sb strings.Builder
	for _, r := range j {
		switch {
		case r < 0x80:
			sb.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&sb, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&sb, `\u%04x`, r)
		}
	}
	return sb.String()
}

func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			for k := i + 1; k <= i+2; k++ {
				if b[k] >= 'A' && b[k] <= 'F' {
					b[k] += 'a' - 'A'
				}
			}
		}
	}
	return string(b)
}

func wrapLines(s string, n int) string {
	var sb strings.Builder
	for len(s) > n {
		sb.WriteString(s[:n])
		sb.WriteByte('\n')
		s = s[n:]
	}
	sb.WriteString(s)
	return sb.String()
}

// scanState carries a stream's position across writes.
type scanState struct {
	cover    int  // leading bytes of the next input already covered by a match
	inMarker bool // the last thing emitted was a marker
}

// scan redacts raw as far as it can be decided and returns the rest. A byte is
// decided once every needle that could start at or before it can be checked
// in full, so at most max-1 bytes (plus a partial character) are kept. final
// decides everything.
func (r *redactor) scan(st *scanState, raw string, final bool) (emit, keep string) {
	if r.max == 0 {
		return raw, ""
	}
	limit := len(raw)
	if !final {
		limit = max(0, len(raw)-(r.max-1))
	}
	var b strings.Builder
	coverEnd, lit := st.cover, 0
	for i := 0; i < limit; i++ {
		if i+1 < len(raw) {
			for _, n := range r.index[uint16(raw[i])<<8|uint16(raw[i+1])] {
				if strings.HasPrefix(raw[i:], n) {
					coverEnd = max(coverEnd, i+len(n))
					break
				}
			}
		}
		if i < coverEnd {
			if lit < i {
				b.WriteString(raw[lit:i])
				st.inMarker = false
			}
			if !st.inMarker {
				b.WriteString(Redacted)
				st.inMarker = true
			}
			lit = i + 1
		}
	}
	end := limit
	if !final && lit < end {
		// Don't end on a partial character (bounded, for invalid UTF-8).
		for k := 0; k < utf8.UTFMax-1 && end > lit && end < len(raw) && !utf8.RuneStart(raw[end]); k++ {
			end--
		}
		if end < len(raw) && !utf8.RuneStart(raw[end]) {
			end = limit
		}
	}
	if lit < end {
		b.WriteString(raw[lit:end])
		st.inMarker = false
	}
	st.cover = max(0, coverEnd-end)
	return b.String(), raw[end:]
}

func (r *redactor) apply(s string) string {
	if len(r.needles) == 0 {
		return s
	}
	out, _ := r.scan(&scanState{}, s, true)
	return out
}

// split redacts the part of raw that is decided and drops the rest (used to
// cut captured output at a limit).
func (r *redactor) split(raw string) (emit, keep string) {
	return r.scan(&scanState{}, raw, false)
}

// redactAny scrubs strings, map keys included, inside a JSON-shaped value.
func (r *redactor) redactAny(v any) any {
	switch x := v.(type) {
	case string:
		return r.apply(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[r.apply(k)] = r.redactAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.redactAny(e)
		}
		return out
	default:
		return v
	}
}

func (r *redactor) maxNeedle() int { return r.max }
