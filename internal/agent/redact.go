package agent

import (
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Redacted replaces secret values in output.
const Redacted = "[REDACTED]"

// redactor scrubs every resolved secret value — and its base64 and
// URL-encoded forms — before output leaves the agent.
type redactor struct{ needles []string }

func newRedactor(secrets []string) *redactor {
	set := map[string]bool{}
	for _, s := range secrets {
		if len(s) < 4 { // too short to redact without mangling normal output
			continue
		}
		set[s] = true
		set[base64.StdEncoding.EncodeToString([]byte(s))] = true
		set[base64.RawStdEncoding.EncodeToString([]byte(s))] = true
		set[base64.URLEncoding.EncodeToString([]byte(s))] = true
		set[url.QueryEscape(s)] = true
		set[url.PathEscape(s)] = true
	}
	r := &redactor{}
	for n := range set {
		r.needles = append(r.needles, n)
	}
	// Longest first so a value isn't half-replaced by a shorter variant.
	sort.Slice(r.needles, func(i, j int) bool { return len(r.needles[i]) > len(r.needles[j]) })
	return r
}

func (r *redactor) apply(s string) string {
	for _, n := range r.needles {
		if strings.Contains(s, n) {
			s = strings.ReplaceAll(s, n, Redacted)
		}
	}
	return s
}

// redactAny scrubs strings inside a JSON-shaped value.
func (r *redactor) redactAny(v any) any {
	switch x := v.(type) {
	case string:
		return r.apply(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = r.redactAny(e)
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

// maxNeedle is the longest needle, used to hold back a tail when streaming so
// a secret split across two writes is still caught.
func (r *redactor) maxNeedle() int {
	if len(r.needles) == 0 {
		return 0
	}
	return len(r.needles[0])
}

// split returns the redacted part of raw that is safe to emit now, and the raw
// tail to hold back for the next write.
//
// Anything that could still become a secret once more output arrives starts
// within the last maxNeedle()-1 bytes, so the cut starts there. It then only
// moves back: to the start of any complete match it would divide, and to a
// UTF-8 character boundary. Moving forward past a match could emit the start
// of an overlapping secret that only completes later.
func (r *redactor) split(raw string) (emit, keep string) {
	hold := r.maxNeedle() - 1
	if hold < 0 {
		hold = 0
	}
	cut := len(raw) - hold
	if cut <= 0 {
		return "", raw
	}
	for moved := true; moved && cut > 0; {
		moved = false
		for cut > 0 && cut < len(raw) && !utf8.RuneStart(raw[cut]) {
			cut--
			moved = true
		}
		for _, n := range r.needles {
			// A complete match containing raw[cut-1:cut+1] starts within
			// len(n)-1 bytes before cut.
			for from := max(0, cut-len(n)+1); from < cut; {
				j := strings.Index(raw[from:], n)
				if j < 0 || from+j >= cut {
					break
				}
				if start := from + j; start+len(n) > cut {
					cut, moved = start, true
					break
				}
				from += j + 1
			}
		}
	}
	return r.apply(raw[:cut]), raw[cut:]
}
