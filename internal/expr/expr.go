// Package expr evaluates CEL expressions and ${{ }} templates over runbook
// context (params, alert, incident, run, target, steps, result, secrets).
//
// CEL is sandboxed and non-Turing-complete, so the same expressions are safe
// to evaluate on the control plane and on the agent.
package expr

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

// Variables available to every expression. Unset ones evaluate as errors if
// referenced, which surfaces mistakes instead of silently matching.
var Variables = []string{"params", "alert", "incident", "run", "target", "steps", "result", "secrets"}

var (
	envOnce sync.Once
	env     *cel.Env
	envErr  error

	cacheMu sync.Mutex
	cache   = map[string]cel.Program{}
)

func getEnv() (*cel.Env, error) {
	envOnce.Do(func() {
		opts := []cel.EnvOption{ext.Strings(), ext.Encoders(), ext.Math(), ext.Lists()}
		for _, v := range Variables {
			opts = append(opts, cel.Variable(v, cel.DynType))
		}
		env, envErr = cel.NewEnv(opts...)
	})
	return env, envErr
}

// Check compiles an expression and returns a descriptive error if invalid.
func Check(src string) error {
	_, err := program(src)
	return err
}

func program(src string) (cel.Program, error) {
	cacheMu.Lock()
	p, ok := cache[src]
	cacheMu.Unlock()
	if ok {
		return p, nil
	}
	e, err := getEnv()
	if err != nil {
		return nil, err
	}
	ast, iss := e.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("invalid expression %q: %w", src, iss.Err())
	}
	p, err = e.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(1_000_000))
	if err != nil {
		return nil, fmt.Errorf("invalid expression %q: %w", src, err)
	}
	cacheMu.Lock()
	cache[src] = p
	cacheMu.Unlock()
	return p, nil
}

// Vars is the evaluation context. Values should be JSON-shaped
// (maps, slices, strings, numbers, bools, nil).
type Vars map[string]any

// Eval evaluates src and returns a JSON-shaped Go value.
func Eval(src string, vars Vars) (any, error) {
	p, err := program(src)
	if err != nil {
		return nil, err
	}
	act := map[string]any{}
	for k, v := range vars {
		act[k] = Normalize(v)
	}
	out, _, err := p.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("evaluate %q: %w", src, err)
	}
	return toNative(out)
}

// EvalBool evaluates src and requires a boolean result.
func EvalBool(src string, vars Vars) (bool, error) {
	v, err := Eval(src, vars)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expression %q returned %T, want bool", src, v)
	}
	return b, nil
}

func toNative(v ref.Val) (any, error) {
	switch v.Type() {
	case types.NullType:
		return nil, nil
	case types.BoolType, types.StringType:
		return v.Value(), nil
	case types.IntType:
		return v.Value().(int64), nil
	case types.UintType:
		return int64(v.Value().(uint64)), nil
	case types.DoubleType:
		return v.Value().(float64), nil
	case types.BytesType:
		return string(v.Value().([]byte)), nil
	}
	if l, ok := v.(traits.Lister); ok {
		var out []any
		it := l.Iterator()
		for it.HasNext() == types.True {
			e, err := toNative(it.Next())
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
		if out == nil {
			out = []any{}
		}
		return out, nil
	}
	if m, ok := v.(traits.Mapper); ok {
		out := map[string]any{}
		it := m.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			e, err := toNative(m.Get(k))
			if err != nil {
				return nil, err
			}
			out[fmt.Sprint(k.Value())] = e
		}
		return out, nil
	}
	if types.IsError(v) {
		return nil, fmt.Errorf("%v", v)
	}
	// Last resort: convert through reflection.
	nv, err := v.ConvertToNative(reflect.TypeOf((*any)(nil)).Elem())
	if err != nil {
		return nil, err
	}
	return nv, nil
}

// Normalize makes JSON-decoded data friendlier to CEL: whole float64 values
// become int64 so `runningCount == 2` and `size() == 1` behave as written.
func Normalize(v any) any {
	switch x := v.(type) {
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
		return x
	case int:
		return int64(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = Normalize(e)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = e
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Normalize(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	default:
		return v
	}
}

// ---------------------------------------------------------------------------
// Templates: ${{ <CEL> }}
// ---------------------------------------------------------------------------

var templateRe = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

// HasTemplate reports whether s contains a ${{ }} expression.
func HasTemplate(s string) bool { return strings.Contains(s, "${{") }

// TemplateExprs returns the expressions inside every ${{ }} in s.
func TemplateExprs(s string) []string {
	var out []string
	for _, m := range templateRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// RenderString expands every ${{ }} in s. A string that is exactly one
// template keeps the expression's type (number, list, …); otherwise results
// are interpolated as text.
func RenderString(s string, vars Vars) (any, error) {
	if !HasTemplate(s) {
		return s, nil
	}
	if m := templateRe.FindStringSubmatchIndex(s); m != nil && m[0] == 0 && m[1] == len(s) {
		return Eval(s[m[2]:m[3]], vars)
	}
	var firstErr error
	out := templateRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := templateRe.FindStringSubmatch(match)
		v, err := Eval(sub[1], vars)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	})
	return out, firstErr
}

// Render expands templates anywhere inside a JSON-shaped value.
func Render(v any, vars Vars) (any, error) {
	switch x := v.(type) {
	case string:
		return RenderString(x, vars)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			r, err := Render(e, vars)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := Render(e, vars)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return v, nil
	}
}
