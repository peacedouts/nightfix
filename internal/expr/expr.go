// Package expr evaluates CEL expressions and ${{ }} templates over runbook
// context (params, alert, incident, run, target, steps, result, secrets).
//
// CEL is sandboxed and non-Turing-complete, so the same expressions are safe
// to evaluate on the control plane and on the agent.
package expr

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
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
		// ext.Lists is left out: lists.range builds its whole list before
		// the cost limit is checked, so a large range exhausts memory.
		opts := []cel.EnvOption{ext.Strings(), ext.Encoders(), ext.Math()}
		for _, v := range Variables {
			opts = append(opts, cel.Variable(v, cel.DynType))
		}
		env, envErr = cel.NewEnv(opts...)
	})
	return env, envErr
}

// MaxSourceLen bounds an expression's source text.
const MaxSourceLen = 4096

// deniedFunctions can build output far larger than their input in a single
// call. CEL's cost limit charges them a flat amount per call and checks it
// only after the call returns, so chaining a few of them allocates gigabytes
// and crashes the process (a Go out-of-memory error can't be recovered).
// Expressions run on the shared control plane and on agents, so they're
// refused at compile time instead.
var deniedFunctions = map[string]bool{"replace": true, "format": true, "join": true, "lists.range": true}

// CEL shares list values instead of copying them, so a macro whose body
// repeats its variable ([v, v]) doubles a value's logical size for the cost
// of one call. Chained or nested, a few hundred bytes of expression build
// structures that take minutes to compare or exhaust memory when converted,
// and the cost limit never sees it. Each doubling needs one macro, so
// bounding both the number of macros and how often a body uses its variable
// bounds the blow-up (to MaxIterVarRefs^MaxComprehensions).
const (
	MaxComprehensions = 3
	MaxIterVarRefs    = 4
	maxResultValues   = 100_000 // backstop when converting a result

	// Every evaluation also has a wall-clock deadline, checked between
	// comprehension iterations. cel-go's cost tracking makes large
	// comprehensions quadratic in wall time while charging them linearly
	// (fixed upstream in cel-go#1430, not yet released), so the cost limit
	// alone let one expression run for a minute.
	maxEvalTime         = 250 * time.Millisecond
	interruptCheckEvery = 1
	costLimit           = 1_000_000
	maxCachedPrograms   = 4096
)

// sizeCost prices every function call by the size of its arguments and
// result. cel-go prices O(n) operations by resolved overload, but variables
// here are dyn, so overloads like _+_ never resolve and are billed a flat 1:
// concatenating two 1 MiB strings cost 5, and a map that concatenated large
// strings ran the process out of memory well inside the limit. Charging by
// size makes the cost limit an actual bound on work and allocation. Costs
// are charged after each call returns, so a single call can still do work
// proportional to its (bounded) inputs, but nothing can repeat it.
type sizeCost struct{}

func (sizeCost) CallCost(_, _ string, args []ref.Val, result ref.Val) *uint64 {
	c := uint64(1) + valSize(result)
	for _, a := range args {
		c += valSize(a)
	}
	return &c
}

// valSize is a shallow size: strings and bytes count one unit per 10 bytes
// (cel-go's traversal factor), lists and maps one per element. Nested
// structures are bounded separately (macro limits, result conversion).
func valSize(v ref.Val) uint64 {
	if v == nil {
		return 0
	}
	switch x := v.Value().(type) {
	case string:
		return uint64(len(x)) / 10
	case []byte:
		return uint64(len(x)) / 10
	}
	if s, ok := v.(traits.Sizer); ok {
		if n, ok := s.Size().Value().(int64); ok && n > 0 {
			return uint64(n)
		}
	}
	return 0
}

const ()

// References reports whether src uses the variable name anywhere (a
// comprehension variable of the same name counts too, which errs on the
// safe side). src must compile.
func References(src, name string) (bool, error) {
	e, err := getEnv()
	if err != nil {
		return false, err
	}
	a, iss := e.Parse(src)
	if iss != nil && iss.Err() != nil {
		return false, iss.Err()
	}
	return identRefs(a.NativeRep().Expr(), name) > 0, nil
}

func identRefs(e celast.Expr, name string) int {
	n := 0
	celast.PreOrderVisit(e, celast.NewExprVisitor(func(x celast.Expr) {
		if x.Kind() == celast.IdentKind && x.AsIdent() == name {
			n++
		}
	}))
	return n
}

// Check compiles an expression and returns a descriptive error if invalid.
func Check(src string) error {
	_, err := program(src)
	return err
}

// CheckBool is Check for an expression used as a condition (a trigger or
// routing match, a when or until). Variables are dynamically typed, so most
// conditions only show their type when evaluated; but one whose type is
// known and isn't bool (a string, a number, a size()) could never be true,
// and is refused instead of silently never matching.
func CheckBool(src string) error {
	if err := Check(src); err != nil {
		return err
	}
	e, err := getEnv()
	if err != nil {
		return err
	}
	ast, iss := e.Compile(src)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	if t := ast.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return fmt.Errorf("expression %q is a %s, not a condition (true or false)", src, t)
	}
	return nil
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
	if len(src) > MaxSourceLen {
		return nil, fmt.Errorf("expression is %d bytes; the limit is %d", len(src), MaxSourceLen)
	}
	ast, iss := e.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("invalid expression %q: %w", src, iss.Err())
	}
	var denied string
	comprehensions := 0
	celast.PreOrderVisit(ast.NativeRep().Expr(), celast.NewExprVisitor(func(x celast.Expr) {
		switch x.Kind() {
		case celast.CallKind:
			if deniedFunctions[x.AsCall().FunctionName()] && denied == "" {
				denied = x.AsCall().FunctionName() + "() is not allowed"
			}
		case celast.ComprehensionKind:
			comprehensions++
			c := x.AsComprehension()
			if n := identRefs(c.LoopStep(), c.IterVar()); n > MaxIterVarRefs && denied == "" {
				denied = fmt.Sprintf("%s is used %d times in one macro body (the limit is %d)", c.IterVar(), n, MaxIterVarRefs)
			}
		}
	}))
	if comprehensions > MaxComprehensions && denied == "" {
		denied = fmt.Sprintf("%d macros (map, filter, all, exists…); the limit is %d", comprehensions, MaxComprehensions)
	}
	if denied != "" {
		return nil, fmt.Errorf("invalid expression %q: %s", src, denied)
	}
	p, err = e.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostTracking(sizeCost{}), cel.CostLimit(costLimit),
		cel.InterruptCheckFrequency(interruptCheckEvery))
	if err != nil {
		return nil, fmt.Errorf("invalid expression %q: %w", src, err)
	}
	cacheMu.Lock()
	if len(cache) >= maxCachedPrograms {
		// Expressions come from stored runbooks and rules, so the working
		// set is small; this only stops unbounded growth.
		cache = map[string]cel.Program{}
	}
	cache[src] = p
	cacheMu.Unlock()
	return p, nil
}

// Vars is the evaluation context. Values should be JSON-shaped
// (maps, slices, strings, numbers, bools, nil).
type Vars map[string]any

// Eval evaluates src and returns a JSON-shaped Go value.
func Eval(src string, vars Vars) (any, error) {
	return EvalCtx(context.Background(), src, vars)
}

// EvalCtx is Eval with a caller's deadline as well: it stops at whichever
// comes first, ctx's or the per-expression limit. Callers that evaluate many
// expressions for one event (routing rules, trigger matches) use it to bound
// their total.
func EvalCtx(parent context.Context, src string, vars Vars) (any, error) {
	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("evaluate %q: %w", src, err)
	}
	p, err := program(src)
	if err != nil {
		return nil, err
	}
	act := map[string]any{}
	for k, v := range vars {
		act[k] = Normalize(v)
	}
	ctx, cancel := context.WithTimeout(parent, maxEvalTime)
	defer cancel()
	out, _, err := p.ContextEval(ctx, act)
	if err != nil {
		if perr := parent.Err(); perr != nil {
			return nil, fmt.Errorf("evaluate %q: %w", src, perr)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("evaluate %q: took longer than %v", src, maxEvalTime)
		}
		return nil, fmt.Errorf("evaluate %q: %w", src, err)
	}
	budget := maxResultValues
	return toNative(out, &budget)
}

// EvalBool evaluates src and requires a boolean result.
func EvalBool(src string, vars Vars) (bool, error) {
	return EvalBoolCtx(context.Background(), src, vars)
}

// EvalBoolCtx is EvalBool with a caller's deadline (see EvalCtx).
func EvalBoolCtx(ctx context.Context, src string, vars Vars) (bool, error) {
	v, err := EvalCtx(ctx, src, vars)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expression %q returned %T, want bool", src, v)
	}
	return b, nil
}

func toNative(v ref.Val, budget *int) (any, error) {
	if *budget--; *budget < 0 {
		return nil, fmt.Errorf("expression result is too large (over %d values)", maxResultValues)
	}
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
			e, err := toNative(it.Next(), budget)
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
			e, err := toNative(m.Get(k), budget)
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
