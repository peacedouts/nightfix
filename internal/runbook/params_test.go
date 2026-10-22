package runbook

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/expr"
)

// Parameters are a security boundary: alert-derived values reach AWS calls
// and scripts through them (runbook-schema.md §3.2). Each case is one value
// against one declaration; values use the shapes they arrive in: float64 for
// JSON numbers (the run record, the signed envelope, YAML after Parse),
// int64 from CEL `from` expressions, strings from labels and the API.

type coerceCase struct {
	name string
	p    Param
	in   any
	want any    // the coerced value, when err is ""
	err  string // substring of the expected error
}

func runCoerce(t *testing.T, cases []coerceCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := coerceParam("p", c.p, c.in)
			if c.err != "" {
				if err == nil {
					t.Fatalf("coerce(%#v) = %#v, want an error containing %q", c.in, got, c.err)
				}
				if !strings.Contains(err.Error(), c.err) {
					t.Fatalf("coerce(%#v): error %q, want it to contain %q", c.in, err, c.err)
				}
				if !strings.HasPrefix(err.Error(), `parameter "p": `) {
					t.Fatalf("error %q doesn't name the parameter", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("coerce(%#v): unexpected error %v", c.in, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("coerce(%#v) = %#v (%T), want %#v (%T)", c.in, got, got, c.want, c.want)
			}
		})
	}
}

func TestCoerceString(t *testing.T) {
	s := Param{Type: "string"}
	anchored := Param{Type: "string", Pattern: `^[a-z]+$`}
	bare := Param{Type: "string", Pattern: `[a-z]+`}
	runCoerce(t, []coerceCase{
		{"plain", s, "abc", "abc", ""},
		{"empty", s, "", "", ""},
		{"json number", s, 3.0, nil, "want string, got float64"},
		{"cel int", s, int64(3), nil, "want string, got int64"},
		{"bool", s, true, nil, "want string, got bool"},
		{"null", s, nil, nil, "want string, got <nil>"},
		{"list", s, []any{"a"}, nil, "want string"},
		{"map", s, map[string]any{"a": "b"}, nil, "want string"},
		{"1024 bytes", s, strings.Repeat("a", 1024), strings.Repeat("a", 1024), ""},
		{"1025 bytes", s, strings.Repeat("a", 1025), nil, "too long"},
		{"length is bytes", s, strings.Repeat("é", 513), nil, "too long"},

		// Go's $ (without (?m)) is end of text, not "before a final newline".
		{"anchored ok", anchored, "abc", "abc", ""},
		{"anchored embedded newline", anchored, "abc\ndef", nil, "does not match"},
		{"anchored trailing newline", anchored, "abc\n", nil, "does not match"},
		{"anchored leading newline", anchored, "\nabc", nil, "does not match"},
		{"anchored empty", anchored, "", nil, "does not match"},
		{"anchored case", anchored, "ABC", nil, "does not match"},
		{"anchored homoglyph", anchored, "аbc", nil, "does not match"}, // Cyrillic а
		{"anchored invalid utf8", anchored, "ab\xff", nil, "does not match"},

		// A pattern written without anchors is anchored implicitly.
		{"bare ok", bare, "abc", "abc", ""},
		{"bare suffix", bare, "abc; rm -rf /", nil, "does not match"},
		{"bare prefix", bare, "$(curl x|sh)abc", nil, "does not match"},
		{"bare newline", bare, "abc\ndef", nil, "does not match"},

		// Flags inside a pattern can't reach the wrapper's anchors.
		{"multiline flag", Param{Type: "string", Pattern: `(?m)^[a-z]+$`}, "abc\ndef", nil, "does not match"},
		{"multiline flag ok", Param{Type: "string", Pattern: `(?m)^[a-z]+$`}, "abc", "abc", ""},
		{"dotall is explicit", Param{Type: "string", Pattern: `(?s)a.b`}, "a\nb", "a\nb", ""},
		{"alternation anchored", Param{Type: "string", Pattern: `prod|staging`}, "xstaging", nil, "does not match"},
		{"alternation anchored 2", Param{Type: "string", Pattern: `prod|staging`}, "prodx", nil, "does not match"},
		{"alternation ok", Param{Type: "string", Pattern: `prod|staging`}, "staging", "staging", ""},
		{"invalid pattern", Param{Type: "string", Pattern: `(`}, "x", nil, "invalid pattern"},
		{"group escape", Param{Type: "string", Pattern: `a)|(.*`}, "x; rm", nil, "invalid pattern"},
		{"literal escape", Param{Type: "string", Pattern: `\Qa)|(.*`}, "x; rm", nil, "invalid pattern"},
		{"literal ok", Param{Type: "string", Pattern: `\Qa.b\E`}, "a.b", "a.b", ""},
		{"literal is literal", Param{Type: "string", Pattern: `\Qa.b\E`}, "axb", nil, "does not match"},
	})
}

// TestCompilePatternAnchoring checks the documented rules directly.
func TestCompilePatternAnchoring(t *testing.T) {
	for _, c := range []struct {
		pattern string
		yes, no []string
	}{
		{`[a-z]+`, []string{"abc"}, []string{"abc\n", "abc def", " abc", "abc\x00"}},
		{`^[a-z]+$`, []string{"abc"}, []string{"abc\n", "abc\ndef"}},
		{`[a-z]+\n?`, []string{"abc", "abc\n"}, []string{"abc\ndef"}},
		{`(?m)[a-z]+$`, []string{"abc"}, []string{"abc\ndef", "abc\n"}},
		{`(?i)prod`, []string{"PROD", "prod"}, []string{"prod2"}},
		{``, []string{""}, []string{"a"}},
	} {
		re, err := CompilePattern(c.pattern)
		if err != nil {
			t.Fatalf("%q: %v", c.pattern, err)
		}
		for _, s := range c.yes {
			if !re.MatchString(s) {
				t.Errorf("%q rejected %q", c.pattern, s)
			}
		}
		for _, s := range c.no {
			if re.MatchString(s) {
				t.Errorf("%q accepted %q", c.pattern, s)
			}
		}
	}
}

func TestCoerceInt(t *testing.T) {
	i := Param{Type: "int"}
	bounded := Param{Type: "int", Min: 1.0, Max: 10.0} // as YAML numbers arrive after Parse
	runCoerce(t, []coerceCase{
		{"cel int64", i, int64(3), int64(3), ""},
		{"go int", i, 3, int64(3), ""},
		{"json 3", i, 3.0, int64(3), ""},
		{"json negative", i, -3.0, int64(-3), ""},
		{"json zero", i, 0.0, int64(0), ""},
		{"json negative zero", i, math.Copysign(0, -1), int64(0), ""},
		{"json 1e3", i, 1e3, int64(1000), ""},
		{"json 3.5", i, 3.5, nil, "want integer"},
		{"json 1e-3", i, 1e-3, nil, "want integer"},
		{"string 3", i, "3", int64(3), ""},
		{"string -3", i, "-3", int64(-3), ""},
		{"string +3", i, "+3", int64(3), ""}, // strconv.ParseInt accepts a leading +
		{"string 007", i, "007", int64(7), ""},
		{"string 3.0", i, "3.0", nil, "want integer"},
		{"string 1e3", i, "1e3", nil, "want integer"},
		{"string hex", i, "0x10", nil, "want integer"},
		{"string underscore", i, "3_000", nil, "want integer"},
		{"string space", i, " 3", nil, "want integer"},
		{"string trailing newline", i, "3\n", nil, "want integer"},
		{"string injection", i, "3; rm -rf /", nil, "want integer"},
		{"string empty", i, "", nil, "want integer"},
		{"string fullwidth", i, "３", nil, "want integer"},
		{"bool", i, true, nil, "want integer, got bool"},
		{"null", i, nil, nil, "want integer, got <nil>"},
		{"list", i, []any{3.0}, nil, "want integer"},

		// Huge values: a float past int64 used to convert to MinInt64.
		{"largest exact", i, float64(MaxSafeInt), int64(MaxSafeInt), ""},
		{"smallest exact", i, -float64(MaxSafeInt), int64(-MaxSafeInt), ""},
		{"2^53", i, float64(1 << 53), nil, "out of range"},
		{"1e18", i, 1e18, nil, "out of range"},
		{"1e300", i, 1e300, nil, "out of range"},
		{"-1e300", i, -1e300, nil, "out of range"},
		{"+Inf", i, math.Inf(1), nil, "want integer"},
		{"-Inf", i, math.Inf(-1), nil, "want integer"},
		{"NaN", i, math.NaN(), nil, "want integer"},
		{"int64 2^62", i, int64(1 << 62), nil, "out of range"},
		{"string past int64", i, "9223372036854775808", nil, "want integer"},
		{"string past 2^53", i, "9007199254740993", nil, "out of range"},

		{"min", bounded, 1.0, int64(1), ""},
		{"max", bounded, 10.0, int64(10), ""},
		{"below min", bounded, 0.0, nil, "below minimum 1"},
		{"negative below min", bounded, -5.0, nil, "below minimum"},
		{"above max", bounded, 11.0, nil, "above maximum 10"},
		{"string above max", bounded, "11", nil, "above maximum"},
		{"huge above max", bounded, 1e300, nil, "out of range"},
		{"negative bounds", Param{Type: "int", Min: -10.0, Max: -1.0}, -10.0, int64(-10), ""},
		{"negative bounds below", Param{Type: "int", Min: -10.0, Max: -1.0}, -11.0, nil, "below minimum"},
		{"fractional min", Param{Type: "int", Min: 1.5}, 1.0, nil, "below minimum"},
		{"fractional min ok", Param{Type: "int", Min: 1.5}, 2.0, int64(2), ""},
		{"int64 bounds", Param{Type: "int", Min: int64(5)}, int64(4), nil, "below minimum"},
		{"string bounds", Param{Type: "int", Min: "5"}, 4.0, nil, "below minimum"},
		{"string bounds ok", Param{Type: "int", Min: "5"}, 5.0, int64(5), ""},
		// A bound that isn't a number used to read as 0.
		{"garbage min", Param{Type: "int", Min: "ten"}, 3.0, nil, "invalid minimum"},
		{"garbage max", Param{Type: "int", Max: "ten"}, -3.0, nil, "invalid maximum"},
		{"bool max", Param{Type: "int", Max: true}, 0.0, nil, "invalid maximum"},
		{"map min", Param{Type: "int", Min: map[string]any{}}, 0.0, nil, "invalid minimum"},
	})
}

func TestCoerceBool(t *testing.T) {
	b := Param{Type: "bool"}
	cases := []coerceCase{
		{"true", b, true, true, ""},
		{"false", b, false, false, ""},
		{"json 1", b, 1.0, nil, "want bool, got float64"},
		{"cel 0", b, int64(0), nil, "want bool, got int64"},
		{"null", b, nil, nil, "want bool"},
	}
	// strconv.ParseBool's spellings, and nothing else.
	for _, s := range []string{"true", "True", "TRUE", "t", "T", "1"} {
		cases = append(cases, coerceCase{"string " + s, b, s, true, ""})
	}
	for _, s := range []string{"false", "False", "FALSE", "f", "F", "0"} {
		cases = append(cases, coerceCase{"string " + s, b, s, false, ""})
	}
	for _, s := range []string{"yes", "no", "on", "off", "y", "", " true", "true\n", "tRUE", "2", "-1"} {
		cases = append(cases, coerceCase{"string " + s, b, s, nil, "want bool"})
	}
	runCoerce(t, cases)
}

func TestCoerceEnum(t *testing.T) {
	env := Param{Type: "enum", Values: []any{"prod", "staging"}}
	num := Param{Type: "enum", Values: []any{1.0, 2.0}} // YAML [1, 2] after Parse
	runCoerce(t, []coerceCase{
		{"value", env, "prod", "prod", ""},
		{"other value", env, "staging", "staging", ""},
		{"case", env, "Prod", nil, "is not one of"},
		{"space", env, "prod ", nil, "is not one of"},
		{"newline", env, "prod\n", nil, "is not one of"},
		{"empty", env, "", nil, "is not one of"},
		{"null", env, nil, nil, "is not one of"},
		{"list", env, []any{"prod"}, nil, "is not one of"},
		{"map", env, map[string]any{"prod": true}, nil, "is not one of"},
		{"injection", env, "prod; rm -rf /", nil, "is not one of"},

		// The declared value is returned, never the input: "1" and int64(1)
		// both become the declared 1.
		{"number", num, 1.0, 1.0, ""},
		{"cel int", num, int64(2), 2.0, ""},
		{"number as string", num, "1", 1.0, ""},
		{"fraction", num, 1.5, nil, "is not one of"},
		{"missing number", num, 3.0, nil, "is not one of"},
		{"no values", Param{Type: "enum"}, "prod", nil, "is not one of"},
	})
}

func TestCoerceDuration(t *testing.T) {
	d := Param{Type: "duration"}
	bounded := Param{Type: "duration", Min: "1m", Max: "1h"}
	patterned := Param{Type: "duration", Pattern: `[0-9]+m`}
	runCoerce(t, []coerceCase{
		{"minutes", d, "5m", "5m", ""},
		{"compound", d, "1h30m", "1h30m", ""},
		{"fraction", d, "1.5h", "1.5h", ""},
		{"millis", d, "300ms", "300ms", ""},
		{"micro sign", d, "5µs", "5µs", ""},
		{"zero", d, "0", "0", ""}, // time.ParseDuration's one unitless value
		{"negative", d, "-5m", "-5m", ""},
		{"no unit", d, "5", nil, "invalid duration"},
		{"space", d, "5 m", nil, "invalid duration"},
		{"word", d, "five minutes", nil, "invalid duration"},
		{"days", d, "1d", nil, "invalid duration"},
		{"empty", d, "", nil, "invalid duration"},
		{"injection", d, "5m; rm -rf /", nil, "invalid duration"},
		{"overflow", d, "9999999999h", nil, "invalid duration"},
		{"json number", d, 300.0, nil, "want duration string, got float64"},
		{"cel int", d, int64(300), nil, "want duration string"},
		{"null", d, nil, nil, "want duration string"},

		// min/max (§3.2) used to be ignored for durations.
		{"at min", bounded, "1m", "1m", ""},
		{"equal to min", bounded, "60s", "60s", ""},
		{"at max", bounded, "1h", "1h", ""},
		{"below min", bounded, "30s", nil, "below minimum 1m"},
		{"negative below min", bounded, "-1h", nil, "below minimum"},
		{"above max", bounded, "61m", nil, "above maximum 1h"},
		{"far above max", bounded, "1000h", nil, "above maximum"},
		{"garbage min", Param{Type: "duration", Min: "soon"}, "5m", nil, "invalid minimum"},
		{"numeric max", Param{Type: "duration", Max: 60.0}, "5m", nil, "invalid maximum"},

		// The pattern lint requires on `from` durations used to be ignored.
		{"pattern ok", patterned, "5m", "5m", ""},
		{"pattern rejects", patterned, "5h", nil, "does not match"},
		{"pattern rejects compound", patterned, "1h5m", nil, "does not match"},
	})
}

func TestCoerceUnknownType(t *testing.T) {
	runCoerce(t, []coerceCase{
		{"float", Param{Type: "float"}, 1.5, nil, `unknown type "float"`},
		{"empty", Param{}, "x", nil, "unknown type"},
		{"case", Param{Type: "String"}, "x", nil, "unknown type"},
	})
}

func TestToFloat(t *testing.T) {
	for _, c := range []struct {
		in   any
		want float64
		ok   bool
	}{
		{1.5, 1.5, true}, {int64(-2), -2, true}, {3, 3, true}, {"4.5", 4.5, true}, {"-1e3", -1000, true},
		{"ten", 0, false}, {"", 0, false}, {"NaN", 0, false}, {true, 0, false}, {nil, 0, false}, {[]any{1.0}, 0, false},
	} {
		got, ok := toFloat(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("toFloat(%#v) = %v, %v; want %v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// paramRunbook is the smallest publishable runbook around one parameter.
func paramRunbook(t *testing.T, param string) *Runbook {
	t.Helper()
	src := `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: params-under-test
  title: Params under test
spec:
  parameters:
    p:
` + param + `
  steps:
    - id: s
      type: shell
      env:
        P: ${{ params.p }}
      run: echo "$P"
`
	rb, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, src)
	}
	return rb
}

// Defaults and bounds are checked at publish: a default that doesn't match
// its type, or a bound that can't be read, would otherwise fail every run.
func TestLintParamDefaultsAndBounds(t *testing.T) {
	for _, c := range []struct {
		name, param, want string // want "" means publishable
	}{
		{"int default ok", "      type: int\n      default: 3", ""},
		{"int default string ok", "      type: int\n      default: \"3\"", ""},
		{"int default word", "      type: int\n      default: three", ".default"},
		{"int default fraction", "      type: int\n      default: 3.5", ".default"},
		{"int default huge", "      type: int\n      default: 1e300", ".default"},
		{"int default bool", "      type: int\n      default: true", ".default"},
		{"int default below min", "      type: int\n      min: 5\n      default: 3", ".default"},
		{"int default above max", "      type: int\n      max: 5\n      default: 6", ".default"},
		{"int bounds ok", "      type: int\n      min: -5\n      max: 5\n      default: 0", ""},
		{"int min word", "      type: int\n      min: five", ".min: must be a number"},
		{"int max bool", "      type: int\n      max: true", ".max: must be a number"},
		{"int min over max", "      type: int\n      min: 10\n      max: 1", "min is greater than max"},
		{"bool default ok", "      type: bool\n      default: false", ""},
		{"bool default yes", "      type: bool\n      default: \"yes\"", ".default"},
		{"bool default number", "      type: bool\n      default: 1", ".default"},
		{"string default number", "      type: string\n      default: 3", ".default"},
		{"string default off pattern", "      type: string\n      pattern: \"[a-z]+\"\n      default: \"a b\"", ".default"},
		{"string default on pattern", "      type: string\n      pattern: \"[a-z]+\"\n      default: ab", ""},
		{"enum default ok", "      type: enum\n      values: [prod, staging]\n      default: prod", ""},
		{"enum default missing", "      type: enum\n      values: [prod, staging]\n      default: dev", ".default"},
		{"enum without values", "      type: enum", "enum parameters need values"},
		{"duration default ok", "      type: duration\n      default: 5m", ""},
		{"duration default unitless", "      type: duration\n      default: \"5\"", ".default"},
		{"duration default number", "      type: duration\n      default: 300", ".default"},
		{"duration bounds ok", "      type: duration\n      min: 1m\n      max: 1h\n      default: 5m", ""},
		{"duration default above max", "      type: duration\n      max: 1h\n      default: 2h", ".default"},
		{"duration numeric min", "      type: duration\n      min: 60", ".min: must be a duration"},
		{"duration garbage max", "      type: duration\n      max: later", ".max: must be a duration"},
		{"duration min over max", "      type: duration\n      min: 1h\n      max: 1m", "min is greater than max"},
		{"unknown type", "      type: float", ".type: must be"},
		{"bad pattern", "      type: string\n      pattern: \"(\"", "invalid regex"},
		{"from without pattern", "      type: string\n      from: alert.labels.x", "must declare a pattern"},
		{"from duration without pattern", "      type: duration\n      from: alert.labels.x", "must declare a pattern"},
		{"from int needs none", "      type: int\n      from: alert.labels.x", ""},
		{"from bad expression", "      type: int\n      from: alert.labels.", ".from"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Lint(paramRunbook(t, c.param))
			if c.want == "" {
				if len(got) > 0 {
					t.Fatalf("unexpected issues: %v", got)
				}
				return
			}
			if !strings.Contains(got.Error(), c.want) {
				t.Fatalf("issues %q, want %q", got.Error(), c.want)
			}
		})
	}
}

// `from` values come from alert data; a value of the wrong type fails the
// run rather than being converted or replaced by the default.
func TestResolveParamsFromExpressions(t *testing.T) {
	alert := expr.Vars{"alert": map[string]any{"labels": map[string]any{
		"count": "3", "bad_count": "3; rm -rf /", "flag": "true", "env": "prod", "wait": "5m",
		"long_wait": "5h", "nested": map[string]any{"a": "b"},
	}, "value": 7.0, "ratio": 0.5}}
	for _, c := range []struct {
		name  string
		param Param
		want  any
		err   string
	}{
		{"int from numeric label", Param{Type: "int", From: "alert.labels.count"}, int64(3), ""},
		{"int from json number", Param{Type: "int", From: "alert.value"}, int64(7), ""},
		{"int from cel arithmetic", Param{Type: "int", From: "alert.value + 1"}, int64(8), ""},
		{"int from fraction", Param{Type: "int", From: "alert.ratio"}, nil, "want integer"},
		{"int from injection", Param{Type: "int", From: "alert.labels.bad_count"}, nil, "want integer"},
		{"int from map", Param{Type: "int", From: "alert.labels.nested"}, nil, "want integer"},
		{"string from number", Param{Type: "string", Pattern: ".*", From: "alert.value"}, nil, "want string, got int64"},
		{"string from map", Param{Type: "string", Pattern: ".*", From: "alert.labels.nested"}, nil, "want string"},
		{"string from list", Param{Type: "string", Pattern: ".*", From: "[alert.labels.env]"}, nil, "want string"},
		{"wrong type is not replaced by the default", Param{Type: "string", Pattern: ".*", From: "alert.value", Default: "x"}, nil, "want string"},
		{"bool from label", Param{Type: "bool", From: "alert.labels.flag"}, true, ""},
		{"bool from number", Param{Type: "bool", From: "alert.value"}, nil, "want bool"},
		{"enum from label", Param{Type: "enum", Values: []any{"prod", "staging"}, From: "alert.labels.env"}, "prod", ""},
		{"enum from other label", Param{Type: "enum", Values: []any{"prod", "staging"}, From: "alert.labels.flag"}, nil, "is not one of"},
		{"duration from label", Param{Type: "duration", Pattern: "[0-9]+m", From: "alert.labels.wait"}, "5m", ""},
		{"duration off pattern", Param{Type: "duration", Pattern: "[0-9]+m", From: "alert.labels.long_wait"}, nil, "does not match"},
		{"duration from number", Param{Type: "duration", Pattern: ".*", From: "alert.value"}, nil, "want duration string"},
		// A from that can't be evaluated (missing label) falls back to the default.
		{"missing label uses default", Param{Type: "string", Pattern: "[a-z]+", From: "alert.labels.missing", Default: "dflt"}, "dflt", ""},
		{"null uses default", Param{Type: "int", From: "null", Default: 4.0}, int64(4), ""},
		{"missing label, required", Param{Type: "string", Pattern: "[a-z]+", From: "alert.labels.missing", Required: true}, nil, "is required"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rb := &Runbook{Spec: Spec{Parameters: map[string]Param{"p": c.param}}}
			got, err := ResolveParams(rb, nil, alert)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("got %v, %v; want error %q", got, err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got["p"], c.want) {
				t.Fatalf("p = %#v (%T), want %#v", got["p"], got["p"], c.want)
			}
		})
	}
}

func TestResolveParamsPrecedence(t *testing.T) {
	rb := &Runbook{Spec: Spec{Parameters: map[string]Param{
		"p":   {Type: "int", From: "alert.value", Default: 1.0},
		"opt": {Type: "string"},
	}}}
	ctx := expr.Vars{"alert": map[string]any{"value": 2.0}}
	got, err := ResolveParams(rb, map[string]any{"p": "3"}, ctx)
	if err != nil || got["p"] != int64(3) {
		t.Fatalf("supplied value should win: %v %v", got, err)
	}
	if _, ok := got["opt"]; ok {
		t.Fatal("an optional parameter with no value was set")
	}
	if got, _ := ResolveParams(rb, nil, ctx); got["p"] != int64(2) {
		t.Fatalf("from should beat the default: %v", got)
	}
	if got, _ := ResolveParams(rb, nil, expr.Vars{}); got["p"] != int64(1) {
		t.Fatalf("default should apply last: %v", got)
	}
	if _, err := ResolveParams(rb, map[string]any{"p": nil}, ctx); err == nil {
		t.Fatal("an explicit null was accepted for an int")
	}
	if _, err := ResolveParams(rb, map[string]any{"p": 1.0, "nope": 1.0}, ctx); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatalf("unknown supplied parameter: %v", err)
	}
}

// The agent re-validates the parameters it receives (JSON-decoded) against
// the signed runbook.
func TestValidateParams(t *testing.T) {
	rb := &Runbook{Spec: Spec{Parameters: map[string]Param{
		"n":    {Type: "int", Required: true, Min: 1.0, Max: 5.0},
		"name": {Type: "string", Pattern: "[a-z]+"},
		"wait": {Type: "duration", Max: "10m"},
	}}}
	for _, c := range []struct {
		name   string
		params map[string]any
		err    string
	}{
		{"as sent", map[string]any{"n": 3.0, "name": "abc", "wait": "5m"}, ""},
		{"optional omitted", map[string]any{"n": 3.0}, ""},
		{"required missing", map[string]any{"name": "abc"}, `"n" is required`},
		{"unknown", map[string]any{"n": 3.0, "x": "y"}, "unknown parameter"},
		{"out of bounds", map[string]any{"n": 6.0}, "above maximum"},
		{"fraction", map[string]any{"n": 3.5}, "want integer"},
		{"pattern", map[string]any{"n": 3.0, "name": "a; b"}, "does not match"},
		{"duration bound", map[string]any{"n": 3.0, "wait": "1h"}, "above maximum"},
		{"wrong type", map[string]any{"n": 3.0, "name": 1.0}, "want string"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateParams(rb, c.params)
			if c.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("got %v, want %q", err, c.err)
			}
		})
	}
}

func TestStepIndex(t *testing.T) {
	rb := &Runbook{Spec: Spec{Steps: []Step{{ID: "a"}, {ID: "b"}, {ID: "c"}}}}
	for id, want := range map[string]int{"a": 0, "b": 1, "c": 2, "d": -1, "": -1, "A": -1, " a": -1} {
		if got := rb.StepIndex(id); got != want {
			t.Errorf("StepIndex(%q) = %d, want %d", id, got, want)
		}
	}
	if got := (&Runbook{}).StepIndex("a"); got != -1 {
		t.Errorf("no steps: got %d", got)
	}
	// Duplicate ids are refused by Lint; StepIndex returns the first.
	dup := &Runbook{Spec: Spec{Steps: []Step{{ID: "x"}, {ID: "x"}}}}
	if got := dup.StepIndex("x"); got != 0 {
		t.Errorf("duplicate id: got %d, want 0", got)
	}
}
