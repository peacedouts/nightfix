package expr

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzEval: any expression either fails to compile or evaluates within the
// time limit (plus slack), without panicking, to a JSON-encodable value.
func FuzzEval(f *testing.F) {
	for _, s := range []string{`alert.labels.service == "api"`, `size(alert.annotations) > 2`, `[1,2,3].map(x, x * 2)`,
		`"a" + "b"`, `alert.value > 3.5 && params.n < 10`, `has(alert.labels.x) ? alert.labels.x : "none"`,
		`[1,2].map(x, [1,2].map(y, [1,2].map(z, x*y*z)))`, `"x".matches("^(a+)+$")`, `1/0`, `int("9223372036854775808")`} {
		f.Add(s)
	}
	vars := Vars{
		"alert":  map[string]any{"labels": map[string]any{"service": "api"}, "annotations": map[string]any{"a": "b"}, "value": 4.0},
		"params": map[string]any{"n": 3},
	}
	f.Fuzz(func(t *testing.T, src string) {
		_ = CheckBool(src)
		if Check(src) != nil {
			return
		}
		start := time.Now()
		v, err := Eval(src, vars)
		if d := time.Since(start); d > maxEvalTime+2*time.Second {
			t.Fatalf("%q took %v", src, d)
		}
		if err != nil {
			return
		}
		if _, err := json.Marshal(v); err != nil {
			t.Fatalf("%q evaluated to a value that isn't JSON: %#v (%v)", src, v, err)
		}
		_ = TemplateExprs("${{ " + src + " }}")
	})
}
