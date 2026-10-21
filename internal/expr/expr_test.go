package expr

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvalAgainstJSONResult(t *testing.T) {
	var result map[string]any
	json.Unmarshal([]byte(`{"services":[{"runningCount":2,"desiredCount":2,"deployments":[{"id":"d1"}]}]}`), &result)
	ok, err := EvalBool(`result.services[0].deployments.size() == 1 &&
		result.services[0].runningCount == result.services[0].desiredCount`, Vars{"result": result})
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
}

func TestMatchAndStringFunctions(t *testing.T) {
	alert := map[string]any{"source": "cloudwatch", "labels": map[string]any{"alarm_name": "ecs-unhealthy-checkout"}}
	ok, err := EvalBool(`alert.source == "cloudwatch" && alert.labels.alarm_name.startsWith("ecs-unhealthy-")`, Vars{"alert": alert})
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	v, err := Eval(`int(result.stdout.trim())`, Vars{"result": map[string]any{"stdout": " 42\n"}})
	if err != nil || v != int64(42) {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestRender(t *testing.T) {
	vars := Vars{"params": map[string]any{"cluster": "prod-east", "service": "checkout-api", "n": 3}}
	in := map[string]any{
		"cluster":  "${{ params.cluster }}",
		"services": []any{"${{ params.service }}"},
		"count":    "${{ params.n }}",
		"msg":      "restart ${{ params.service }} on ${{ params.cluster }}",
		"plain":    true,
	}
	out, err := Render(in, vars)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"cluster": "prod-east", "services": []any{"checkout-api"}, "count": int64(3),
		"msg": "restart checkout-api on prod-east", "plain": true,
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %#v", out)
	}
}

func TestInvalidExpression(t *testing.T) {
	if err := Check(`alert.labels.x ==`); err == nil {
		t.Fatal("expected compile error")
	}
	if _, err := Eval(`missing.field`, Vars{}); err == nil {
		t.Fatal("expected error for undeclared variable")
	}
}

func TestExpensiveFunctionsAreRefused(t *testing.T) {
	for _, src := range []string{
		`"aaaaaaaaaa".replace("a","aaaaaaaaaa").replace("a","aaaaaaaaaa")`,
		`"%s".format(["x"])`,
		`["a","b"].join("-")`,
		`lists.range(50000000).size() > 0`,
		`alert.summary.replace("a", "b") == ""`,
	} {
		if err := Check(src); err == nil {
			t.Errorf("Check(%s) accepted an expression that can exhaust memory", src)
		}
	}
	if err := Check(strings.Repeat("1 + ", MaxSourceLen) + "1 == 2"); err == nil {
		t.Error("overlong expression accepted")
	}
	// Ordinary string helpers still work.
	if v, err := Eval(`"  42 ".trim() == "42" && "a-b".split("-").size() == 2 && "ABC".lowerAscii() == "abc"`, nil); err != nil || v != true {
		t.Errorf("got %v, %v", v, err)
	}
}

// Chained or nested macros whose bodies repeat their variable build
// exponentially large shared structures inside the cost limit; one
// expression could pin a worker for minutes or crash it.
func TestMacroAmplificationIsBounded(t *testing.T) {
	chain := func(depth int, body string) string {
		s := `[1,2,3,4,5,6,7,8]`
		for i := 0; i < depth; i++ {
			v := fmt.Sprintf("v%d", i)
			s = fmt.Sprintf("[%s].map(%s, %s)[0]", s, v, strings.ReplaceAll(body, "X", v))
		}
		return s
	}
	for _, src := range []string{
		chain(4, "X+X"),
		chain(4, "[X, X]"),
		chain(2, "[X, X, X, X, X]") + ".size() > 0", // too many uses of the variable
		chain(5, "X") + ".size() > 0",
	} {
		if err := Check(src); err == nil {
			t.Errorf("accepted %s", src)
		}
	}
	// Within the limits the worst case stays small and fast.
	start := time.Now()
	if _, err := Eval(chain(3, "[X, X, X, X]"), nil); err != nil {
		t.Fatalf("bounded expression failed: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("bounded expression took %v", d)
	}
	// Ordinary macro use still works.
	if v, err := Eval(`alert.labels.exists(k, k == "service") && [1,2,3].filter(x, x > 1).size() == 2 && [1,2].all(x, x > 0)`,
		Vars{"alert": map[string]any{"labels": map[string]any{"service": "a"}}}); err != nil || v != true {
		t.Fatalf("got %v, %v", v, err)
	}
	// A huge result is refused instead of converted.
	big := make([]any, maxResultValues+1)
	if _, err := Eval(`params.items`, Vars{"params": map[string]any{"items": big}}); err == nil {
		t.Fatal("oversized result converted")
	}
}
