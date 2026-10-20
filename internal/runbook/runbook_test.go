package runbook

import (
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/expr"
)

func load(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../examples/runbooks/ecs-service-restart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExampleIsValid(t *testing.T) {
	rb, err := Parse(load(t))
	if err != nil {
		t.Fatal(err)
	}
	if is := Lint(rb); len(is) > 0 {
		t.Fatalf("unexpected issues: %v", is)
	}
	if !rb.Spec.Steps[1].IsIdempotent() || rb.Spec.Steps[2].IsIdempotent() {
		t.Fatal("DescribeServices should be idempotent, UpdateService should not")
	}
}

func TestDigestIgnoresFormatting(t *testing.T) {
	a, _ := Parse(load(t))
	// Same content, different key order and quoting.
	reordered := strings.Replace(string(load(t)), "  team: platform\n  tags: [ecs, restart]\n",
		"  tags: [\"ecs\", \"restart\"]\n  team: platform\n", 1)
	b, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	_, da, _ := Canonical(a)
	_, db, _ := Canonical(b)
	if da != db {
		t.Fatalf("digests differ: %s vs %s", da, db)
	}
	ca, _, _ := Canonical(a)
	back, err := FromCanonical(ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, d2, _ := Canonical(back); d2 != da {
		t.Fatal("canonical round trip changed the digest")
	}
}

func lintErrs(t *testing.T, mutate func(string) string) string {
	t.Helper()
	rb, err := Parse([]byte(mutate(string(load(t)))))
	if err != nil {
		return err.Error()
	}
	return Lint(rb).Error()
}

func TestLintRules(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"template in run", "    - id: restart\n", "    - id: sh\n      type: shell\n      run: echo ${{ params.service }}\n    - id: restart\n", "templates are not allowed in run"},
		{"from without pattern", "      pattern: \"^[A-Za-z0-9_-]{1,255}$\"\n    service:", "    service:", "must declare a pattern"},
		{"auto without services", "      services: [checkout-api]\n", "", "auto triggers must list the services"},
		{"auto without cooldown", "      cooldown: 15m\n", "", "cooldown: required"},
		{"secret in aws input", "        forceNewDeployment: true\n", "        forceNewDeployment: true\n        token: ${{ secrets.x }}\n", "secrets may only be referenced"},
		{"unknown field", "  policy:\n", "  polcy:\n    x: 1\n  policy:\n", "unknown field"},
		{"unsupported type", "      type: note\n", "      type: approval\n", "not supported in this build"},
		{"non read-only wait", "          action: DescribeServices\n          input:\n            cluster", "          action: UpdateService\n          input:\n            cluster", "wait checks must be read-only"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := lintErrs(t, func(s string) string {
				if !strings.Contains(s, c.old) {
					t.Fatalf("fixture text %q not found", c.old)
				}
				return strings.Replace(s, c.old, c.new, 1)
			})
			if !strings.Contains(got, c.want) {
				t.Fatalf("want %q in %q", c.want, got)
			}
		})
	}
}

func TestResolveParams(t *testing.T) {
	rb, _ := Parse(load(t))
	ctx := expr.Vars{"alert": map[string]any{"labels": map[string]any{"cluster": "prod-east", "service": "checkout-api"}}}
	p, err := ResolveParams(rb, nil, ctx)
	if err != nil || p["cluster"] != "prod-east" || p["service"] != "checkout-api" {
		t.Fatalf("got %v %v", p, err)
	}
	// Injection attempt via alert labels is rejected by the pattern.
	ctx = expr.Vars{"alert": map[string]any{"labels": map[string]any{"cluster": "prod; rm -rf /", "service": "x"}}}
	if _, err := ResolveParams(rb, nil, ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected pattern rejection, got %v", err)
	}
	if err := ValidateParams(rb, map[string]any{"cluster": "a", "service": "b", "extra": 1}); err == nil {
		t.Fatal("unknown param accepted")
	}
}
