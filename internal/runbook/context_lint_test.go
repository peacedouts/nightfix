package runbook

import (
	"strings"
	"testing"
)

// Alert and incident data are shaped by whoever can publish an alert, and
// the agent validates only parameters, so step inputs can't use them
// directly; they go through a `from:` parameter with a pattern. Places the
// control plane renders for humans (onFailure.message) may still use them.
func TestLintAlertDataInStepInputs(t *testing.T) {
	waitStep := "\n    - id: wait"
	for _, c := range []struct {
		name, old, new, want string // want "" means publishable
	}{
		{"aws input alert", `clusters: ["${{ params.cluster }}"]` + waitStep, `clusters: ["${{ alert.labels.cluster }}"]` + waitStep, "alert data can't be used in step inputs"},
		{"aws input interpolated", `clusters: ["${{ params.cluster }}"]` + waitStep, `clusters: ["prod-${{ alert.labels['cluster'] }}"]` + waitStep, "alert data can't be used in step inputs"},
		{"wait check input", `            clusters: ["${{ params.cluster }}"]`, `            clusters: ["${{ incident.title }}"]`, "incident data can't be used in step inputs"},
		{"env", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets.db }}\n        SVC: ${{ alert.annotations.svc }}", "alert data can't be used in step inputs"},
		{"files", `hook.txt: "${{ secrets.hook }}"`, `hook.txt: "${{ secrets.hook }}"` + "\n        alert.json: \"${{ string(alert.raw) }}\"", "alert data can't be used in step inputs"},
		{"macro over alert", `clusters: ["${{ params.cluster }}"]` + waitStep, `clusters: ["${{ alert.labels.exists(k, k == 'x') ? 'a' : 'b' }}"]` + waitStep, "alert data can't be used in step inputs"},

		{"outputs", "ok: result.exitCode == 0", "ok: alert.labels.service", "alert data can't be used in step outputs"},

		// Allowed.
		{"params", `clusters: ["${{ params.cluster }}"]` + waitStep, `clusters: ["${{ params.cluster }}-${{ run.id }}"]` + waitStep, ""},
		{"word in a string", `clusters: ["${{ params.cluster }}"]` + waitStep, `clusters: ["${{ 'alert-' + params.cluster }}"]` + waitStep, ""},
		{"onFailure message", `message: "Check of ${{ params.cluster }} failed."`, `message: "Check of ${{ alert.labels.cluster }} for ${{ incident.title }} failed."`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(secretsRunbook, c.old) {
				t.Fatalf("fixture text %q not found", c.old)
			}
			rb, err := Parse([]byte(strings.Replace(secretsRunbook, c.old, c.new, 1)))
			if err != nil {
				t.Fatal(err)
			}
			got := Lint(rb)
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
