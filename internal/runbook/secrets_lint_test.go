package runbook

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// secretsRunbook declares one secret (db) and is publishable as is. Cases
// replace one line of it.
const secretsRunbook = `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: secrets-under-test
  title: Secrets under test
spec:
  parameters:
    cluster:
      type: string
      pattern: "[a-z-]+"
      default: prod
  secrets:
    db:
      ref: secret://aws-sm/prod/db
      key: password
    hook:
      ref: secret://aws-ssm/prod/hook
  steps:
    - id: context
      type: note
      markdown: Checks the database.
    - id: query
      type: shell
      when: params.cluster == "prod"
      env:
        PGPASSWORD: ${{ secrets.db }}
      files:
        hook.txt: "${{ secrets.hook }}"
      run: psql -c 'select 1'
      outputs:
        ok: result.exitCode == 0
    - id: describe
      type: aws
      service: ecs
      action: DescribeClusters
      input:
        clusters: ["${{ params.cluster }}"]
    - id: wait
      type: wait
      interval: 5s
      check:
        aws:
          service: ecs
          action: DescribeClusters
          input:
            clusters: ["${{ params.cluster }}"]
      until: result.clusters[0].status == "ACTIVE"
  onFailure:
    action: notify
    message: "Check of ${{ params.cluster }} failed."
`

func TestSecretsRunbookIsPublishable(t *testing.T) {
	rb, err := Parse([]byte(secretsRunbook))
	if err != nil {
		t.Fatal(err)
	}
	if is := Lint(rb); len(is) > 0 {
		t.Fatalf("unexpected issues: %v", is)
	}
	if got := SecretsUsed(rb.Spec.Steps[1]); !reflect.DeepEqual(got, []string{"db", "hook"}) {
		t.Fatalf("SecretsUsed = %v", got)
	}
}

// Secrets may appear only in env and files values (and http headers, a step
// type this build refuses); never in run, aws input, outputs, narrative
// text, when/until or onFailure.message; and only as declared secrets.<name>.
func TestLintSecretPlacement(t *testing.T) {
	for _, c := range []struct {
		name, old, new, want string // want "" means publishable
	}{
		// Allowed places and spellings.
		{"env with function", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ base64.encode(bytes(secrets.db)) }}", ""},
		{"env interpolated", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: \"user:${{ secrets.db }}@host\"", ""},
		{"env two secrets", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets.db }}${{ secrets.hook }}", ""},
		{"env tight template", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{secrets.db}}", ""},
		{"param named like secrets", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ params.secrets_dir }}", ""},

		// Undeclared or oddly spelled references.
		{"env undeclared", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets.dbx }}", `undeclared secret "dbx"`},
		{"files undeclared", `hook.txt: "${{ secrets.hook }}"`, `hook.txt: "${{ secrets.nope }}"`, `undeclared secret "nope"`},
		{"index syntax", "PGPASSWORD: ${{ secrets.db }}", `PGPASSWORD: ${{ secrets["db"] }}`, "reference secrets as secrets.<name>"},
		{"spaced dot", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets . db }}", "reference secrets as secrets.<name>"},
		{"space before dot", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets .db }}", "reference secrets as secrets.<name>"},
		{"whole map", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets }}", "reference secrets as secrets.<name>"},
		{"macro over secrets", "PGPASSWORD: ${{ secrets.db }}", "PGPASSWORD: ${{ secrets.exists(k, k == 'db') }}", `undeclared secret "exists"`},
		{"files index syntax", `hook.txt: "${{ secrets.hook }}"`, `hook.txt: "${{ secrets['hook'] }}"`, "reference secrets as secrets.<name>"},

		// Places secrets may never go.
		{"run", "run: psql -c 'select 1'", "run: echo ${{ secrets.db }}", "templates are not allowed in run"},
		{"aws input", `clusters: ["${{ params.cluster }}"]` + "\n    - id: wait", `clusters: ["${{ secrets.db }}"]` + "\n    - id: wait", "secrets may only be referenced"},
		{"aws input spaced", `clusters: ["${{ params.cluster }}"]` + "\n    - id: wait", `clusters: ["${{ secrets . db }}"]` + "\n    - id: wait", "secrets may only be referenced"},
		{"aws input index", `clusters: ["${{ params.cluster }}"]` + "\n    - id: wait", `clusters: ["${{ secrets['db'] }}"]` + "\n    - id: wait", "secrets may only be referenced"},
		{"aws input nested template", `clusters: ["${{ params.cluster }}"]` + "\n    - id: wait", `clusters: ["${{ \"${{ secrets.db }}\" }}"]` + "\n    - id: wait", "secrets may only be referenced"},
		{"wait check input", `            clusters: ["${{ params.cluster }}"]`, `            clusters: ["${{ secrets.db }}"]`, "secrets may only be referenced"},
		{"outputs", "ok: result.exitCode == 0", "ok: secrets.db", "secrets can never be step outputs"},
		{"outputs index", "ok: result.exitCode == 0", `ok: secrets["db"]`, "secrets can never be step outputs"},
		{"note markdown", "markdown: Checks the database.", "markdown: Password is ${{ secrets.db }}", "templates are not allowed in markdown"},
		{"when", `when: params.cluster == "prod"`, `when: secrets.db == "x"`, ".when: secrets may only be referenced"},
		{"when index", `when: params.cluster == "prod"`, `when: secrets["db"] == "x"`, ".when: secrets may only be referenced"},
		{"until", `until: result.clusters[0].status == "ACTIVE"`, `until: result.clusters[0].status == secrets.db`, ".until: secrets may only be referenced"},
		{"onFailure message", `message: "Check of ${{ params.cluster }} failed."`, `message: "Check failed: ${{ secrets.db }}"`, "spec.onFailure.message: secrets may only be referenced"},
		{"onFailure message spaced", `message: "Check of ${{ params.cluster }} failed."`, `message: "Check failed: ${{ secrets . db }}"`, "spec.onFailure.message: secrets may only be referenced"},
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

// checkSecretRefs is what keeps env and files values to declared secrets.
func TestCheckSecretRefs(t *testing.T) {
	rb := &Runbook{Spec: Spec{Secrets: map[string]SecretRef{"db": {Ref: "secret://aws-sm/db"}, "db_2": {Ref: "secret://aws-sm/db2"}}}}
	for _, c := range []struct {
		v    string
		want []string
	}{
		{"${{ secrets.db }}", nil},
		{"${{ secrets.db_2 }}", nil},
		{"plain text", nil},
		{"${{ params.x }}", nil},
		{"${{ secrets.db.size() > 0 ? secrets.db : 'none' }}", nil},
		{"${{ secrets.db }} and ${{ secrets.other }}", []string{`undeclared secret "other"`}},
		{"${{ secrets.d }}", []string{`undeclared secret "d"`}},
		{"${{ secrets.DB }}", []string{`undeclared secret "DB"`}},
		{`${{ secrets["db"] }}`, []string{"reference secrets as secrets.<name>"}},
		{"${{ secrets . db }}", []string{"reference secrets as secrets.<name>"}},
		{"${{ secrets.db }}${{ secrets }}", []string{"reference secrets as secrets.<name>"}},
		{"${{ has(secrets.db) }}", nil},
		// Not a template: never rendered, but an undeclared name still reads
		// as a mistake.
		{"secrets.nope", []string{`undeclared secret "nope"`}},
	} {
		var got []string
		checkSecretRefs("p", c.v, rb, func(_, format string, args ...any) {
			got = append(got, fmt.Sprintf(format, args...))
		})
		if len(got) != len(c.want) {
			t.Errorf("%q: issues %q, want %q", c.v, got, c.want)
			continue
		}
		for i := range got {
			if !strings.Contains(got[i], c.want[i]) {
				t.Errorf("%q: issue %q, want %q", c.v, got[i], c.want[i])
			}
		}
	}
}

// Conditions (trigger matches, when, until) whose type is known and isn't
// bool are refused at publish: they could never be true.
func TestLintConditionsMustBeBool(t *testing.T) {
	for field, cond := range map[string]string{"when": `size(params)`, "until": `"done"`} {
		src := strings.Replace(conditionRunbook, "WHEN", `"true"`, 1)
		if field == "when" {
			src = strings.Replace(conditionRunbook, "WHEN", cond, 1)
		}
		if field == "until" {
			src = strings.Replace(src, `until: result.ok == true`, "until: '"+cond+"'", 1)
		}
		rb, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%s: parse: %v", field, err)
		}
		found := false
		for _, is := range Lint(rb) {
			if strings.Contains(is.Path, field) && strings.Contains(is.Message, "not a condition") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %q was not refused: %v", field, cond, Lint(rb))
		}
	}
}

const conditionRunbook = `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: cond
  title: Conditions
spec:
  target:
    agentSelector:
      env: prod
  triggers:
    - type: manual
  steps:
    - id: check
      type: shell
      when: 'WHEN'
      run: echo hi
    - id: wait
      type: wait
      interval: 10s
      timeout: 1m
      check:
        aws:
          service: ecs
          action: DescribeServices
          input:
            cluster: c
      until: result.ok == true
`

func TestParseRefusesMultipleDocuments(t *testing.T) {
	src := conditionRunbook + "---\napiVersion: nightfix.dev/v1alpha1\nkind: Runbook\n"
	if _, err := Parse([]byte(strings.Replace(src, "'WHEN'", "'true'", 1))); err == nil || !strings.Contains(err.Error(), "one YAML document") {
		t.Fatalf("a file with two documents: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(conditionRunbook, "'WHEN'", "'true'", 1))); err != nil {
		t.Fatalf("one document: %v", err)
	}
}
