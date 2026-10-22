package runbook

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/expr"
)

// Issue is one validation finding.
type Issue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (i Issue) String() string { return i.Path + ": " + i.Message }

// Issues is a list of findings; it implements error when non-empty.
type Issues []Issue

func (is Issues) Error() string {
	var b strings.Builder
	for i, x := range is {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(x.String())
	}
	return b.String()
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	stepIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// Step types the v1alpha1 schema defines.
var knownStepTypes = map[string]bool{
	"note": true, "manual": true, "approval": true, "shell": true, "python": true,
	"aws": true, "container": true, "http": true, "wait": true,
}

// SupportedStepTypes are the types this build can execute end to end.
// The others are valid schema but rejected at publish until implemented.
var SupportedStepTypes = map[string]bool{"note": true, "approval": true, "shell": true, "aws": true, "wait": true}

// AWSServices this build can call (JSON-protocol services; see agent/awscall).
var AWSServices = map[string]bool{
	"ecs": true, "secretsmanager": true, "ssm": true, "dynamodb": true, "logs": true,
	"kms": true, "elasticache": false, "rds": false,
}

// Lint applies the publish-time rules from runbook-schema.md. A runbook with
// any issue is not publishable.
// Size limits that keep linting (which compiles every expression) cheap
// and bounded no matter what's submitted. Real runbooks are far smaller.
const (
	MaxSteps       = 100
	MaxExpressions = 500
	MaxRetries     = 10
)

func Lint(rb *Runbook) Issues {
	var is Issues
	add := func(path, format string, args ...any) {
		is = append(is, Issue{path, fmt.Sprintf(format, args...)})
	}
	// Refuse oversized runbooks before compiling anything: each distinct
	// expression is compiled, and a single validate request could otherwise
	// make the shared control plane compile tens of thousands of them.
	if len(rb.Spec.Steps) > MaxSteps {
		add("spec.steps", "%d steps; the limit is %d", len(rb.Spec.Steps), MaxSteps)
		return is
	}
	if n := countExpressions(rb); n > MaxExpressions {
		add("spec", "%d expressions; the limit is %d", n, MaxExpressions)
		return is
	}

	if rb.APIVersion != APIVersion {
		add("apiVersion", "must be %q", APIVersion)
	}
	if rb.Kind != Kind {
		add("kind", "must be %q", Kind)
	}
	if !nameRe.MatchString(rb.Metadata.Name) {
		add("metadata.name", "must match %s", nameRe)
	}
	if strings.TrimSpace(rb.Metadata.Title) == "" {
		add("metadata.title", "is required")
	}

	// Parameters.
	for _, name := range sortedKeys(rb.Spec.Parameters) {
		p := rb.Spec.Parameters[name]
		path := "spec.parameters." + name
		switch p.Type {
		case "string", "int", "bool", "enum", "duration":
		default:
			add(path+".type", "must be string, int, bool, enum or duration")
		}
		if p.Pattern != "" {
			if _, err := CompilePattern(p.Pattern); err != nil {
				add(path+".pattern", "invalid regex: %v", err)
			}
		}
		if p.Type == "enum" && len(p.Values) == 0 {
			add(path+".values", "enum parameters need values")
		}
		if p.From != "" {
			// Alert data is attacker-influenceable: derived params must be constrained.
			if p.Pattern == "" && p.Type != "enum" && p.Type != "bool" && p.Type != "int" {
				add(path, "parameters with `from` must declare a pattern or be an enum")
			}
			if err := expr.Check(p.From); err != nil {
				add(path+".from", "%v", err)
			}
		}
		lintBounds(path, p, add)
		if p.Default != nil {
			if _, err := coerceParam(name, p, p.Default); err != nil {
				add(path+".default", "%v", err)
			}
		}
	}

	// Secrets.
	for _, name := range sortedKeys(rb.Spec.Secrets) {
		s := rb.Spec.Secrets[name]
		if _, _, err := ParseSecretRef(s.Ref); err != nil {
			add("spec.secrets."+name+".ref", "%v", err)
		}
	}

	// Policy.
	for i, r := range rb.Spec.Policy.AllowedRoles {
		switch strings.ToLower(r) {
		case "responder", "admin", "owner":
		default:
			add(fmt.Sprintf("spec.policy.allowedRoles[%d]", i), "must be Responder, Admin or Owner")
		}
	}
	if rb.Spec.Policy.Timeout != "" {
		d, err := time.ParseDuration(rb.Spec.Policy.Timeout)
		if err != nil || d <= 0 || d > 4*time.Hour {
			add("spec.policy.timeout", "must be a duration up to 4h")
		}
	}

	// Steps.
	if len(rb.Spec.Steps) == 0 {
		add("spec.steps", "at least one step is required")
	}
	seen := map[string]bool{}
	hasManual := false
	for i, s := range rb.Spec.Steps {
		path := fmt.Sprintf("spec.steps[%d]", i)
		if !stepIDRe.MatchString(s.ID) {
			add(path+".id", "must match %s", stepIDRe)
		} else if seen[s.ID] {
			add(path+".id", "duplicate step id %q", s.ID)
		}
		seen[s.ID] = true
		if !knownStepTypes[s.Type] {
			add(path+".type", "unknown step type %q", s.Type)
			continue
		}
		if !SupportedStepTypes[s.Type] {
			add(path+".type", "step type %q is not supported in this build yet", s.Type)
		}
		if s.Type == "manual" {
			hasManual = true
		}
		lintStep(path, s, rb, add)
	}

	// Triggers.
	for i, t := range rb.Spec.Triggers {
		path := fmt.Sprintf("spec.triggers[%d]", i)
		switch t.Type {
		case "manual", "api":
			if t.Match != "" || t.Mode != "" || t.BeforePaging || len(t.Services) > 0 {
				add(path, "%s triggers take no match, mode, services or beforePaging", t.Type)
			}
			continue
		case "alert":
		default:
			add(path+".type", "must be manual, alert or api")
			continue
		}
		if t.Match == "" {
			add(path+".match", "alert triggers need a match expression")
		} else if err := expr.CheckBool(t.Match); err != nil {
			add(path+".match", "%v", err)
		}
		switch t.Mode {
		case "suggest", "one-click", "auto":
		default:
			add(path+".mode", "must be suggest, one-click or auto")
		}
		if t.BeforePaging && t.Mode != "auto" {
			add(path+".beforePaging", "only applies to auto triggers")
		}
		if t.Mode == "auto" {
			if len(t.Services) == 0 {
				add(path+".services", "auto triggers must list the services they may act on")
			}
			if t.Cooldown == "" {
				add(path+".cooldown", "required for auto triggers")
			} else if d, err := time.ParseDuration(t.Cooldown); err != nil || d <= 0 {
				add(path+".cooldown", "must be a positive duration")
			}
			if t.MaxRunsPerHour <= 0 {
				add(path+".maxRunsPerHour", "required for auto triggers")
			}
			if hasManual {
				add(path, "auto triggers cannot be used with manual steps")
			}
			for _, name := range sortedKeys(rb.Spec.Parameters) {
				p := rb.Spec.Parameters[name]
				if p.Required && p.From == "" && p.Default == nil {
					add(path, "parameter %q must resolve via from or default for auto runs", name)
				}
			}
		}
	}

	if f := rb.Spec.OnFailure; f != nil {
		switch f.Action {
		case "escalate", "notify", "none":
		default:
			add("spec.onFailure.action", "must be escalate, notify or none")
		}
		lintTemplate("spec.onFailure.message", f.Message, false, add)
	}
	return is
}

// lintBounds checks min/max: numbers for int, duration strings for duration,
// and min no greater than max. (A bound that can't be read would otherwise
// fail every run, or, before, silently read as 0.)
func lintBounds(path string, p Param, add func(string, string, ...any)) {
	switch p.Type {
	case "int":
		lo, lok := toFloat(p.Min)
		hi, hok := toFloat(p.Max)
		if p.Min != nil && !lok {
			add(path+".min", "must be a number")
		}
		if p.Max != nil && !hok {
			add(path+".max", "must be a number")
		}
		if p.Min != nil && p.Max != nil && lok && hok && lo > hi {
			add(path, "min is greater than max")
		}
	case "duration":
		lo, lok := toDuration(p.Min)
		hi, hok := toDuration(p.Max)
		if p.Min != nil && !lok {
			add(path+".min", "must be a duration such as 30s or 5m")
		}
		if p.Max != nil && !hok {
			add(path+".max", "must be a duration such as 30s or 5m")
		}
		if p.Min != nil && p.Max != nil && lok && hok && lo > hi {
			add(path, "min is greater than max")
		}
	}
}

func lintStep(path string, s Step, rb *Runbook, add func(string, string, ...any)) {
	// when: and until: are decided without secrets (on the control plane, and
	// on the agent with only the check's result).
	for _, f := range [][2]string{{"when", s.When}, {"until", s.Until}} {
		if secretIdentRe.MatchString(f[1]) {
			add(path+"."+f[0], "secrets may only be referenced in env, files or http headers")
		}
	}
	if s.When != "" {
		if err := expr.CheckBool(s.When); err != nil {
			add(path+".when", "%v", err)
		} else if whenTargetRe.MatchString(s.When) {
			// when: is evaluated on the control plane, before an agent is
			// picked, so target isn't known yet: it would fail every run.
			add(path+".when", "can't reference target (when: is decided before an agent is chosen); use params instead")
		}
	}
	if s.Timeout != "" {
		if d, err := time.ParseDuration(s.Timeout); err != nil || d <= 0 {
			add(path+".timeout", "must be a positive duration")
		}
	}
	if s.Retries < 0 || s.Retries > MaxRetries {
		add(path+".retries", "must be between 0 and %d", MaxRetries)
	}
	switch s.OnFailure {
	case "", "stop", "continue", "escalate":
	default:
		add(path+".onFailure", "must be stop, continue or escalate")
	}
	for _, k := range sortedKeys(s.Outputs) {
		if strings.Contains(s.Outputs[k], "secrets") {
			add(path+".outputs."+k, "secrets can never be step outputs")
		}
		if err := expr.Check(s.Outputs[k]); err != nil {
			add(path+".outputs."+k, "%v", err)
		}
	}
	// Narrative text is shown to humans; no templating, no secrets.
	if expr.HasTemplate(s.Markdown) {
		add(path+".markdown", "templates are not allowed in markdown")
	}

	switch s.Type {
	case "approval":
		if s.Count < 0 || s.Count > 10 {
			add(path+".count", "must be between 1 and 10")
		}
		for i, r := range s.FromRoles {
			switch strings.ToLower(r) {
			case "responder", "admin", "owner":
			case "viewer":
				add(fmt.Sprintf("%s.fromRoles[%d]", path, i), "viewers can't approve steps")
			default:
				add(fmt.Sprintf("%s.fromRoles[%d]", path, i), "must be Responder, Admin or Owner")
			}
		}
		if s.ExpiresAfter != "" {
			d, err := time.ParseDuration(s.ExpiresAfter)
			switch {
			case err != nil || d < time.Minute:
				add(path+".expiresAfter", "must be a duration of at least 1m")
			case d > rb.RunTimeout():
				add(path+".expiresAfter", "can't be longer than the run timeout (%s)", rb.RunTimeout())
			}
		}
		if s.Retries != 0 || s.Timeout != "" {
			add(path, "approval steps take expiresAfter, not timeout or retries")
		}
	case "shell", "python":
		if strings.TrimSpace(s.Run) == "" {
			add(path+".run", "is required")
		}
		// The core injection rule: untrusted input never reaches a script string.
		if expr.HasTemplate(s.Run) {
			add(path+".run", "templates are not allowed in run; pass values through env or files")
		}
		for _, k := range sortedKeys(s.Env) {
			if !envKeyRe.MatchString(k) {
				add(path+".env."+k, "env names must match %s", envKeyRe)
			} else if ReservedEnv(k) {
				add(path+".env."+k, "%s is reserved: the shell or the agent acts on it", k)
			}
			lintTemplate(path+".env."+k, s.Env[k], true, add)
			checkSecretRefs(path+".env."+k, s.Env[k], rb, add)
		}
		for _, k := range sortedKeys(s.Files) {
			lintTemplate(path+".files."+k, s.Files[k], true, add)
			checkSecretRefs(path+".files."+k, s.Files[k], rb, add)
		}
		switch s.RunOn {
		case "", "agent":
		case "ssm":
			add(path+".runOn", "ssm execution is not supported in this build yet")
		default:
			add(path+".runOn", "must be agent or ssm")
		}
	case "aws":
		lintAWSCall(path, s.Service, s.Action, s.Input, add)
		if s.AssumeRole != "" {
			add(path+".assumeRole", "assumeRole is not supported in this build yet")
		}
	case "wait":
		if s.Check == nil || (s.Check.AWS == nil && s.Check.HTTP == nil) {
			add(path+".check", "wait steps need an aws or http check")
		} else if s.Check.AWS != nil {
			lintAWSCall(path+".check.aws", s.Check.AWS.Service, s.Check.AWS.Action, s.Check.AWS.Input, add)
			if a := s.Check.AWS.Action; !(strings.HasPrefix(a, "Describe") || strings.HasPrefix(a, "List") || strings.HasPrefix(a, "Get")) {
				add(path+".check.aws.action", "wait checks must be read-only (Describe*, List*, Get*)")
			}
		} else {
			add(path+".check.http", "http checks are not supported in this build yet")
		}
		if s.Until == "" {
			add(path+".until", "is required")
		} else if err := expr.CheckBool(s.Until); err != nil {
			add(path+".until", "%v", err)
		}
		if s.Interval != "" {
			if d, err := time.ParseDuration(s.Interval); err != nil || d < time.Second {
				add(path+".interval", "must be a duration of at least 1s")
			}
		}
	case "container":
		if !strings.Contains(s.Image, "@sha256:") {
			add(path+".image", "container images must be pinned by digest")
		}
	}
}

func lintAWSCall(path, service, action string, input map[string]any, add func(string, string, ...any)) {
	if !AWSServices[service] {
		add(path+".service", "aws service %q is not supported in this build", service)
	}
	if action == "" {
		add(path+".action", "is required")
	}
	walkStrings(input, func(p, v string) {
		lintTemplate(path+".input"+p, v, false, add)
	})
}

// lintTemplate compiles every ${{ }} in v. Secrets are only allowed where
// allowSecrets is set (env, files, http headers).
func lintTemplate(path, v string, allowSecrets bool, add func(string, string, ...any)) {
	for _, e := range expr.TemplateExprs(v) {
		if err := expr.Check(e); err != nil {
			add(path, "%v", err)
		}
		if !allowSecrets && strings.Contains(e, "secrets") {
			add(path, "secrets may only be referenced in env, files or http headers")
		}
	}
}

var whenTargetRe = regexp.MustCompile(`\btarget\b`)

var secretUseRe = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)

// secretIdentRe finds the secrets variable however it's spelled.
var secretIdentRe = regexp.MustCompile(`\bsecrets\b`)

// checkSecretRefs requires every secret a value uses to be declared. Only
// the secrets.<name> form is accepted: it's the form SecretsUsed finds, so a
// secret spelled any other way (secrets["db"], secrets . db, a quoted CEL
// identifier) would never be resolved, and therefore never redacted.
func checkSecretRefs(path, v string, rb *Runbook, add func(string, string, ...any)) {
	for _, m := range secretUseRe.FindAllStringSubmatch(v, -1) {
		if _, ok := rb.Spec.Secrets[m[1]]; !ok {
			add(path, "references undeclared secret %q", m[1])
		}
	}
	for _, e := range expr.TemplateExprs(v) {
		if secretIdentRe.MatchString(secretUseRe.ReplaceAllString(e, "")) {
			add(path, "reference secrets as secrets.<name>")
			return
		}
	}
}

// SecretsUsed returns the declared secret names a step references.
func SecretsUsed(s Step) []string {
	set := map[string]bool{}
	scan := func(v string) {
		for _, m := range secretUseRe.FindAllStringSubmatch(v, -1) {
			set[m[1]] = true
		}
	}
	for _, v := range s.Env {
		scan(v)
	}
	for _, v := range s.Files {
		scan(v)
	}
	for _, v := range s.Headers {
		scan(v)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseSecretRef splits secret://<provider>/<name> into provider and name.
func ParseSecretRef(ref string) (provider, name string, err error) {
	rest, ok := strings.CutPrefix(ref, "secret://")
	if !ok {
		return "", "", fmt.Errorf("secret refs must start with secret://")
	}
	provider, name, ok = strings.Cut(rest, "/")
	if !ok || name == "" {
		return "", "", fmt.Errorf("secret ref must be secret://<provider>/<name>")
	}
	switch provider {
	case "aws-sm", "aws-ssm":
	case "vault":
		return "", "", fmt.Errorf("vault secrets are not supported yet")
	default:
		return "", "", fmt.Errorf("unknown secret provider %q", provider)
	}
	return provider, name, nil
}

func walkStrings(v any, fn func(path, s string)) {
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch x := v.(type) {
		case string:
			fn(p, x)
		case map[string]any:
			for _, k := range sortedKeys(x) {
				walk(p+"."+k, x[k])
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", p, i), e)
			}
		}
	}
	walk("", v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// countExpressions counts every CEL expression Lint would compile: each
// ${{ }} anywhere in the runbook, plus when/until/outputs/match/from fields.
func countExpressions(rb *Runbook) int {
	b, _ := json.Marshal(rb)
	n := strings.Count(string(b), "${{")
	for _, p := range rb.Spec.Parameters {
		if p.From != "" {
			n++
		}
	}
	for _, t := range rb.Spec.Triggers {
		if t.Match != "" {
			n++
		}
	}
	for _, st := range rb.Spec.Steps {
		n += len(st.Outputs)
		if st.When != "" {
			n++
		}
		if st.Until != "" {
			n++
		}
	}
	return n
}
