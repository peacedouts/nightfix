// Package runbook parses, validates and canonicalizes runbooks
// (docs: runbook-schema.md, v1alpha1).
package runbook

import (
	"strings"
	"time"
)

const (
	APIVersion = "lightning.ir/v1alpha1"
	Kind       = "Runbook"
)

// Runbook is the authored document.
type Runbook struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name        string            `json:"name" yaml:"name"`
	Title       string            `json:"title" yaml:"title"`
	Description string            `json:"description,omitempty" yaml:"description"`
	Team        string            `json:"team,omitempty" yaml:"team"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels"`
}

type Spec struct {
	Parameters map[string]Param     `json:"parameters,omitempty" yaml:"parameters"`
	Secrets    map[string]SecretRef `json:"secrets,omitempty" yaml:"secrets"`
	Target     Target               `json:"target" yaml:"target"`
	Triggers   []Trigger            `json:"triggers,omitempty" yaml:"triggers"`
	Policy     Policy               `json:"policy,omitempty" yaml:"policy"`
	Steps      []Step               `json:"steps" yaml:"steps"`
	OnFailure  *OnFailure           `json:"onFailure,omitempty" yaml:"onFailure"`
}

type Param struct {
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description,omitempty" yaml:"description"`
	Required    bool   `json:"required,omitempty" yaml:"required"`
	Default     any    `json:"default,omitempty" yaml:"default"`
	From        string `json:"from,omitempty" yaml:"from"`
	Pattern     string `json:"pattern,omitempty" yaml:"pattern"`
	Values      []any  `json:"values,omitempty" yaml:"values"`
	Min         any    `json:"min,omitempty" yaml:"min"`
	Max         any    `json:"max,omitempty" yaml:"max"`
}

type SecretRef struct {
	Ref string `json:"ref" yaml:"ref"`
	Key string `json:"key,omitempty" yaml:"key"`
}

type Target struct {
	AgentSelector map[string]string `json:"agentSelector,omitempty" yaml:"agentSelector"`
}

type Trigger struct {
	Type           string   `json:"type" yaml:"type"`
	Services       []string `json:"services,omitempty" yaml:"services"`
	Match          string   `json:"match,omitempty" yaml:"match"`
	Mode           string   `json:"mode,omitempty" yaml:"mode"`
	BeforePaging   bool     `json:"beforePaging,omitempty" yaml:"beforePaging"`
	Cooldown       string   `json:"cooldown,omitempty" yaml:"cooldown"`
	MaxRunsPerHour int      `json:"maxRunsPerHour,omitempty" yaml:"maxRunsPerHour"`
}

type Policy struct {
	AllowedRoles []string `json:"allowedRoles,omitempty" yaml:"allowedRoles"`
	Timeout      string   `json:"timeout,omitempty" yaml:"timeout"`
	Concurrency  int      `json:"concurrency,omitempty" yaml:"concurrency"`
}

type OnFailure struct {
	Action  string `json:"action" yaml:"action"`
	Message string `json:"message,omitempty" yaml:"message"`
}

// Step holds every step type's fields; Type selects which apply.
type Step struct {
	ID         string            `json:"id" yaml:"id"`
	Name       string            `json:"name,omitempty" yaml:"name"`
	Type       string            `json:"type" yaml:"type"`
	When       string            `json:"when,omitempty" yaml:"when"`
	Timeout    string            `json:"timeout,omitempty" yaml:"timeout"`
	Retries    int               `json:"retries,omitempty" yaml:"retries"`
	OnFailure  string            `json:"onFailure,omitempty" yaml:"onFailure"`
	Idempotent *bool             `json:"idempotent,omitempty" yaml:"idempotent"`
	Outputs    map[string]string `json:"outputs,omitempty" yaml:"outputs"`

	// note / manual
	Markdown  string   `json:"markdown,omitempty" yaml:"markdown"`
	Checklist []string `json:"checklist,omitempty" yaml:"checklist"`

	// approval
	Count            int      `json:"count,omitempty" yaml:"count"`
	FromRoles        []string `json:"fromRoles,omitempty" yaml:"fromRoles"`
	ExcludeRequester bool     `json:"excludeRequester,omitempty" yaml:"excludeRequester"`
	ExpiresAfter     string   `json:"expiresAfter,omitempty" yaml:"expiresAfter"`

	// shell / python
	Run   string            `json:"run,omitempty" yaml:"run"`
	Env   map[string]string `json:"env,omitempty" yaml:"env"`
	Files map[string]string `json:"files,omitempty" yaml:"files"`
	RunOn string            `json:"runOn,omitempty" yaml:"runOn"`

	// aws
	Service    string         `json:"service,omitempty" yaml:"service"`
	Action     string         `json:"action,omitempty" yaml:"action"`
	Input      map[string]any `json:"input,omitempty" yaml:"input"`
	AssumeRole string         `json:"assumeRole,omitempty" yaml:"assumeRole"`

	// wait
	Check    *Check `json:"check,omitempty" yaml:"check"`
	Until    string `json:"until,omitempty" yaml:"until"`
	Interval string `json:"interval,omitempty" yaml:"interval"`

	// http
	Method       string            `json:"method,omitempty" yaml:"method"`
	URL          string            `json:"url,omitempty" yaml:"url"`
	Headers      map[string]string `json:"headers,omitempty" yaml:"headers"`
	Body         any               `json:"body,omitempty" yaml:"body"`
	ExpectStatus []int             `json:"expectStatus,omitempty" yaml:"expectStatus"`

	// container
	Image   string   `json:"image,omitempty" yaml:"image"`
	Command []string `json:"command,omitempty" yaml:"command"`
}

type Check struct {
	AWS  *AWSCall  `json:"aws,omitempty" yaml:"aws"`
	HTTP *HTTPCall `json:"http,omitempty" yaml:"http"`
}

type AWSCall struct {
	Service string         `json:"service" yaml:"service"`
	Action  string         `json:"action" yaml:"action"`
	Input   map[string]any `json:"input,omitempty" yaml:"input"`
}

type HTTPCall struct {
	Method  string            `json:"method,omitempty" yaml:"method"`
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers"`
}

// Step types that run on the control plane rather than the agent.
var controlPlaneSteps = map[string]bool{"note": true, "manual": true, "approval": true}

// RunsOnControlPlane reports whether the step executes in the control plane.
func (s Step) RunsOnControlPlane() bool { return controlPlaneSteps[s.Type] }

// IsIdempotent applies the explicit flag, else the defaults from the agent
// protocol: read-only AWS actions, GET/HEAD requests and waits are safe to
// retry; everything else is not.
func (s Step) IsIdempotent() bool {
	if s.Idempotent != nil {
		return *s.Idempotent
	}
	switch s.Type {
	case "wait", "note":
		return true
	case "aws":
		for _, p := range []string{"Describe", "List", "Get"} {
			if strings.HasPrefix(s.Action, p) {
				return true
			}
		}
		return false
	case "http":
		m := strings.ToUpper(s.Method)
		return m == "" || m == "GET" || m == "HEAD"
	default:
		return false
	}
}

// StepTimeout returns the step timeout (default 5m).
func (s Step) StepTimeout() time.Duration {
	return durationOr(s.Timeout, 5*time.Minute)
}

// RunTimeout returns the whole-run timeout (default 30m, max 4h).
func (r *Runbook) RunTimeout() time.Duration {
	return durationOr(r.Spec.Policy.Timeout, 30*time.Minute)
}

// WaitInterval returns a wait step's polling interval (default 15s).
func (s Step) WaitInterval() time.Duration {
	return durationOr(s.Interval, 15*time.Second)
}

func durationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// StepIndex returns the index of the step with the given id, or -1.
func (r *Runbook) StepIndex(id string) int {
	for i, s := range r.Spec.Steps {
		if s.ID == id {
			return i
		}
	}
	return -1
}
