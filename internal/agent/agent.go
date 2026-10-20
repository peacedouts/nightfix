// Package agent is the customer-deployed runner. It connects outbound to the
// control plane over mutual TLS, receives one signed step attempt at a time,
// re-verifies everything locally, executes under the customer's own IAM role
// and streams redacted output back (agent-protocol.md).
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// Version is reported to the control plane.
const Version = "0.1.0-skeleton"

// AWSCaller makes an AWS API call (awscall.Client in production).
type AWSCaller interface {
	Call(ctx context.Context, service, action string, input map[string]any) (map[string]any, error)
}

// Config configures an agent.
type Config struct {
	Endpoint string // https://agent.nightfix.dev:443
	CAPEM    []byte // CA to trust for the gateway (and enrollment)

	// Enrollment: "iam" (default) proves the agent's AWS role; "token" uses
	// EnrollToken. OrgID (org_…) is required for iam.
	EnrollMethod string
	OrgID        string
	IAM          IAMSigner
	EnrollToken  string
	StateDir     string // empty: no persistent disk, re-enroll on restart

	// RequiredSigners, when set, is the locally pinned list of signers every
	// runbook bundle must carry. It always wins over the control plane's list.
	RequiredSigners []string
	AllowlistFile   string
	AllowlistMode   string // off | warn | enforce
	Freeze          bool   // local kill switch: connect for visibility, run nothing
	Slots           int

	AWS AWSCaller
	Log *slog.Logger
}

// Agent runs dispatched steps.
type Agent struct {
	cfg       Config
	c         *client
	id        *identity
	allowlist *allowlist

	mu       sync.Mutex
	inflight map[string]context.CancelFunc
	seen     map[string]time.Time // attempt ids already accepted (replay guard)
	frozen   bool
}

// New prepares an agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Slots <= 0 {
		cfg.Slots = 4
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.AllowlistMode == "" {
		cfg.AllowlistMode = "off"
	}
	c, err := newClient(cfg.Endpoint, cfg.CAPEM)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, c: c, inflight: map[string]context.CancelFunc{}, seen: map[string]time.Time{}}
	if cfg.AllowlistMode != "off" {
		al, err := loadAllowlist(cfg.AllowlistFile)
		if err != nil {
			return nil, err
		}
		a.allowlist = al
	}
	return a, nil
}

// ID returns the agent id once enrolled.
func (a *Agent) ID() string {
	if a.id == nil {
		return ""
	}
	return a.id.AgentID
}

// Run enrolls if needed, then serves until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	id, err := loadIdentity(a.cfg.StateDir)
	if err != nil {
		switch a.cfg.EnrollMethod {
		case "token":
			if a.cfg.EnrollToken == "" {
				return errors.New("token enrollment needs an enrollment token")
			}
			id, err = a.c.enroll(ctx, a.cfg.EnrollToken, Version)
		case "", "iam":
			if a.cfg.OrgID == "" || a.cfg.IAM == nil {
				return errors.New("iam enrollment needs the org id (org_…) and AWS credentials")
			}
			id, err = a.c.enrollIAM(ctx, a.cfg.OrgID, a.cfg.IAM, Version)
		default:
			return fmt.Errorf("unknown enrollment method %q", a.cfg.EnrollMethod)
		}
		if err != nil {
			return err
		}
		if err := saveIdentity(a.cfg.StateDir, id); err != nil {
			return err
		}
		a.cfg.Log.Info("enrolled", "agent", id.AgentID, "labels", id.Labels)
	}
	a.id = id
	if err := a.c.setCert(id.CertPEM, id.KeyPEM); err != nil {
		return err
	}

	backoff := time.Second
	for ctx.Err() == nil {
		if err := a.hello(ctx); err != nil {
			a.cfg.Log.Warn("hello failed; retrying", "err", err, "in", backoff)
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		break
	}
	go a.heartbeatLoop(ctx)
	go a.renewLoop(ctx)

	for ctx.Err() == nil {
		if err := a.pollOnce(ctx); err != nil && ctx.Err() == nil {
			a.cfg.Log.Warn("poll failed; retrying", "err", err, "in", backoff)
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
	}
	return ctx.Err()
}

func (a *Agent) capabilities() []string { return []string{"shell", "aws", "wait"} }

func (a *Agent) inFlight() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.inflight))
	for id := range a.inflight {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (a *Agent) hello(ctx context.Context) error {
	var w agentapi.Welcome
	err := a.c.post(ctx, "/agent/v1/hello", agentapi.Hello{
		ProtocolVersion: agentapi.ProtocolVersion, AgentVersion: Version, Capabilities: a.capabilities(),
		Slots: a.cfg.Slots, AllowlistMode: a.cfg.AllowlistMode, FrozenLocal: a.cfg.Freeze, InFlight: a.inFlight(),
	}, &w)
	if err != nil {
		return err
	}
	a.id.Labels = w.Labels
	a.id.Trust = w.TrustConfig
	return saveIdentity(a.cfg.StateDir, a.id)
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.c.post(ctx, "/agent/v1/heartbeat", agentapi.Heartbeat{InFlight: a.inFlight()}, nil); err != nil && ctx.Err() == nil {
				a.cfg.Log.Warn("heartbeat failed", "err", err)
			}
		}
	}
}

// renewLoop renews the certificate once 2/3 of its lifetime has passed.
func (a *Agent) renewLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		issued, expires := a.c.certExpiry()
		if expires.IsZero() || time.Now().Before(issued.Add(expires.Sub(issued)*2/3)) {
			continue
		}
		cert, key, err := a.c.renew(ctx)
		if err != nil {
			a.cfg.Log.Warn("certificate renewal failed", "err", err)
			continue
		}
		if err := a.c.setCert(cert, key); err == nil {
			a.id.CertPEM, a.id.KeyPEM = cert, key
			saveIdentity(a.cfg.StateDir, a.id)
			a.cfg.Log.Info("certificate renewed")
		}
	}
}

func (a *Agent) pollOnce(ctx context.Context) error {
	free := a.cfg.Slots - len(a.inFlight())
	if a.cfg.Freeze {
		free = 0
	}
	var resp agentapi.PollResponse
	if err := a.c.post(ctx, "/agent/v1/poll", agentapi.PollRequest{FreeSlots: free, InFlight: a.inFlight()}, &resp); err != nil {
		return err
	}
	a.mu.Lock()
	for _, id := range resp.Cancel {
		if cancel, ok := a.inflight[id]; ok {
			a.cfg.Log.Info("cancelling attempt", "attempt", id)
			cancel()
		}
	}
	if resp.Frozen && !a.frozen {
		a.cfg.Log.Warn("org is frozen: cancelling all work and refusing new dispatches")
		for _, cancel := range a.inflight {
			cancel()
		}
	}
	a.frozen = resp.Frozen
	a.mu.Unlock()

	if resp.Frozen {
		sleep(ctx, 2*time.Second)
		return nil
	}
	if free <= 0 {
		sleep(ctx, time.Second)
	}
	if resp.Dispatch != nil {
		a.handleDispatch(ctx, *resp.Dispatch)
	}
	return nil
}

// verified is a dispatch that passed every local check.
type verified struct {
	env  signing.Envelope
	rb   *runbook.Runbook
	step runbook.Step
}

// verify re-validates a dispatch before anything runs (agent-protocol.md §6.3).
func (a *Agent) verify(d agentapi.Dispatch) (*verified, error) {
	if a.cfg.Freeze {
		return nil, errors.New("agent is frozen locally")
	}
	env, err := signing.OpenEnvelope(d.Envelope, a.id.Trust, a.id.AgentID, time.Now())
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	_, dup := a.seen[env.AttemptID]
	a.mu.Unlock()
	if dup {
		return nil, errors.New("attempt already accepted once (replay)")
	}
	if env.RunbookDigest != d.Bundle.Digest {
		return nil, errors.New("envelope digest does not match the bundle")
	}
	rb, err := signing.VerifyBundle(d.Bundle, a.id.Trust, a.cfg.RequiredSigners)
	if err != nil {
		return nil, err
	}
	if a.allowlist != nil && !a.allowlist.allows(rb.Metadata.Name, d.Bundle.Digest) {
		msg := fmt.Sprintf("runbook %s (%s) is not on the local allowlist", rb.Metadata.Name, d.Bundle.Digest)
		if a.cfg.AllowlistMode == "enforce" {
			return nil, errors.New(msg)
		}
		a.cfg.Log.Warn(msg + " (allowlist mode is warn)")
	}
	if env.StepIndex < 0 || env.StepIndex >= len(rb.Spec.Steps) || rb.Spec.Steps[env.StepIndex].ID != env.StepID {
		return nil, errors.New("envelope step does not exist in the runbook")
	}
	step := rb.Spec.Steps[env.StepIndex]
	if !contains(a.capabilities(), step.Type) {
		return nil, fmt.Errorf("step type %q is not supported by this agent", step.Type)
	}
	if err := runbook.ValidateParams(rb, env.Params); err != nil {
		return nil, fmt.Errorf("parameters failed local validation: %w", err)
	}
	for k, want := range rb.Spec.Target.AgentSelector {
		if a.id.Labels[k] != want {
			return nil, fmt.Errorf("runbook targets %s=%s; this agent has %s=%q", k, want, k, a.id.Labels[k])
		}
	}
	return &verified{env: env, rb: rb, step: step}, nil
}

func (a *Agent) handleDispatch(ctx context.Context, d agentapi.Dispatch) {
	attemptID := attemptIDOf(d)
	v, err := a.verify(d)
	if err != nil {
		a.cfg.Log.Warn("rejecting dispatch", "attempt", attemptID, "reason", err)
		if attemptID != "" {
			a.c.post(ctx, "/agent/v1/attempts/"+attemptID+"/ack", agentapi.Ack{Accepted: false, Reason: err.Error()}, nil)
		}
		return
	}
	if err := a.c.post(ctx, "/agent/v1/attempts/"+v.env.AttemptID+"/ack", agentapi.Ack{Accepted: true}, nil); err != nil {
		a.cfg.Log.Warn("ack failed; dropping attempt", "attempt", v.env.AttemptID, "err", err)
		return
	}
	stepCtx, cancel := context.WithTimeout(context.Background(), v.step.StepTimeout())
	a.mu.Lock()
	a.inflight[v.env.AttemptID] = cancel
	a.seen[v.env.AttemptID] = time.Now()
	for id, t := range a.seen {
		if time.Since(t) > time.Hour {
			delete(a.seen, id)
		}
	}
	a.mu.Unlock()
	a.cfg.Log.Info("running step", "runbook", v.rb.Metadata.Name, "step", v.step.ID, "attempt", v.env.AttemptID)

	go func() {
		defer cancel()
		res := a.execute(stepCtx, v)
		a.sendResult(ctx, v.env.AttemptID, res)
		a.mu.Lock()
		delete(a.inflight, v.env.AttemptID)
		a.mu.Unlock()
		a.cfg.Log.Info("step finished", "step", v.step.ID, "status", res.Status, "error", res.Error)
	}()
}

// sendResult retries until the control plane has the result. Holding it
// across reconnects is what lets a disconnected agent finish a step and
// report later.
func (a *Agent) sendResult(ctx context.Context, attemptID string, res agentapi.Result) {
	backoff := 500 * time.Millisecond
	for i := 0; ; i++ {
		err := a.c.post(ctx, "/agent/v1/attempts/"+attemptID+"/result", res, nil)
		if err == nil {
			return
		}
		var se *statusError
		if errors.As(err, &se) && se.Code/100 == 4 {
			a.cfg.Log.Warn("result refused", "attempt", attemptID, "err", err)
			return
		}
		if ctx.Err() != nil || i > 100 {
			a.cfg.Log.Error("giving up on reporting result", "attempt", attemptID, "err", err)
			return
		}
		sleep(ctx, jitter(backoff))
		backoff = min(backoff*2, 30*time.Second)
	}
}

func attemptIDOf(d agentapi.Dispatch) string {
	// Best effort, for rejecting a dispatch we couldn't verify.
	var e struct {
		AttemptID string `json:"attempt_id"`
	}
	if jsonUnmarshal([]byte(d.Envelope.Payload), &e) == nil {
		return e.AttemptID
	}
	return ""
}

// ---------------------------------------------------------------------------
// Local allowlist
// ---------------------------------------------------------------------------

type allowlist struct {
	Runbooks []struct {
		Name    string `yaml:"name"`
		Digest  string `yaml:"digest"`
		Version string `yaml:"version"`
	} `yaml:"runbooks"`
}

func loadAllowlist(path string) (*allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	var al allowlist
	if err := yaml.UnmarshalWithOptions(b, &al, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	return &al, nil
}

func (al *allowlist) allows(name, digest string) bool {
	for _, r := range al.Runbooks {
		if r.Name == name && (r.Digest == digest || r.Version == "*") {
			return true
		}
	}
	return false
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(time.Now().UnixNano()%int64(d/2+1))
}
