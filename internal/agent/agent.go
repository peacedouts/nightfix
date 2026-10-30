// Package agent is the customer-deployed runner. It connects outbound to the
// control plane over mutual TLS, receives one signed step attempt at a time,
// re-verifies everything locally, executes under the customer's own IAM role
// and streams redacted output back (agent-protocol.md).
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
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
	// PinnedKeys maps a pinned signer's key id to its base64 Ed25519 public
	// key. A pinned key is always used instead of whatever the control plane
	// sends for that id; without it, a compromised control plane could pair a
	// pinned id with a key of its own.
	PinnedKeys    map[string]string
	AllowlistFile string
	// AllowlistYAML is the allowlist itself, for platforms where a file is
	// awkward (ECS); it's used when AllowlistFile is empty.
	AllowlistYAML string
	AllowlistMode string // off | warn | enforce
	// StepTypes limits what this agent runs (e.g. aws and wait, no shell).
	// Empty means every type it supports. Set locally, so the control plane
	// can't widen it.
	StepTypes []string
	Freeze    bool // local kill switch: connect for visibility, run nothing
	Slots     int

	AWS AWSCaller
	Log *slog.Logger
}

// Agent runs dispatched steps.
type Agent struct {
	cfg       Config
	c         *client
	id        *identity
	allowlist *allowlist

	// steps tracks running step goroutines, so shutdown can let them finish
	// (scripts get their SIGTERM grace) and report. results is the context
	// results are sent with: it outlives Run's, and shutdown cancels it once
	// its grace period is over.
	steps         sync.WaitGroup
	resultsOnce   sync.Once
	results       context.Context
	resultsCancel context.CancelFunc

	mu       sync.Mutex
	inflight map[string]context.CancelFunc
	stopping bool                 // shutting down: in-flight steps were cancelled by the agent itself
	seen     map[string]time.Time // attempt ids already accepted (replay guard)
	frozen   bool

	renewEvery time.Duration // renewCheckInterval when created
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
	switch cfg.AllowlistMode {
	case "off", "warn", "enforce":
	default:
		// A typo must not quietly behave like "warn".
		return nil, fmt.Errorf("allowlist mode %q: must be off, warn or enforce", cfg.AllowlistMode)
	}
	for id, pub := range cfg.PinnedKeys {
		if !contains(cfg.RequiredSigners, id) {
			return nil, fmt.Errorf("pinned key %s is not a required signer", id)
		}
		if b, err := base64.StdEncoding.DecodeString(pub); err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pinned key %s: not a base64 Ed25519 public key", id)
		}
	}
	c, err := newClient(cfg.Endpoint, cfg.CAPEM)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, c: c, inflight: map[string]context.CancelFunc{}, seen: map[string]time.Time{}, renewEvery: renewCheckInterval}
	for _, t := range cfg.StepTypes {
		if !contains(supportedStepTypes, t) {
			return nil, fmt.Errorf("step type %q isn't one this agent can run (%s)", t, strings.Join(supportedStepTypes, ", "))
		}
	}
	switch cfg.AllowlistMode {
	case "off", "":
	case "warn", "enforce":
		// A file, when given, wins over the inline list.
		var al *allowlist
		if cfg.AllowlistFile != "" {
			al, err = loadAllowlist(cfg.AllowlistFile)
		} else {
			al, err = parseAllowlist([]byte(cfg.AllowlistYAML))
		}
		if err != nil {
			return nil, err
		}
		a.allowlist = al
	default:
		return nil, fmt.Errorf("allowlist mode %q: use off, warn or enforce", cfg.AllowlistMode)
	}
	return a, nil
}

// ID returns the agent id once enrolled. Safe to call while Run is running
// (re-enrollment replaces the identity).
func (a *Agent) ID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.id == nil {
		return ""
	}
	return a.id.AgentID
}

// Run enrolls if needed, then serves until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	id, err := loadIdentity(a.cfg.StateDir)
	if err == nil && id.expired(time.Now()) {
		// Down for longer than the certificate lives (24h): it can't be
		// renewed, so enroll again rather than retrying it forever.
		a.cfg.Log.Warn("stored identity has expired; enrolling again", "agent", id.AgentID)
		err = errors.New("identity expired")
	}
	if err != nil {
		if id, err = a.enroll(ctx); err != nil {
			return err
		}
	}
	if err := a.useIdentity(id); err != nil {
		return err
	}

	// Steps die with the agent (agent-protocol.md §8): on shutdown, cancel
	// everything in flight so scripts are stopped rather than orphaned, give
	// them their SIGTERM grace, and report them.
	defer a.shutdown()

	// backoff grows across failed hellos, polls and enrollments, and resets
	// only once a poll succeeds: a hello that works followed by a poll that
	// is refused (a revoked agent) must not retry every second forever.
	backoff := time.Second
	started, needHello, reenrolled := false, true, false
	for ctx.Err() == nil {
		// The gateway checks the certificate when a connection is opened, so a
		// kept-alive connection goes on working after it expires. Treat expiry
		// as a refusal here rather than waiting for a new connection.
		if a.c.certExpired(time.Now()) {
			needHello = true
		}
		// Hello again after any failed poll: it's how in-flight attempts are
		// reconciled after an outage and how new trust config and labels
		// reach a running agent.
		if needHello {
			if err := a.helloUnlessExpired(ctx); err != nil {
				if ctx.Err() != nil {
					continue
				}
				if identityRejected(err) {
					// Revoked, replaced or expired: this identity will never
					// work again. IAM agents can prove who they are again;
					// a token is single-use, so a human has to re-enroll.
					if a.cfg.EnrollMethod == "token" {
						return fmt.Errorf("the gateway no longer accepts this agent's identity (%v); enroll it again with a new token", err)
					}
					if reenrolled {
						// The identity just enrolled was refused too: back off
						// rather than enroll (and use up an agent) in a loop.
						a.cfg.Log.Warn("the new identity was rejected as well; waiting before enrolling again", "err", err, "in", backoff)
						sleep(ctx, jitter(backoff))
						backoff = min(backoff*2, time.Minute)
						if ctx.Err() != nil {
							continue
						}
					}
					a.cfg.Log.Warn("the gateway rejected this agent's identity; enrolling again", "err", err)
					if id, eerr := a.enroll(ctx); eerr != nil {
						a.cfg.Log.Warn("re-enrollment failed; retrying", "err", eerr, "in", backoff)
					} else if eerr := a.useIdentity(id); eerr != nil {
						return eerr
					} else {
						reenrolled = true
						continue
					}
				} else {
					a.cfg.Log.Warn("hello failed; retrying", "err", err, "in", backoff)
				}
				sleep(ctx, jitter(backoff))
				backoff = min(backoff*2, time.Minute)
				continue
			}
			needHello, reenrolled = false, false
			if !started {
				started = true
				go a.heartbeatLoop(ctx)
				go a.renewLoop(ctx)
			}
		}
		if err := a.pollOnce(ctx); err != nil && ctx.Err() == nil {
			a.cfg.Log.Warn("poll failed; reconnecting", "err", err, "in", backoff)
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, time.Minute)
			needHello = true
			continue
		}
		backoff = time.Second
	}
	return ctx.Err()
}

// enroll proves the agent's identity and saves it. The state directory is
// checked first: enrolling and then failing to save would use up a
// single-use token, or an agent slot, on every restart.
func (a *Agent) enroll(ctx context.Context) (*identity, error) {
	if err := checkStateDir(a.cfg.StateDir); err != nil {
		return nil, err
	}
	var id *identity
	var err error
	// Enroll as nobody: the identity being replaced may be one the gateway
	// refuses during the handshake.
	a.c.clearCert()
	switch a.cfg.EnrollMethod {
	case "token":
		if a.cfg.EnrollToken == "" {
			return nil, errors.New("token enrollment needs an enrollment token")
		}
		id, err = a.c.enroll(ctx, a.cfg.EnrollToken, Version)
	case "", "iam":
		if a.cfg.OrgID == "" || a.cfg.IAM == nil {
			return nil, errors.New("iam enrollment needs the org id (org_…) and AWS credentials")
		}
		id, err = a.c.enrollIAM(ctx, a.cfg.OrgID, a.cfg.IAM, Version)
	default:
		return nil, fmt.Errorf("unknown enrollment method %q", a.cfg.EnrollMethod)
	}
	if err != nil {
		return nil, err
	}
	if err := saveIdentity(a.cfg.StateDir, id); err != nil {
		return nil, err
	}
	a.cfg.Log.Info("enrolled", "agent", id.AgentID, "labels", id.Labels)
	return id, nil
}

// useIdentity switches to id. The client certificate and a.id change under
// one lock so a renewal finishing meanwhile can't pair one with the other.
func (a *Agent) useIdentity(id *identity) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.c.setCert(id.CertPEM, id.KeyPEM); err != nil {
		return err
	}
	a.id = id
	return nil
}

// persist saves the current identity. It holds the agent lock so hello and
// certificate renewal can't interleave their writes.
func (a *Agent) persist() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return saveIdentity(a.cfg.StateDir, a.id)
}

// errCertExpired is the agent noticing its own certificate has expired.
var errCertExpired = errors.New("the agent's certificate has expired")

// helloUnlessExpired says hello, unless the certificate has already expired.
func (a *Agent) helloUnlessExpired(ctx context.Context) error {
	if a.c.certExpired(time.Now()) {
		return errCertExpired
	}
	return a.hello(ctx)
}

// identityRejected reports whether the gateway refused the agent's
// certificate itself (revoked, replaced, expired or unknown), as opposed to
// an outage.
func identityRejected(err error) bool {
	if errors.Is(err, errCertExpired) {
		return true
	}
	var se *statusError
	if errors.As(err, &se) && se.Code == http.StatusUnauthorized {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"tls: expired certificate", "tls: bad certificate", "tls: certificate required", "tls: revoked certificate", "tls: unknown certificate"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func (a *Agent) cancelAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, cancel := range a.inflight {
		cancel()
	}
}

// supportedStepTypes are the step types this build can run.
var supportedStepTypes = []string{"shell", "aws", "wait"}

// capabilities are the step types this agent runs: what it supports, less
// anything the local configuration leaves out. They're both advertised and
// enforced, so a control plane that ignores the advertisement is refused.
func (a *Agent) capabilities() []string {
	if len(a.cfg.StepTypes) == 0 {
		return supportedStepTypes
	}
	var out []string
	for _, t := range supportedStepTypes {
		if contains(a.cfg.StepTypes, t) {
			out = append(out, t)
		}
	}
	return out
}

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
	a.mu.Lock()
	a.id.Labels = w.Labels
	a.id.Trust = w.TrustConfig
	a.mu.Unlock()
	return a.persist()
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

// renewCheckInterval is how often renewLoop looks at the certificate; a
// failed renewal is retried at the same pace until the certificate expires
// (then Run re-enrolls or stops).
var renewCheckInterval = time.Minute

// renewDue reports whether 2/3 of the certificate's lifetime has passed.
func renewDue(issued, expires, now time.Time) bool {
	return !expires.IsZero() && !now.Before(issued.Add(expires.Sub(issued)*2/3))
}

// renewLoop renews the certificate once 2/3 of its lifetime has passed.
func (a *Agent) renewLoop(ctx context.Context) {
	every := a.renewEvery
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		issued, expires := a.c.certExpiry()
		if !renewDue(issued, expires, time.Now()) {
			continue
		}
		a.mu.Lock()
		renewing := a.id
		a.mu.Unlock()
		cert, key, err := a.c.renew(ctx)
		if err != nil {
			a.cfg.Log.Warn("certificate renewal failed", "err", err)
			continue
		}
		a.mu.Lock()
		if a.id != renewing {
			// Re-enrolled while renewing: this certificate is the old identity's.
			a.mu.Unlock()
			continue
		}
		if err := a.c.setCert(cert, key); err != nil {
			a.mu.Unlock()
			a.cfg.Log.Warn("the renewed certificate is unusable; retrying", "err", err)
			continue
		}
		a.id.CertPEM, a.id.KeyPEM = cert, key
		a.mu.Unlock()
		if err := a.persist(); err != nil {
			// The new certificate works in memory; on restart the old one
			// is still accepted until it expires, then the agent re-enrolls.
			a.cfg.Log.Error("could not save the renewed certificate", "err", err)
		}
		a.cfg.Log.Info("certificate renewed")
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
	trust, labels := a.trust()
	env, err := signing.OpenEnvelope(d.Envelope, trust, a.id.OrgID, a.id.AgentID, time.Now())
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
	rb, err := signing.VerifyBundle(d.Bundle, trust, a.cfg.RequiredSigners)
	if err != nil {
		return nil, err
	}
	if a.allowlist != nil && !a.allowlist.allows(rb.Metadata.Name, d.Bundle.Digest, d.Bundle.Version) {
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
		if labels[k] != want {
			return nil, fmt.Errorf("runbook targets %s=%s; this agent has %s=%q", k, want, k, labels[k])
		}
	}
	return &verified{env: env, rb: rb, step: step}, nil
}

// trust returns the trust config to verify with — the control plane's, with
// locally pinned keys always replacing whatever it sent for those ids — and
// the agent's current labels.
func (a *Agent) trust() (signing.TrustConfig, map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tc := signing.TrustConfig{Keys: map[string]string{}, RequiredSigners: a.id.Trust.RequiredSigners,
		EnvelopeSigners: a.id.Trust.EnvelopeSigners}
	for id, pub := range a.id.Trust.Keys {
		tc.Keys[id] = pub
	}
	for id, pub := range a.cfg.PinnedKeys {
		tc.Keys[id] = pub
	}
	return tc, a.id.Labels
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
	if err := a.ack(ctx, v.env.AttemptID); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Code/100 == 4 {
			// Refused (expired, reassigned): the control plane doesn't
			// consider this agent to be running it.
			a.cfg.Log.Warn("ack refused; dropping attempt", "attempt", v.env.AttemptID, "err", err)
			return
		}
		// The ack may or may not have been recorded. Don't run the step, and
		// say so, so the attempt fails as "not started" instead of being
		// declared lost (and paging as "may or may not have completed").
		a.cfg.Log.Warn("ack failed; reporting the step as not started", "attempt", v.env.AttemptID, "err", err)
		// Listed as in flight until the result is delivered, so a hello in
		// the meantime doesn't make the control plane declare it lost. Marked
		// seen, so if the lease expires and the same attempt is dispatched
		// again before the result gets through, the agent refuses it rather
		// than running it and then delivering the stale "not started" result
		// onto the running attempt. (That's also why the delete below can't
		// remove a real step's entry: none can start under this ID.)
		a.mu.Lock()
		a.inflight[v.env.AttemptID] = func() {}
		a.seen[v.env.AttemptID] = time.Now()
		a.mu.Unlock()
		a.steps.Add(1)
		go func() {
			defer a.steps.Done()
			a.sendResult(a.resultsCtx(), v.env.AttemptID, agentapi.Result{Status: "failed",
				Error: "the agent couldn't confirm the dispatch with the control plane, so the step was not started"})
			a.mu.Lock()
			delete(a.inflight, v.env.AttemptID)
			a.mu.Unlock()
		}()
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

	a.steps.Add(1)
	go func() {
		defer a.steps.Done()
		defer cancel()
		res := a.execute(stepCtx, v)
		a.sendResult(a.resultsCtx(), v.env.AttemptID, res)
		a.mu.Lock()
		delete(a.inflight, v.env.AttemptID)
		a.mu.Unlock()
		a.cfg.Log.Info("step finished", "step", v.step.ID, "status", res.Status, "error", res.Error)
	}()
}

// ack confirms a dispatch, retrying a lost response within the dispatch
// lease (30s): a repeat ack of an attempt already running is a no-op.
func (a *Agent) ack(ctx context.Context, attemptID string) error {
	backoff := time.Second
	for i := 0; ; i++ {
		err := a.c.post(ctx, "/agent/v1/attempts/"+attemptID+"/ack", agentapi.Ack{Accepted: true}, nil)
		var se *statusError
		if err == nil || (errors.As(err, &se) && se.Code/100 == 4 && se.Code != 408 && se.Code != 429) || i >= 3 || ctx.Err() != nil {
			return err
		}
		sleep(ctx, jitter(backoff))
		backoff *= 2
	}
}

// shutdownGrace bounds how long shutdown waits for running steps to stop and
// report. It must fit in the task's stop timeout (the agent module sets 60s):
// scripts get 10s after SIGTERM, then results are sent.
const shutdownGrace = 40 * time.Second

func (a *Agent) shutdown() {
	a.mu.Lock()
	a.stopping = true
	a.mu.Unlock()
	a.cancelAll()
	done := make(chan struct{})
	go func() { a.steps.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		a.cfg.Log.Warn("shutting down with steps still running", "attempts", a.inFlight())
	}
	a.resultsCtx()
	a.resultsCancel()
}

func (a *Agent) isStopping() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopping
}

// resultsCtx is the context results are sent with (see Agent.results).
func (a *Agent) resultsCtx() context.Context {
	a.resultsOnce.Do(func() { a.results, a.resultsCancel = context.WithCancel(context.Background()) })
	return a.results
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
		// 408 and 429 are transient; any other 4xx means the control plane
		// won't take this result, so retrying can't help.
		if errors.As(err, &se) && se.Code/100 == 4 && se.Code != 408 && se.Code != 429 {
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
	return parseAllowlist(b)
}

func parseAllowlist(b []byte) (*allowlist, error) {
	if strings.TrimSpace(string(b)) == "" {
		return nil, errors.New("allowlist: the allowlist is empty (set NIGHTFIX_ALLOWLIST_FILE or NIGHTFIX_ALLOWLIST); with mode enforce an empty list would refuse everything, so write the runbooks out")
	}
	var al allowlist
	if err := yaml.UnmarshalWithOptions(b, &al, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	for i, r := range al.Runbooks {
		// Signatures cover a bundle's digest, not its version number, so a
		// version pin would trust a field a compromised control plane can
		// relabel. Pin the digest, or allow every version with "*".
		if r.Digest == "" && r.Version != "*" {
			return nil, fmt.Errorf("allowlist entry %d (%s): pin a digest (sha256:…), or set version: \"*\" to allow every version; version numbers aren't signed", i+1, r.Name)
		}
		if r.Digest != "" && r.Version != "" && r.Version != "*" {
			return nil, fmt.Errorf("allowlist entry %d (%s): version numbers aren't signed; pin by digest only", i+1, r.Name)
		}
	}
	return &al, nil
}

func (al *allowlist) allows(name, digest string, version int) bool {
	for _, r := range al.Runbooks {
		if r.Name != name {
			continue
		}
		switch {
		case r.Digest != "":
			if r.Digest == digest {
				return true
			}
		case r.Version == "*":
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
