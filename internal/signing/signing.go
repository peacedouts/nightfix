// Package signing implements runbook bundle signatures, signed dispatch
// envelopes and the agent's trust configuration (agent-protocol.md §3.3, §6).
//
// Bundles answer "what may run": the canonical runbook, its digest, and a
// signature from every required signer. Envelopes answer "when and where": one
// step attempt, bound to one agent, with resolved params and a short expiry,
// signed by the control plane.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/peacedouts/nightfix/internal/canonical"
	"github.com/peacedouts/nightfix/internal/runbook"
)

// Key is a named Ed25519 key pair. Private is nil for verify-only keys.
type Key struct {
	ID      string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKey makes a new key whose ID is derived from the public key.
func GenerateKey(prefix string) (Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	sum := sha256.Sum256(pub)
	return Key{ID: prefix + "-" + hex.EncodeToString(sum[:6]), Public: pub, Private: priv}, nil
}

// Sign signs msg. In production the control-plane key lives in AWS KMS and
// this becomes a KMS Sign call; the signature format is the same.
func (k Key) Sign(msg []byte) []byte { return ed25519.Sign(k.Private, msg) }

// ---------------------------------------------------------------------------
// Trust configuration
// ---------------------------------------------------------------------------

// TrustConfig is what an agent trusts: public keys by ID, and the signers
// whose signature every runbook bundle must carry.
type TrustConfig struct {
	Keys            map[string]string `json:"keys"` // key_id -> base64 public key
	RequiredSigners []string          `json:"required_signers"`
	// EnvelopeSigners are the control-plane keys allowed to sign dispatch
	// envelopes. Customer co-signer keys can sign runbook bundles but must
	// never be able to dispatch work on their own.
	EnvelopeSigners []string `json:"envelope_signers"`
}

func (tc TrustConfig) publicKey(id string) (ed25519.PublicKey, error) {
	b64, ok := tc.Keys[id]
	if !ok {
		return nil, fmt.Errorf("unknown signing key %q", id)
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("malformed public key %q", id)
	}
	return ed25519.PublicKey(b), nil
}

// ---------------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------------

// Signature is one signer's signature over a digest.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64
}

// Bundle is an immutable published runbook version as shipped to agents.
type Bundle struct {
	Name          string      `json:"name"`
	Version       int         `json:"version"`
	Digest        string      `json:"digest"`
	CanonicalJSON string      `json:"canonical_json"`
	Signatures    []Signature `json:"signatures"`
}

// SignDigest returns a signature over a runbook digest string.
func SignDigest(k Key, digest string) Signature {
	return Signature{KeyID: k.ID, Signature: base64.StdEncoding.EncodeToString(k.Sign([]byte(digest)))}
}

// VerifyBundle recomputes the digest and requires a valid signature from
// every required signer. requiredOverride, if non-empty, replaces the trust
// config's list — that's the agent's locally pinned list, which always wins.
func VerifyBundle(b Bundle, tc TrustConfig, requiredOverride []string) (*runbook.Runbook, error) {
	if got := runbook.Digest([]byte(b.CanonicalJSON)); got != b.Digest {
		return nil, fmt.Errorf("bundle digest mismatch: content hashes to %s, bundle says %s", got, b.Digest)
	}
	required := tc.RequiredSigners
	if len(requiredOverride) > 0 {
		required = requiredOverride
	}
	if len(required) == 0 {
		return nil, errors.New("no required signers configured")
	}
	for _, id := range required {
		pub, err := tc.publicKey(id)
		if err != nil {
			return nil, fmt.Errorf("required signer %s: %w", id, err)
		}
		ok := false
		for _, s := range b.Signatures {
			if s.KeyID != id {
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(s.Signature)
			if err == nil && ed25519.Verify(pub, []byte(b.Digest), sig) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("bundle is missing a valid signature from required signer %s", id)
		}
	}
	rb, err := runbook.FromCanonical([]byte(b.CanonicalJSON))
	if err != nil {
		return nil, err
	}
	// The canonical text must itself be canonical, so no one can smuggle a
	// different-but-equivalent document past a digest pin.
	c, d, err := runbook.Canonical(rb)
	if err != nil || d != b.Digest || string(c) != b.CanonicalJSON {
		return nil, errors.New("bundle content is not in canonical form")
	}
	return rb, nil
}

// ---------------------------------------------------------------------------
// Dispatch envelopes
// ---------------------------------------------------------------------------

// Envelope binds one step attempt to one agent. See agent-protocol.md §6.2.
type Envelope struct {
	AttemptID     string         `json:"attempt_id"`
	RunID         string         `json:"run_id"`
	StepID        string         `json:"step_id"`
	StepIndex     int            `json:"step_index"`
	AttemptNumber int            `json:"attempt_number"`
	RunbookDigest string         `json:"runbook_digest"`
	AgentID       string         `json:"agent_id"`
	OrgID         string         `json:"org_id"`
	Params        map[string]any `json:"params"`
	Context       map[string]any `json:"context"`
	IssuedAt      int64          `json:"issued_at_unix_ms"`
	ExpiresAt     int64          `json:"expires_at_unix_ms"`
	RequestedBy   string         `json:"requested_by"`
}

// SignedEnvelope carries the exact canonical bytes that were signed.
type SignedEnvelope struct {
	Payload   string `json:"payload"`   // canonical JSON of Envelope
	Signature string `json:"signature"` // base64 Ed25519 over Payload
	KeyID     string `json:"key_id"`
}

// SealEnvelope canonicalizes and signs an envelope.
func SealEnvelope(k Key, e Envelope) (SignedEnvelope, error) {
	c, err := canonical.Marshal(e)
	if err != nil {
		return SignedEnvelope{}, err
	}
	return SignedEnvelope{
		Payload:   string(c),
		Signature: base64.StdEncoding.EncodeToString(k.Sign(c)),
		KeyID:     k.ID,
	}, nil
}

// MaxClockSkew is tolerated when checking envelope expiry.
const MaxClockSkew = 30 * time.Second

// OpenEnvelope verifies the signing key, the signature, the target org and
// agent, and the expiry.
// Dispatch envelopes are signed by the control-plane key only; the bundle's
// required signers decide what may run.
func OpenEnvelope(se SignedEnvelope, tc TrustConfig, orgID, agentID string, now time.Time) (Envelope, error) {
	var e Envelope
	if !slices.Contains(tc.EnvelopeSigners, se.KeyID) {
		return e, fmt.Errorf("dispatch envelope is signed by %q, which is not a control-plane key", se.KeyID)
	}
	pub, err := tc.publicKey(se.KeyID)
	if err != nil {
		return e, err
	}
	sig, err := base64.StdEncoding.DecodeString(se.Signature)
	if err != nil || !ed25519.Verify(pub, []byte(se.Payload), sig) {
		return e, errors.New("dispatch envelope signature is invalid")
	}
	if err := decodeStrict([]byte(se.Payload), &e); err != nil {
		return e, fmt.Errorf("decode envelope: %w", err)
	}
	if e.OrgID != orgID {
		return e, fmt.Errorf("envelope is for org %s, not this agent's org", e.OrgID)
	}
	if e.AgentID != agentID {
		return e, fmt.Errorf("envelope is for agent %s, not this agent", e.AgentID)
	}
	if now.Add(-MaxClockSkew).UnixMilli() > e.ExpiresAt {
		return e, errors.New("dispatch envelope expired")
	}
	return e, nil
}
