// Package agentapi defines the messages exchanged between the agent and the
// control plane's agent gateway.
//
// Transport note: agent-protocol.md specifies one long-lived gRPC
// bidirectional stream. This skeleton carries the same messages over mutual
// TLS HTTPS with long-polling (POST /agent/v1/poll), which needs no generated
// code. The message shapes, signatures, leases and failure semantics are the
// protocol's; swapping the transport for gRPC later doesn't change them.
package agentapi

import "github.com/peacedouts/nightfix/internal/signing"

// ProtocolVersion is sent in Hello. A control plane accepts agents of the
// previous minor release (deploy/README.md, "Releases and upgrades"): when
// this changes, keep accepting the previous version for a minor release.
const ProtocolVersion = 1

// EnrollRequest is sent once, before the agent has a certificate.
type EnrollRequest struct {
	Method  string      `json:"method"` // iam (default) | token
	Token   string      `json:"token,omitempty"`
	OrgID   string      `json:"org_id,omitempty"` // iam: the org the agent is joining
	Nonce   string      `json:"nonce,omitempty"`  // iam: from ChallengeResponse
	IAM     *IAMRequest `json:"iam,omitempty"`
	CSRPEM  string      `json:"csr_pem"`
	Version string      `json:"agent_version"`
}

// Headers the agent must include in, and sign into, its STS request. Binding
// the org and a single-use nonce into the signature means the request can't
// be replayed later or used to enroll into a different org.
const (
	HeaderOrg   = "X-Nightfix-Org"
	HeaderNonce = "X-Nightfix-Nonce"
)

// STSBody is the exact GetCallerIdentity request body the control plane accepts.
const STSBody = "Action=GetCallerIdentity&Version=2011-06-15"

// IAMRequest is a SigV4-signed sts:GetCallerIdentity request that the agent
// built but did not send. The control plane sends it to STS itself; STS
// verifies the signature and answers with the caller's identity. The control
// plane builds the STS URL from Region — it never fetches a URL the agent
// supplies.
type IAMRequest struct {
	Region  string              `json:"region"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// ChallengeRequest asks for an enrollment nonce.
type ChallengeRequest struct {
	OrgID string `json:"org_id"`
}

// ChallengeResponse carries a single-use nonce valid for a few minutes.
type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

// EnrollResponse carries the agent's identity and trust configuration.
type EnrollResponse struct {
	AgentID     string              `json:"agent_id"`
	OrgID       string              `json:"org_id"`
	CertPEM     string              `json:"cert_pem"`
	CAPEM       string              `json:"ca_pem"`
	Labels      map[string]string   `json:"labels"`
	TrustConfig signing.TrustConfig `json:"trust_config"`
}

// RenewRequest asks for a fresh certificate before the current one expires.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse returns the new certificate.
type RenewResponse struct {
	CertPEM string `json:"cert_pem"`
}

// Hello is sent on every (re)connect.
type Hello struct {
	ProtocolVersion int      `json:"protocol_version"`
	AgentVersion    string   `json:"agent_version"`
	Capabilities    []string `json:"capabilities"`
	Slots           int      `json:"slots"`
	AllowlistMode   string   `json:"allowlist_mode"`
	FrozenLocal     bool     `json:"frozen_local"`
	InFlight        []string `json:"in_flight"`
}

// Welcome answers Hello.
type Welcome struct {
	AgentID     string              `json:"agent_id"`
	Labels      map[string]string   `json:"labels"`
	TrustConfig signing.TrustConfig `json:"trust_config"`
}

// PollRequest asks for work. FreeSlots of zero means "just tell me about
// cancellations and freezes".
type PollRequest struct {
	FreeSlots int      `json:"free_slots"`
	InFlight  []string `json:"in_flight"`
}

// PollResponse returns at most one dispatch.
type PollResponse struct {
	Dispatch *Dispatch `json:"dispatch,omitempty"`
	Cancel   []string  `json:"cancel,omitempty"` // attempt ids to stop
	Frozen   bool      `json:"frozen,omitempty"` // org kill switch is on
}

// Dispatch is one step attempt: the signed runbook bundle and the signed
// envelope binding the attempt to this agent.
type Dispatch struct {
	Bundle   signing.Bundle         `json:"bundle"`
	Envelope signing.SignedEnvelope `json:"envelope"`
}

// Ack accepts or rejects a dispatch.
type Ack struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// Heartbeat renews leases for attempts still running.
type Heartbeat struct {
	InFlight []string `json:"in_flight"`
}

// OutputChunk is redacted stdout/stderr or an executor log line.
type OutputChunk struct {
	Seq    int    `json:"seq"`
	Stream string `json:"stream"` // stdout | stderr | log
	Data   string `json:"data"`
}

// OutputBatch carries several chunks.
type OutputBatch struct {
	Chunks []OutputChunk `json:"chunks"`
}

// Result is the terminal report for an attempt.
type Result struct {
	Status   string         `json:"status"` // succeeded | failed | timed_out | cancelled
	ExitCode *int           `json:"exit_code,omitempty"`
	Outputs  map[string]any `json:"outputs,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// MaxChunkBytes and MaxOutputBytes bound streamed output.
const (
	MaxChunkBytes  = 32 << 10
	MaxOutputBytes = 1 << 20
)
