package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
)

// agentIdentity is an authenticated agent (from its mTLS certificate).
type agentIdentity struct {
	OrgID   string
	AgentID string
	Serial  string // serial of the certificate this request authenticated with
}

// Enroll exchanges proof of identity and a CSR for a certificate. Labels
// always come from the matched enrollment rule, never from the agent.
//
//   - iam (default): a SigV4-signed sts:GetCallerIdentity request bound to
//     the org and a single-use challenge nonce; matched on account + role.
//   - token: a single- or limited-use token (fallback for non-IAM hosts).
func (s *Server) Enroll(ctx context.Context, req agentapi.EnrollRequest) (*agentapi.EnrollResponse, error) {
	var orgID, ruleID string
	audit := map[string]any{"method": req.Method}
	switch req.Method {
	case "iam":
		if req.Nonce == "" {
			return nil, httpError{400, "iam enrollment needs a challenge nonce"}
		}
		// Consume the nonce first: a request gets one chance, success or not.
		if err := s.DB.QueryRowContext(ctx, `SELECT org_id FROM nfx_consume_enroll_challenge($1)`, hashSecret(req.Nonce)).
			Scan(&orgID); err != nil {
			return nil, httpError{401, "unknown, used or expired enrollment challenge"}
		}
		if ids.Encode("org", orgID) != req.OrgID {
			return nil, httpError{401, "challenge was issued for a different org"}
		}
		id, err := s.verifyIAM(ctx, req.OrgID, req.Nonce, req.IAM)
		if err != nil {
			return nil, httpError{401, "iam enrollment: " + err.Error()}
		}
		audit["arn"], audit["account"] = id.Arn, id.Account
		denied := false
		err = s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
			err := tx.QueryRow(`SELECT id FROM enrollment_rules WHERE method = 'iam' AND aws_account_id = $1 AND role_name = $2
				AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) ORDER BY created_at LIMIT 1`,
				id.Account, id.RoleName).Scan(&ruleID)
			if isNoRows(err) {
				// Returning nil commits the denial to the audit log.
				denied = true
				return tx.Audit(ctx, "agent", id.Arn, "agent.enroll_denied", "enrollment", id.Arn,
					map[string]string{"reason": "no matching rule", "account": id.Account, "role": id.RoleName})
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		if denied {
			return nil, httpError{403, fmt.Sprintf("no IAM enrollment rule matches role %s in account %s", id.RoleName, id.Account)}
		}
	case "token":
		if err := s.DB.QueryRowContext(ctx, `SELECT org_id, rule_id FROM nfx_route_enrollment_token($1)`, hashSecret(req.Token)).
			Scan(&orgID, &ruleID); err != nil {
			return nil, httpError{401, "invalid or expired enrollment token"}
		}
	default:
		return nil, httpError{400, "method must be iam or token"}
	}
	audit["rule"] = ruleID

	var resp agentapi.EnrollResponse
	err := s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		var labels db.JSON[map[string]string]
		var max, active int
		if err := tx.QueryRow(`SELECT labels, max_agents FROM enrollment_rules WHERE id = $1 FOR UPDATE`, ruleID).Scan(&labels, &max); err != nil {
			return err
		}
		// Agents without persistent disk (Fargate) re-enroll on every start, so
		// count only agents that are live or just enrolled, not old identities.
		if err := tx.QueryRow(`SELECT count(*) FROM agents WHERE enrollment_rule_id = $1 AND revoked_at IS NULL
			AND (last_seen_at > now() - interval '10 minutes' OR created_at > now() - interval '10 minutes')`, ruleID).Scan(&active); err != nil {
			return err
		}
		if active >= max {
			return httpError{403, fmt.Sprintf("enrollment rule allows at most %d live agents", max)}
		}
		agentID := ids.NewString()
		certPEM, serial, exp, err := s.CA.IssueAgentCert([]byte(req.CSRPEM), orgID, agentID)
		if err != nil {
			return httpError{400, err.Error()}
		}
		if _, err := tx.Exec(`INSERT INTO agents (id, org_id, enrollment_rule_id, labels, version, cert_serial, cert_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, agentID, orgID, ruleID, labels, req.Version, serial, exp); err != nil {
			return err
		}
		tc, err := trustConfig(tx)
		if err != nil {
			return err
		}
		resp = agentapi.EnrollResponse{AgentID: agentID, OrgID: orgID, CertPEM: string(certPEM), CAPEM: string(s.CA.CertPEM),
			Labels: labels.V, TrustConfig: tc}
		audit["labels"], audit["cert_serial"] = labels.V, serial
		return tx.Audit(ctx, "agent", agentID, "agent.enroll", "agent", agentID, audit)
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Renew issues a new certificate and retires the old serial.
func (s *Server) Renew(ctx context.Context, a agentIdentity, req agentapi.RenewRequest) (*agentapi.RenewResponse, error) {
	var out agentapi.RenewResponse
	err := s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		certPEM, serial, exp, err := s.CA.IssueAgentCert([]byte(req.CSRPEM), a.OrgID, a.AgentID)
		if err != nil {
			return httpError{400, err.Error()}
		}
		// Keep the serial the agent renewed with valid until it's seen using
		// the new one; if this response is lost the agent can still retry.
		// A retry that authenticates with that previous serial keeps it.
		if _, err := tx.Exec(`UPDATE agents SET
				prev_cert_serial     = CASE WHEN cert_serial = $4 THEN cert_serial ELSE prev_cert_serial END,
				prev_cert_expires_at = CASE WHEN cert_serial = $4 THEN cert_expires_at ELSE prev_cert_expires_at END,
				cert_serial = $2, cert_expires_at = $3
			WHERE id = $1`, a.AgentID, serial, exp, a.Serial); err != nil {
			return err
		}
		out.CertPEM = string(certPEM)
		return tx.Audit(ctx, "agent", a.AgentID, "agent.renew", "agent", a.AgentID, map[string]any{"cert_serial": serial})
	})
	return &out, err
}

// Hello records the agent's capabilities and reconciles in-flight attempts.
func (s *Server) Hello(ctx context.Context, a agentIdentity, h agentapi.Hello) (*agentapi.Welcome, error) {
	if h.ProtocolVersion != agentapi.ProtocolVersion {
		return nil, httpError{426, fmt.Sprintf("protocol version %d is not supported; upgrade the agent", h.ProtocolVersion)}
	}
	var w agentapi.Welcome
	err := s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		var labels db.JSON[map[string]string]
		if err := tx.QueryRow(`UPDATE agents SET status = 'online', last_seen_at = now(), version = $2, capabilities = $3,
			slots = $4, allowlist_mode = $5, frozen_local = $6 WHERE id = $1 RETURNING labels`,
			a.AgentID, h.AgentVersion, stringArray(h.Capabilities), max(h.Slots, 1), h.AllowlistMode, h.FrozenLocal).Scan(&labels); err != nil {
			return err
		}
		if err := s.renewLeases(tx, a, h.InFlight); err != nil {
			return err
		}
		tc, err := trustConfig(tx)
		if err != nil {
			return err
		}
		w = agentapi.Welcome{AgentID: a.AgentID, Labels: labels.V, TrustConfig: tc}
		return nil
	})
	return &w, err
}

func (s *Server) renewLeases(tx *db.Tx, a agentIdentity, inFlight []string) error {
	if len(inFlight) == 0 {
		return nil
	}
	_, err := tx.Exec(`UPDATE step_attempts SET lease_expires_at = now() + $3::interval
		WHERE agent_id = $1 AND id = ANY($2::uuid[]) AND state IN ('dispatched','running')`,
		a.AgentID, stringArray(inFlight), pgInterval(s.Cfg.LeaseDuration))
	return err
}

// Poll long-polls for one step attempt for this agent.
func (s *Server) Poll(ctx context.Context, a agentIdentity, req agentapi.PollRequest) (*agentapi.PollResponse, error) {
	deadline := time.Now().Add(s.Cfg.PollWait)
	for {
		resp, err := s.pollOnce(ctx, a, req)
		if err != nil || resp.Dispatch != nil || len(resp.Cancel) > 0 || resp.Frozen || req.FreeSlots <= 0 || time.Now().After(deadline) {
			return resp, err
		}
		select {
		case <-ctx.Done():
			return resp, nil
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Server) pollOnce(ctx context.Context, a agentIdentity, req agentapi.PollRequest) (*agentapi.PollResponse, error) {
	resp := &agentapi.PollResponse{}
	err := s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		var labels db.JSON[map[string]string]
		var frozenLocal bool
		var revoked sql.NullTime
		if err := tx.QueryRow(`UPDATE agents SET status = 'online', last_seen_at = now() WHERE id = $1
			RETURNING labels, frozen_local, revoked_at`, a.AgentID).Scan(&labels, &frozenLocal, &revoked); err != nil {
			return err
		}
		if revoked.Valid {
			return httpError{403, "agent revoked"}
		}
		if err := s.renewLeases(tx, a, req.InFlight); err != nil {
			return err
		}
		// Attempts this agent holds that were cancelled (run finished, timed out,
		// or org frozen).
		rows, err := tx.Query(`SELECT id FROM step_attempts WHERE agent_id = $1 AND state = 'cancelled' AND id = ANY($2::uuid[])`,
			a.AgentID, stringArray(req.InFlight))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			rows.Scan(&id)
			resp.Cancel = append(resp.Cancel, id)
		}
		rows.Close()

		var frozen sql.NullTime
		if err := tx.QueryRow(`SELECT frozen_at FROM orgs`).Scan(&frozen); err != nil {
			return err
		}
		if frozen.Valid {
			resp.Frozen = true
			return nil
		}
		if frozenLocal || req.FreeSlots <= 0 {
			return nil
		}

		var attemptID, runID, stepID string
		var idx, n int
		err = tx.QueryRow(`SELECT a.id, a.run_id, a.step_id, a.step_index, a.attempt_number
			FROM step_attempts a JOIN runbook_runs r ON r.id = a.run_id
			WHERE a.state = 'queued' AND r.status = 'running' AND r.target_selector <@ $1::jsonb
			ORDER BY a.created_at LIMIT 1 FOR UPDATE OF a SKIP LOCKED`, labels).Scan(&attemptID, &runID, &stepID, &idx, &n)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		run, err := s.loadRun(tx, runID, false)
		if err != nil {
			return err
		}
		d, err := s.buildDispatch(tx, a, run, attemptID, stepID, idx, n)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE step_attempts SET state = 'dispatched', agent_id = $2, dispatched_at = now(),
			lease_expires_at = now() + $3::interval WHERE id = $1`, attemptID, a.AgentID, pgInterval(s.Cfg.LeaseDuration)); err != nil {
			return err
		}
		resp.Dispatch = d
		return nil
	})
	return resp, err
}

func (s *Server) buildDispatch(tx *db.Tx, a agentIdentity, run runRow, attemptID, stepID string, idx, n int) (*agentapi.Dispatch, error) {
	var name, cj, digest string
	var version int
	if err := tx.QueryRow(`SELECT r.name, v.version, v.canonical_json, v.digest FROM runbook_versions v
		JOIN runbooks r ON r.id = v.runbook_id WHERE v.id = $1`, run.VersionID).Scan(&name, &version, &cj, &digest); err != nil {
		return nil, err
	}
	b := signing.Bundle{Name: name, Version: version, Digest: digest, CanonicalJSON: cj}
	rows, err := tx.Query(`SELECT key_id, signature FROM runbook_signatures WHERE version_id = $1 ORDER BY key_id`, run.VersionID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kid string
		var sig []byte
		rows.Scan(&kid, &sig)
		b.Signatures = append(b.Signatures, signing.Signature{KeyID: kid, Signature: base64.StdEncoding.EncodeToString(sig)})
	}
	rows.Close()

	key, err := s.signingKey(tx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	env, err := signing.SealEnvelope(key, signing.Envelope{
		AttemptID: attemptID, RunID: run.ID, StepID: stepID, StepIndex: idx, AttemptNumber: n,
		RunbookDigest: digest, AgentID: a.AgentID, OrgID: a.OrgID, Params: run.Params, Context: run.Context,
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(s.Cfg.EnvelopeTTL).UnixMilli(), RequestedBy: run.RequestedBy,
	})
	if err != nil {
		return nil, err
	}
	return &agentapi.Dispatch{Bundle: b, Envelope: env}, nil
}

// lockAttempt loads an attempt the agent holds, under lock.
func lockAttempt(tx *db.Tx, a agentIdentity, attemptID string) (state string, err error) {
	err = tx.QueryRow(`SELECT state FROM step_attempts WHERE id = $1 AND agent_id = $2 FOR UPDATE`, attemptID, a.AgentID).Scan(&state)
	if isNoRows(err) {
		return "", httpError{404, "unknown attempt for this agent"}
	}
	return state, err
}

// Ack records acceptance (running) or rejection of a dispatch.
func (s *Server) Ack(ctx context.Context, a agentIdentity, attemptID string, ack agentapi.Ack) error {
	return s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		state, err := lockAttempt(tx, a, attemptID)
		if err != nil {
			return err
		}
		if state != "dispatched" {
			return httpError{409, "attempt is " + state}
		}
		if ack.Accepted {
			_, err := tx.Exec(`UPDATE step_attempts SET state = 'running', started_at = now(),
				lease_expires_at = now() + $2::interval WHERE id = $1`, attemptID, pgInterval(s.Cfg.LeaseDuration))
			return err
		}
		if _, err := tx.Exec(`UPDATE step_attempts SET state = 'rejected', error = $2, finished_at = now() WHERE id = $1`,
			attemptID, "agent rejected the dispatch: "+ack.Reason); err != nil {
			return err
		}
		if err := tx.Audit(ctx, "agent", a.AgentID, "attempt.rejected", "step_attempt", attemptID, map[string]string{"reason": ack.Reason}); err != nil {
			return err
		}
		return s.onAttemptFinished(ctx, tx, attemptID, "rejected", attemptOutcome{Error: "agent rejected the dispatch: " + ack.Reason})
	})
}

// Heartbeat renews leases.
func (s *Server) Heartbeat(ctx context.Context, a agentIdentity, h agentapi.Heartbeat) error {
	return s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`UPDATE agents SET status = 'online', last_seen_at = now() WHERE id = $1`, a.AgentID); err != nil {
			return err
		}
		return s.renewLeases(tx, a, h.InFlight)
	})
}

// Output stores redacted output chunks, capped per attempt.
func (s *Server) Output(ctx context.Context, a agentIdentity, attemptID string, b agentapi.OutputBatch) error {
	return s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		if _, err := lockAttempt(tx, a, attemptID); err != nil {
			return err
		}
		var stored int
		if err := tx.QueryRow(`SELECT COALESCE(sum(octet_length(data)), 0) FROM step_output_chunks WHERE attempt_id = $1`, attemptID).Scan(&stored); err != nil {
			return err
		}
		for _, c := range b.Chunks {
			if stored >= agentapi.MaxOutputBytes {
				break
			}
			// Output is arbitrary bytes from customer scripts; Postgres text
			// rejects NUL and invalid UTF-8, and a rejected chunk would fail
			// every retry of this batch and lose the rest of the output.
			data := strings.ReplaceAll(strings.ToValidUTF8(c.Data, "\uFFFD"), "\x00", "\uFFFD")
			data = truncate(data, agentapi.MaxChunkBytes)
			if stored+len(data) > agentapi.MaxOutputBytes {
				data = truncate(data, agentapi.MaxOutputBytes-stored) + "\n[output truncated at 1 MiB]\n"
			}
			stream := c.Stream
			if stream != "stdout" && stream != "stderr" {
				stream = "log"
			}
			// Dedupe resends by seq. The primary key includes received_at (the
			// partition key), so ON CONFLICT never fires for a resend; the
			// attempt row lock taken above serializes writers instead.
			res, err := tx.Exec(`INSERT INTO step_output_chunks (org_id, attempt_id, seq, stream, data)
				SELECT $1,$2,$3,$4,$5 WHERE NOT EXISTS (SELECT 1 FROM step_output_chunks WHERE attempt_id = $2 AND seq = $3)`,
				tx.OrgID, attemptID, c.Seq, stream, data)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			stored += len(data)
		}
		return nil
	})
}

// Result records an attempt's terminal state. Duplicate reports are no-ops.
func (s *Server) Result(ctx context.Context, a agentIdentity, attemptID string, r agentapi.Result) error {
	return s.DB.WithOrg(ctx, a.OrgID, func(tx *db.Tx) error {
		state, err := lockAttempt(tx, a, attemptID)
		if err != nil {
			return err
		}
		if state != "running" && state != "dispatched" {
			return nil // already terminal (duplicate, cancelled or lost): accept and ignore
		}
		switch r.Status {
		case "succeeded", "failed", "timed_out", "cancelled":
		default:
			return httpError{400, "invalid result status"}
		}
		// The control plane's own cancellations are already terminal above,
		// so a "cancelled" report means the agent stopped the step itself
		// (typically shutting down mid-step). The step may or may not have
		// done its work: handle it like a lost agent (retry only if
		// idempotent, otherwise a human decides) rather than leaving the run
		// waiting on an attempt that will never finish.
		if r.Status == "cancelled" {
			r.Status = "lost"
			if r.Error == "" {
				r.Error = "the agent stopped the step before it finished"
			}
		}
		var exit sql.NullInt64
		if r.ExitCode != nil {
			exit = sql.NullInt64{Int64: int64(*r.ExitCode), Valid: true}
		}
		var errMsg sql.NullString
		if r.Error != "" {
			errMsg = sql.NullString{String: r.Error, Valid: true}
		}
		if _, err := tx.Exec(`UPDATE step_attempts SET state = $2, exit_code = $3, outputs = $4, error = $5, finished_at = now()
			WHERE id = $1`, attemptID, r.Status, exit, db.JSON[map[string]any]{V: r.Outputs}, errMsg); err != nil {
			return err
		}
		return s.onAttemptFinished(ctx, tx, attemptID, r.Status, attemptOutcome{Status: r.Status, ExitCode: r.ExitCode, Outputs: r.Outputs, Error: r.Error})
	})
}

var _ = errors.New
