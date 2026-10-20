package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/runbook"
)

type startRunOpts struct {
	VersionID, Digest string
	Runbook           *runbook.Runbook
	Params            map[string]any
	IncidentID        string
	Fingerprint       string
	TriggerType       string
	Mode              string
	RequestedByType   string
	RequestedByID     string
	BeforePaging      bool
	Alert, Incident   map[string]any
}

type runRow struct {
	ID          string
	VersionID   string
	RunbookName string
	Digest      string
	IncidentID  sql.NullString
	Status      string
	CurrentStep int
	Params      map[string]any
	Context     map[string]any
	Selector    map[string]string
	RequestedBy string
	Error       sql.NullString
}

func (s *Server) loadRun(tx *db.Tx, id string, lock bool) (runRow, error) {
	q := `SELECT id, runbook_version_id, runbook_name, digest, incident_id, status, current_step, params, context,
		target_selector, requested_by_type || ':' || requested_by_id, error FROM runbook_runs WHERE id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	var r runRow
	var params, rctx db.JSON[map[string]any]
	var sel db.JSON[map[string]string]
	err := tx.QueryRow(q, id).Scan(&r.ID, &r.VersionID, &r.RunbookName, &r.Digest, &r.IncidentID, &r.Status,
		&r.CurrentStep, &params, &rctx, &sel, &r.RequestedBy, &r.Error)
	r.Params, r.Context, r.Selector = params.V, rctx.V, sel.V
	if r.Context == nil {
		r.Context = map[string]any{}
	}
	return r, err
}

// loadVersion returns a published runbook version.
func (s *Server) loadVersion(tx *db.Tx, runbookID string, version int) (*runbook.Runbook, string, string, error) {
	var vid, digest, cj string
	if err := tx.QueryRow(`SELECT id, digest, canonical_json FROM runbook_versions WHERE runbook_id = $1 AND version = $2`,
		runbookID, version).Scan(&vid, &digest, &cj); err != nil {
		return nil, "", "", fmt.Errorf("load runbook version: %w", err)
	}
	rb, err := runbook.FromCanonical([]byte(cj))
	return rb, vid, digest, err
}

func (s *Server) loadVersionByID(tx *db.Tx, versionID string) (*runbook.Runbook, error) {
	var cj string
	if err := tx.QueryRow(`SELECT canonical_json FROM runbook_versions WHERE id = $1`, versionID).Scan(&cj); err != nil {
		return nil, err
	}
	return runbook.FromCanonical([]byte(cj))
}

func selector(rb *runbook.Runbook) map[string]string {
	if rb.Spec.Target.AgentSelector == nil {
		return map[string]string{}
	}
	return rb.Spec.Target.AgentSelector
}

// startRun records a run and advances it to its first agent step.
func (s *Server) startRun(ctx context.Context, tx *db.Tx, o startRunOpts) (string, error) {
	runID := ids.NewString()
	rctx := map[string]any{
		"run":   map[string]any{"id": ids.Encode("run", runID), "mode": o.Mode, "requestedBy": o.RequestedByType + ":" + o.RequestedByID},
		"steps": map[string]any{},
	}
	if o.Alert != nil {
		rctx["alert"] = o.Alert
	}
	if o.Incident != nil {
		rctx["incident"] = o.Incident
	}
	var incident, fp sql.NullString
	if o.IncidentID != "" {
		incident = sql.NullString{String: o.IncidentID, Valid: true}
	}
	if o.Fingerprint != "" {
		fp = sql.NullString{String: o.Fingerprint, Valid: true}
	}
	deadline := time.Now().Add(o.Runbook.RunTimeout())
	if _, err := tx.Exec(`INSERT INTO runbook_runs (id, org_id, runbook_version_id, runbook_name, digest, incident_id, fingerprint,
			trigger_type, mode, requested_by_type, requested_by_id, params, context, target_selector, status, before_paging, deadline_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'running',$15,$16)`,
		runID, tx.OrgID, o.VersionID, o.Runbook.Metadata.Name, o.Digest, incident, fp, o.TriggerType, o.Mode,
		o.RequestedByType, o.RequestedByID, db.JSON[map[string]any]{V: o.Params}, db.JSON[map[string]any]{V: rctx},
		db.JSON[map[string]string]{V: selector(o.Runbook)}, o.BeforePaging, deadline); err != nil {
		return "", err
	}
	if err := tx.Audit(ctx, o.RequestedByType, o.RequestedByID, "run.start", "run", runID,
		map[string]any{"runbook": o.Runbook.Metadata.Name, "digest": o.Digest, "params": o.Params, "mode": o.Mode}); err != nil {
		return "", err
	}
	if o.IncidentID != "" {
		if err := s.timeline(tx, o.IncidentID, "run.started", o.RequestedByType, o.RequestedByID,
			fmt.Sprintf("Run of %s started (%s)", o.Runbook.Metadata.Name, o.Mode),
			map[string]any{"run_id": ids.Encode("run", runID), "params": o.Params}); err != nil {
			return "", err
		}
	}
	return runID, s.advance(ctx, tx, runID)
}

// stepVars is the CEL context the control plane evaluates `when` with.
// `target` is only known on the agent, so `when` can't reference it here.
func stepVars(r runRow) expr.Vars {
	v := expr.Vars{"params": r.Params}
	for _, k := range []string{"alert", "incident", "run", "steps"} {
		if x, ok := r.Context[k]; ok {
			v[k] = x
		}
	}
	return v
}

// advance runs control-plane steps inline and queues the next agent step,
// or finishes the run when no steps remain.
func (s *Server) advance(ctx context.Context, tx *db.Tx, runID string) error {
	run, err := s.loadRun(tx, runID, true)
	if err != nil {
		return err
	}
	if run.Status != "running" {
		return nil
	}
	rb, err := s.loadVersionByID(tx, run.VersionID)
	if err != nil {
		return err
	}
	for idx := run.CurrentStep; idx < len(rb.Spec.Steps); idx++ {
		step := rb.Spec.Steps[idx]
		if step.When != "" {
			ok, err := expr.EvalBool(step.When, stepVars(run))
			if err != nil {
				return s.finishRun(ctx, tx, run, rb, "failed", fmt.Sprintf("step %s: when: %v", step.ID, err))
			}
			if !ok {
				s.recordStep(run, step.ID, "skipped", nil)
				continue
			}
		}
		if step.RunsOnControlPlane() {
			if step.Type == "approval" {
				return s.openGate(ctx, tx, run, rb, idx, step)
			}
			// note: posted to the incident timeline.
			if run.IncidentID.Valid && step.Markdown != "" {
				if err := s.timeline(tx, run.IncidentID.String, "run.note", "runbook", run.RunbookName, step.Markdown,
					map[string]any{"step": step.ID}); err != nil {
					return err
				}
			}
			s.recordStep(run, step.ID, "succeeded", nil)
			continue
		}
		if _, err := tx.Exec(`UPDATE runbook_runs SET current_step = $2, context = $3 WHERE id = $1`,
			run.ID, idx, db.JSON[map[string]any]{V: run.Context}); err != nil {
			return err
		}
		return s.queueAttempt(tx, run.ID, idx, step.ID, 1)
	}
	if _, err := tx.Exec(`UPDATE runbook_runs SET current_step = $2, context = $3 WHERE id = $1`,
		run.ID, len(rb.Spec.Steps), db.JSON[map[string]any]{V: run.Context}); err != nil {
		return err
	}
	return s.finishRun(ctx, tx, run, rb, "succeeded", "")
}

func (s *Server) queueAttempt(tx *db.Tx, runID string, idx int, stepID string, n int) error {
	_, err := tx.Exec(`INSERT INTO step_attempts (id, org_id, run_id, step_index, step_id, attempt_number, state)
		VALUES ($1,$2,$3,$4,$5,$6,'queued')`, ids.NewString(), tx.OrgID, runID, idx, stepID, n)
	return err
}

// recordStep stores a step's status and outputs where later steps read them
// (steps.<id>.outputs.<name>).
func (s *Server) recordStep(run runRow, stepID, status string, outputs map[string]any) {
	steps, _ := run.Context["steps"].(map[string]any)
	if steps == nil {
		steps = map[string]any{}
		run.Context["steps"] = steps
	}
	if outputs == nil {
		outputs = map[string]any{}
	}
	steps[stepID] = map[string]any{"status": status, "outputs": outputs}
}

func (s *Server) finishRun(ctx context.Context, tx *db.Tx, run runRow, rb *runbook.Runbook, status, errMsg string) error {
	var e sql.NullString
	if errMsg != "" {
		e = sql.NullString{String: errMsg, Valid: true}
	}
	if _, err := tx.Exec(`UPDATE runbook_runs SET status = $2, error = $3, finished_at = now(), context = $4 WHERE id = $1`,
		run.ID, status, e, db.JSON[map[string]any]{V: run.Context}); err != nil {
		return err
	}
	// Anything still queued or in flight is cancelled; agents learn on poll.
	if _, err := tx.Exec(`UPDATE step_attempts SET state = 'cancelled', finished_at = now()
		WHERE run_id = $1 AND state IN ('queued','dispatched','running')`, run.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE approval_gates SET status = 'cancelled', decided_at = now()
		WHERE run_id = $1 AND status = 'pending'`, run.ID); err != nil {
		return err
	}
	if err := tx.Audit(ctx, "system", "control-plane", "run.finish", "run", run.ID,
		map[string]any{"status": status, "error": errMsg}); err != nil {
		return err
	}
	run.Status, run.Error = status, e
	return s.onRunFinished(ctx, tx, run, rb)
}

// attemptOutcome is what an agent reports for a step attempt.
type attemptOutcome struct {
	Status   string         `json:"status"` // succeeded | failed | timed_out | cancelled
	ExitCode *int           `json:"exit_code,omitempty"`
	Outputs  map[string]any `json:"outputs,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// onAttemptFinished applies a terminal attempt state to its run: record
// outputs and advance, retry, or fail per the step's onFailure.
func (s *Server) onAttemptFinished(ctx context.Context, tx *db.Tx, attemptID string, state string, out attemptOutcome) error {
	var runID, stepID string
	var idx, n int
	if err := tx.QueryRow(`SELECT run_id, step_id, step_index, attempt_number FROM step_attempts WHERE id = $1`, attemptID).
		Scan(&runID, &stepID, &idx, &n); err != nil {
		return err
	}
	run, err := s.loadRun(tx, runID, true)
	if err != nil || run.Status != "running" || run.CurrentStep != idx {
		return err // run already finished or moved on: the report is stale
	}
	rb, err := s.loadVersionByID(tx, run.VersionID)
	if err != nil {
		return err
	}
	step := rb.Spec.Steps[idx]
	if run.IncidentID.Valid {
		msg := fmt.Sprintf("Step %s (%s): %s", step.ID, step.Type, state)
		if out.Error != "" {
			msg += " — " + out.Error
		}
		if err := s.timeline(tx, run.IncidentID.String, "run.step", "agent", "", msg,
			map[string]any{"run_id": ids.Encode("run", run.ID), "step": step.ID, "attempt": n, "outputs": out.Outputs}); err != nil {
			return err
		}
	}

	switch state {
	case "succeeded":
		s.recordStep(run, step.ID, "succeeded", out.Outputs)
		if _, err := tx.Exec(`UPDATE runbook_runs SET current_step = $2, context = $3 WHERE id = $1`,
			run.ID, idx+1, db.JSON[map[string]any]{V: run.Context}); err != nil {
			return err
		}
		return s.advance(ctx, tx, run.ID)

	case "lost":
		// The agent vanished mid-step. Only steps known to be safe to repeat
		// are retried; anything else may or may not have happened.
		if step.IsIdempotent() && n <= step.Retries {
			return s.queueAttempt(tx, run.ID, idx, step.ID, n+1)
		}
		s.recordStep(run, step.ID, "lost", nil)
		return s.finishRun(ctx, tx, run, rb, "needs_human",
			fmt.Sprintf("step %s may or may not have completed: the agent was lost mid-step", step.ID))

	case "cancelled":
		return nil // cancellation is driven by finishRun, nothing more to do

	default: // failed, timed_out, rejected
		if state != "rejected" && n <= step.Retries {
			return s.queueAttempt(tx, run.ID, idx, step.ID, n+1)
		}
		s.recordStep(run, step.ID, state, out.Outputs)
		errMsg := fmt.Sprintf("step %s %s", step.ID, state)
		if out.Error != "" {
			errMsg += ": " + out.Error
		}
		if step.OnFailure == "continue" {
			if _, err := tx.Exec(`UPDATE runbook_runs SET current_step = $2, context = $3 WHERE id = $1`,
				run.ID, idx+1, db.JSON[map[string]any]{V: run.Context}); err != nil {
				return err
			}
			return s.advance(ctx, tx, run.ID)
		}
		runStatus := "failed"
		if state == "timed_out" {
			runStatus = "timed_out"
		}
		return s.finishRun(ctx, tx, run, rb, runStatus, errMsg)
	}
}

// ProcessExpiredLeases re-queues attempts no agent acknowledged and marks
// acknowledged-then-silent attempts lost.
func (s *Server) ProcessExpiredLeases(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_expired_lease", func(tx *db.Tx, id string) error {
			var state string
			if err := tx.QueryRow(`SELECT state FROM step_attempts WHERE id = $1`, id).Scan(&state); err != nil {
				return err
			}
			if state == "dispatched" {
				// Never started: safe to hand to any matching agent.
				_, err := tx.Exec(`UPDATE step_attempts SET state = 'queued', agent_id = NULL, lease_expires_at = NULL,
					dispatched_at = NULL WHERE id = $1`, id)
				return err
			}
			if _, err := tx.Exec(`UPDATE step_attempts SET state = 'lost', finished_at = now(),
				error = 'agent stopped renewing its lease mid-step' WHERE id = $1`, id); err != nil {
				return err
			}
			return s.onAttemptFinished(ctx, tx, id, "lost", attemptOutcome{Error: "agent lost"})
		})
		if err != nil {
			return n, err
		}
		if !claimed {
			return n, nil
		}
		n++
	}
}

// ProcessOverdueRuns times out runs past their policy timeout.
func (s *Server) ProcessOverdueRuns(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_overdue_run", func(tx *db.Tx, id string) error {
			run, err := s.loadRun(tx, id, false)
			if err != nil {
				return err
			}
			rb, err := s.loadVersionByID(tx, run.VersionID)
			if err != nil {
				return err
			}
			return s.finishRun(ctx, tx, run, rb, "timed_out", "run exceeded its policy timeout of "+rb.RunTimeout().String())
		})
		if err != nil {
			return n, err
		}
		if !claimed {
			return n, nil
		}
		n++
	}
}
