package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/runbook"
)

// Approval steps (runbook-schema.md §3.7). When a run reaches one, the
// control plane opens a gate and the run waits in awaiting_approval. People
// eligible under the step's fromRoles, within their scopes, approve or
// reject it from the API or Slack. Enough approvals continue the run; one
// rejection cancels it; expiry times it out. Approvals always come from a
// person: API keys and triggers can never approve.
//
// A run started by an alert and holding the page (beforePaging) pages as
// soon as it needs an approval: waiting for a human is never a reason to
// keep humans from being told.

type gateRow struct {
	ID               string
	RunID            string
	StepIndex        int
	StepID           string
	Required         int
	FromRoles        []string
	ExcludeRequester bool
	Status           string
	ExpiresAt        time.Time
}

func (s *Server) loadGate(tx *db.Tx, id string, lock bool) (gateRow, error) {
	q := `SELECT id, run_id, step_index, step_id, required_count, from_roles, exclude_requester, status, expires_at
		FROM approval_gates WHERE id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	var g gateRow
	var roles stringArray
	err := tx.QueryRow(q, id).Scan(&g.ID, &g.RunID, &g.StepIndex, &g.StepID, &g.Required, &roles, &g.ExcludeRequester, &g.Status, &g.ExpiresAt)
	g.FromRoles = roles
	if isNoRows(err) {
		return g, httpError{http.StatusNotFound, "no such approval"}
	}
	return g, err
}

func roleList(roles []string) string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = strings.ToUpper(r[:1]) + r[1:]
	}
	return strings.Join(out, " or ")
}

func stepLabel(st runbook.Step) string {
	if st.Name != "" {
		return st.Name
	}
	return st.ID
}

// openGate pauses the run at an approval step.
func (s *Server) openGate(ctx context.Context, tx *db.Tx, run runRow, rb *runbook.Runbook, idx int, st runbook.Step) error {
	expires := time.Now().Add(st.ApprovalExpiry())
	var deadline time.Time
	if err := tx.QueryRow(`SELECT deadline_at FROM runbook_runs WHERE id = $1`, run.ID).Scan(&deadline); err != nil {
		return err
	}
	if deadline.Before(expires) {
		expires = deadline
	}
	gateID := ids.NewString()
	roles := st.ApprovalRoles()
	if _, err := tx.Exec(`INSERT INTO approval_gates (id, org_id, run_id, step_index, step_id, required_count, from_roles, exclude_requester, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, gateID, tx.OrgID, run.ID, idx, st.ID, st.ApprovalCount(), stringArray(roles),
		st.ExcludeRequester, expires); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE runbook_runs SET status = 'awaiting_approval', current_step = $2, context = $3 WHERE id = $1`,
		run.ID, idx, db.JSON[map[string]any]{V: run.Context}); err != nil {
		return err
	}
	if err := tx.Audit(ctx, "system", "control-plane", "approval.requested", "run", run.ID, map[string]any{
		"step": st.ID, "gate": ids.Encode("apr", gateID), "required": st.ApprovalCount(), "from_roles": roles,
		"exclude_requester": st.ExcludeRequester, "expires_at": expires}); err != nil {
		return err
	}
	if !run.IncidentID.Valid {
		return nil // runs outside an incident are approved through the API (GET /v1/approvals lists them)
	}

	need := fmt.Sprintf("%d approval", st.ApprovalCount())
	if st.ApprovalCount() > 1 {
		need += "s"
	}
	msg := fmt.Sprintf("Run of %s is waiting for approval: %s. Needs %s from %s; expires in %s",
		run.RunbookName, stepLabel(st), need, roleList(roles), roundDur(time.Until(expires)))
	if st.ExcludeRequester {
		msg += " (not from whoever started the run)"
	}
	if err := s.timeline(tx, run.IncidentID.String, "approval.requested", "runbook", run.RunbookName, msg,
		map[string]any{"run_id": ids.Encode("run", run.ID), "step": st.ID, "gate": ids.Encode("apr", gateID)}); err != nil {
		return err
	}
	inc, err := s.loadIncident(tx, run.IncidentID.String, true)
	if err != nil {
		return err
	}
	if inc.Status == "remediating" && inc.RemediationRunID.Valid && inc.RemediationRunID.String == run.ID {
		if err := s.page(ctx, tx, inc, fmt.Sprintf("Auto-remediation %s needs an approval before %q; approve or reject it to continue",
			run.RunbookName, stepLabel(st))); err != nil {
			return err
		}
	}
	var interactive int
	if err := tx.QueryRow(`SELECT count(*) FROM slack_apps WHERE archived_at IS NULL`).Scan(&interactive); err != nil {
		return err
	}
	_, err = s.enqueue(tx, inc, "approval", []string{"slack"}, map[string]any{
		"title": inc.Title, "reason": msg, "service": s.serviceName(tx, inc.ServiceID), "severity": inc.Severity,
		"approval": map[string]any{
			"gate": ids.Encode("apr", gateID), "run": ids.Encode("run", run.ID), "step": st.ID, "step_name": stepLabel(st),
			"runbook": run.RunbookName, "interactive": interactive > 0,
		},
	})
	return err
}

// approvalResult is what a decision returns.
type approvalResult struct {
	Gate      string `json:"gate"`
	Run       string `json:"run"`
	Step      string `json:"step"`
	Status    string `json:"status"` // pending | approved | rejected
	Approvals int    `json:"approvals"`
	Required  int    `json:"required"`
}

// decide records one person's decision on a gate and applies it to the run.
// Every check runs again here, at decision time, against the approver's
// current roles (data-model.md §5.3).
func (s *Server) decide(ctx context.Context, tx *db.Tx, p principal, gateID, decision, comment, via string) (approvalResult, error) {
	var res approvalResult
	if p.Kind != "user" {
		return res, httpError{http.StatusForbidden, "approvals must come from a person signed in with Auth0, not an API key"}
	}
	if len(comment) > 1000 {
		return res, httpError{http.StatusBadRequest, "comment is limited to 1000 characters"}
	}
	g, err := s.loadGate(tx, gateID, true)
	if err != nil {
		return res, err
	}
	res = approvalResult{Gate: ids.Encode("apr", g.ID), Run: ids.Encode("run", g.RunID), Step: g.StepID, Status: g.Status, Required: g.Required}
	if g.Status != "pending" {
		return res, httpError{http.StatusConflict, "this approval is already " + g.Status}
	}
	if !g.ExpiresAt.After(time.Now()) {
		return res, httpError{http.StatusConflict, "this approval expired"}
	}
	var frozen sql.NullTime
	if err := tx.QueryRow(`SELECT frozen_at FROM orgs`).Scan(&frozen); err != nil {
		return res, err
	}
	if frozen.Valid {
		return res, httpError{http.StatusConflict, "the org is frozen; nothing can be approved until it's unfrozen"}
	}
	run, err := s.loadRun(tx, g.RunID, true)
	if err != nil {
		return res, err
	}
	if run.Status != "awaiting_approval" || run.CurrentStep != g.StepIndex {
		return res, httpError{http.StatusConflict, "the run is no longer waiting for this approval"}
	}
	rb, err := s.loadVersionByID(tx, run.VersionID)
	if err != nil {
		return res, err
	}
	st := rb.Spec.Steps[g.StepIndex]

	// Eligible if any listed role (or a higher one) reaches this runbook and
	// its target environment through the approver's bindings.
	res2 := runbookResource(rb.Metadata.Team, rb.Metadata.Tags, run.Selector)
	var denied error
	eligible := false
	for _, role := range g.FromRoles {
		if err := p.can(role, res2); err == nil {
			eligible = true
			break
		} else if denied == nil {
			denied = err
		}
	}
	if !eligible {
		return res, httpError{http.StatusForbidden, fmt.Sprintf("approving this step needs the %s role: %v", roleList(g.FromRoles), denied)}
	}
	if g.ExcludeRequester && run.RequestedBy == "user:"+p.actor() {
		return res, httpError{http.StatusForbidden, "you started this run, and this step needs someone else's approval"}
	}
	var voted int
	if err := tx.QueryRow(`SELECT count(*) FROM approvals WHERE gate_id = $1 AND approver_id = $2`, g.ID, p.actor()).Scan(&voted); err != nil {
		return res, err
	}
	if voted > 0 {
		return res, httpError{http.StatusConflict, "you already decided on this approval"}
	}
	if _, err := tx.Exec(`INSERT INTO approvals (id, org_id, gate_id, approver_id, approver_email, decision, comment, via)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, ids.NewString(), tx.OrgID, g.ID, p.actor(), p.Email, decision, comment, via); err != nil {
		return res, err
	}
	if err := tx.Audit(ctx, p.actorType(), p.actor(), "approval."+decision, "run", run.ID,
		map[string]any{"step": g.StepID, "gate": res.Gate, "via": via, "comment": comment}); err != nil {
		return res, err
	}

	approvers, err := s.gateApprovers(tx, g.ID)
	if err != nil {
		return res, err
	}
	res.Approvals = len(approvers)
	who := p.display()
	if via == "slack" {
		who += " (in Slack)"
	}
	var note string
	switch {
	case decision == "rejected":
		res.Status = "rejected"
		note = fmt.Sprintf("Approval for %s rejected by %s", stepLabel(st), who)
		if comment != "" {
			note += ": " + comment
		}
	case len(approvers) >= g.Required:
		res.Status = "approved"
		note = fmt.Sprintf("%s approved by %s (%d of %d); the run continues", stepLabel(st), who, len(approvers), g.Required)
	default:
		res.Status = "pending"
		note = fmt.Sprintf("%s approved by %s (%d of %d); waiting for more", stepLabel(st), who, len(approvers), g.Required)
	}
	if run.IncidentID.Valid {
		if err := s.timeline(tx, run.IncidentID.String, "approval."+decision, p.actorType(), p.actor(), note,
			map[string]any{"run_id": res.Run, "step": g.StepID, "via": via}); err != nil {
			return res, err
		}
		inc, err := s.loadIncident(tx, run.IncidentID.String, false)
		if err != nil {
			return res, err
		}
		if err := s.notifyUpdate(tx, inc, s.serviceName(tx, inc.ServiceID), note); err != nil {
			return res, err
		}
	}

	switch res.Status {
	case "rejected":
		if _, err := tx.Exec(`UPDATE approval_gates SET status = 'rejected', decided_at = now() WHERE id = $1`, g.ID); err != nil {
			return res, err
		}
		s.recordStep(run, g.StepID, "rejected", map[string]any{"rejected_by": p.display()})
		reason := fmt.Sprintf("approval for step %s was rejected by %s", g.StepID, p.display())
		if comment != "" {
			reason += ": " + comment
		}
		return res, s.finishRun(ctx, tx, run, rb, "cancelled", reason)
	case "approved":
		if _, err := tx.Exec(`UPDATE approval_gates SET status = 'approved', decided_at = now() WHERE id = $1`, g.ID); err != nil {
			return res, err
		}
		// Later steps can read who approved: steps.<id>.outputs.approved_by.
		s.recordStep(run, g.StepID, "succeeded", map[string]any{"approved_by": approvers})
		if _, err := tx.Exec(`UPDATE runbook_runs SET status = 'running', current_step = $2, context = $3 WHERE id = $1`,
			run.ID, g.StepIndex+1, db.JSON[map[string]any]{V: run.Context}); err != nil {
			return res, err
		}
		return res, s.advance(ctx, tx, run.ID)
	}
	return res, nil
}

func (s *Server) gateApprovers(tx *db.Tx, gateID string) ([]string, error) {
	rows, err := tx.Query(`SELECT approver_email FROM approvals WHERE gate_id = $1 AND decision = 'approved' ORDER BY decided_at`, gateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var e string
		rows.Scan(&e)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ProcessExpiredGates times out runs whose approval nobody gave in time.
func (s *Server) ProcessExpiredGates(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_expired_gate", func(tx *db.Tx, id string) error {
			g, err := s.loadGate(tx, id, false)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE approval_gates SET status = 'expired', decided_at = now() WHERE id = $1`, id); err != nil {
				return err
			}
			run, err := s.loadRun(tx, g.RunID, true)
			if err != nil {
				return err
			}
			if run.Status != "awaiting_approval" || run.CurrentStep != g.StepIndex {
				return nil
			}
			rb, err := s.loadVersionByID(tx, run.VersionID)
			if err != nil {
				return err
			}
			approvers, err := s.gateApprovers(tx, g.ID)
			if err != nil {
				return err
			}
			if err := tx.Audit(ctx, "system", "control-plane", "approval.expired", "run", run.ID,
				map[string]any{"step": g.StepID, "gate": ids.Encode("apr", g.ID), "approvals": len(approvers)}); err != nil {
				return err
			}
			s.recordStep(run, g.StepID, "expired", map[string]any{"approved_by": approvers})
			return s.finishRun(ctx, tx, run, rb, "timed_out",
				fmt.Sprintf("approval for step %s expired with %d of %d approvals", g.StepID, len(approvers), g.Required))
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

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

func (s *Server) approvalRoutes(route routeFn) {
	route("GET /v1/approvals", "viewer", s.apiListApprovals)
	route("POST /v1/runs/{id}/steps/{step}/approve", "responder*", func(r *http.Request, p principal) (any, error) {
		return s.apiDecide(r, p, "approved")
	})
	route("POST /v1/runs/{id}/steps/{step}/reject", "responder*", func(r *http.Request, p principal) (any, error) {
		return s.apiDecide(r, p, "rejected")
	})
}

func (s *Server) apiDecide(r *http.Request, p principal, decision string) (any, error) {
	runID, err := ids.Decode("run", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	var req struct {
		Comment string `json:"comment"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			return nil, err
		}
	}
	var res approvalResult
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var gateID string
		if err := tx.QueryRow(`SELECT id FROM approval_gates WHERE run_id = $1 AND step_id = $2 ORDER BY step_index DESC LIMIT 1`,
			runID, r.PathValue("step")).Scan(&gateID); err != nil {
			if isNoRows(err) {
				return httpError{404, "this run has no approval for step " + r.PathValue("step")}
			}
			return err
		}
		res, err = s.decide(r.Context(), tx, p, gateID, decision, strings.TrimSpace(req.Comment), "api")
		return err
	})
	return res, err
}

func (s *Server) apiListApprovals(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT g.id, g.run_id, g.step_id, g.required_count, g.from_roles, g.exclude_requester, g.expires_at,
				r.runbook_name, i.number, (SELECT count(*) FROM approvals a WHERE a.gate_id = g.id AND a.decision = 'approved')
			FROM approval_gates g JOIN runbook_runs r ON r.id = g.run_id LEFT JOIN incidents i ON i.id = r.incident_id
			WHERE g.status = 'pending' AND g.expires_at > now() ORDER BY g.expires_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var gid, rid, step, rbName string
			var req, have int
			var roles stringArray
			var excl bool
			var exp time.Time
			var inc sql.NullInt64
			if err := rows.Scan(&gid, &rid, &step, &req, &roles, &excl, &exp, &rbName, &inc, &have); err != nil {
				return err
			}
			a := map[string]any{"gate": ids.Encode("apr", gid), "run": ids.Encode("run", rid), "runbook": rbName, "step": step,
				"required": req, "approvals": have, "from_roles": []string(roles), "exclude_requester": excl, "expires_at": exp}
			if inc.Valid {
				a["incident"] = inc.Int64
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// runApprovals describes a run's gates and decisions for GET /v1/runs/{id}.
func (s *Server) runApprovals(tx *db.Tx, runID string) ([]map[string]any, error) {
	rows, err := tx.Query(`SELECT id, step_id, required_count, from_roles, status, expires_at FROM approval_gates
		WHERE run_id = $1 ORDER BY step_index`, runID)
	if err != nil {
		return nil, err
	}
	var gates []map[string]any
	var gateIDs []string
	for rows.Next() {
		var id, step, status string
		var req int
		var roles stringArray
		var exp time.Time
		if err := rows.Scan(&id, &step, &req, &roles, &status, &exp); err != nil {
			rows.Close()
			return nil, err
		}
		gates = append(gates, map[string]any{"gate": ids.Encode("apr", id), "step": step, "required": req,
			"from_roles": []string(roles), "status": status, "expires_at": exp})
		gateIDs = append(gateIDs, id)
	}
	rows.Close()
	for i, id := range gateIDs {
		vr, err := tx.Query(`SELECT approver_email, decision, comment, via, decided_at FROM approvals WHERE gate_id = $1 ORDER BY decided_at`, id)
		if err != nil {
			return nil, err
		}
		decisions := []map[string]any{}
		for vr.Next() {
			var email, dec, comment, via string
			var at time.Time
			vr.Scan(&email, &dec, &comment, &via, &at)
			decisions = append(decisions, map[string]any{"by": email, "decision": dec, "comment": comment, "via": via, "at": at})
		}
		vr.Close()
		gates[i]["decisions"] = decisions
	}
	return gates, nil
}
