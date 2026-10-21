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
	need := fmt.Sprintf("%d approval", st.ApprovalCount())
	if st.ApprovalCount() > 1 {
		need += "s"
	}
	msg := fmt.Sprintf("Run of %s is waiting for approval: %s. Needs %s from %s; expires in %s",
		run.RunbookName, stepLabel(st), need, roleList(roles), roundDur(time.Until(expires)))
	if st.ExcludeRequester {
		msg += " (not from whoever started the run)"
	}
	var inc *incidentRow
	if run.IncidentID.Valid {
		if err := s.timeline(tx, run.IncidentID.String, "approval.requested", "runbook", run.RunbookName, msg,
			map[string]any{"run_id": ids.Encode("run", run.ID), "step": st.ID, "gate": ids.Encode("apr", gateID)}); err != nil {
			return err
		}
		i, err := s.loadIncident(tx, run.IncidentID.String, true)
		if err != nil {
			return err
		}
		if i.Status == "remediating" && i.RemediationRunID.Valid && i.RemediationRunID.String == run.ID {
			if err := s.page(ctx, tx, i, fmt.Sprintf("Auto-remediation %s needs an approval before %q; approve or reject it to continue",
				run.RunbookName, stepLabel(st))); err != nil {
				return err
			}
		}
		inc = &i
	}
	var interactive int
	if err := tx.QueryRow(`SELECT count(*) FROM slack_apps WHERE archived_at IS NULL`).Scan(&interactive); err != nil {
		return err
	}
	return s.notifyApproval(tx, rb, inc, "approval", map[string]any{
		"reason": msg,
		"approval": map[string]any{
			"gate": ids.Encode("apr", gateID), "run": ids.Encode("run", run.ID), "step": st.ID, "step_name": stepLabel(st),
			"runbook": run.RunbookName, "interactive": interactive > 0, "requested_by": s.requesterDisplay(tx, run),
		},
	})
}

// notifyApproval sends an approval request or decision to Slack. Runs in an
// incident use the incident's service targets, like every other incident
// message. Otherwise (or when the service has no Slack target) it goes to
// the runbook team's approval channel, else the org's default one.
func (s *Server) notifyApproval(tx *db.Tx, rb *runbook.Runbook, inc *incidentRow, kind string, payload map[string]any) error {
	if inc != nil {
		payload["title"], payload["service"], payload["severity"] = inc.Title, s.serviceName(tx, inc.ServiceID), inc.Severity
		n, err := s.enqueue(tx, *inc, kind, []string{"slack"}, payload)
		if err != nil || n > 0 {
			return err
		}
	}
	var channel string
	err := tx.QueryRow(`SELECT c.id FROM approval_channels c LEFT JOIN teams t ON t.id = c.team_id
		WHERE (t.slug = $1 AND t.archived_at IS NULL) OR c.team_id IS NULL
		ORDER BY c.team_id IS NULL LIMIT 1`, rb.Metadata.Team).Scan(&channel)
	if isNoRows(err) {
		return nil // nowhere configured; GET /v1/approvals still lists it
	}
	if err != nil {
		return err
	}
	var incID any
	if inc != nil {
		incID = inc.ID
	}
	payload["kind"] = kind
	_, err = tx.Exec(`INSERT INTO notifications (id, org_id, incident_id, channel_id, kind, payload) VALUES ($1,$2,$3,$4,$5,$6)`,
		ids.NewString(), tx.OrgID, incID, channel, kind, db.JSON[map[string]any]{V: payload})
	return err
}

// approvalClosed posts that a run's approval request is over to wherever
// the request went (the incident's Slack targets or the approval channel).
func (s *Server) approvalClosed(tx *db.Tx, rb *runbook.Runbook, run runRow, note string) error {
	var inc *incidentRow
	if run.IncidentID.Valid {
		i, err := s.loadIncident(tx, run.IncidentID.String, false)
		if err != nil {
			return err
		}
		inc = &i
	}
	return s.notifyApproval(tx, rb, inc, "update", map[string]any{"reason": note})
}

// requesterDisplay names whoever started a run, for people deciding on it.
func (s *Server) requesterDisplay(tx *db.Tx, run runRow) string {
	typ, id, _ := strings.Cut(run.RequestedBy, ":")
	switch typ {
	case "user":
		if uid, err := ids.Decode("usr", id); err == nil {
			var email string
			if tx.QueryRow(`SELECT email FROM nfx_org_users() WHERE id = $1`, uid).Scan(&email) == nil {
				return email
			}
		}
		return id
	case "api_key":
		return "an API key (" + id + ")"
	default:
		return "an alert trigger"
	}
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
	// Lock order everywhere: org, then run, then gate. Freeze takes the org
	// row first; run timeouts and gate expiry take the run first.
	var frozen sql.NullTime
	if err := tx.QueryRow(`SELECT frozen_at FROM orgs FOR SHARE`).Scan(&frozen); err != nil {
		return res, err
	}
	g, err := s.loadGate(tx, gateID, false)
	if err != nil {
		return res, err
	}
	run, err := s.loadRun(tx, g.RunID, true)
	if err != nil {
		return res, err
	}
	if g, err = s.loadGate(tx, gateID, true); err != nil {
		return res, err
	}
	res = approvalResult{Gate: ids.Encode("apr", g.ID), Run: ids.Encode("run", g.RunID), Step: g.StepID, Status: g.Status, Required: g.Required}
	if g.Status != "pending" {
		return res, httpError{http.StatusConflict, "this approval is already " + g.Status}
	}
	if !g.ExpiresAt.After(time.Now()) {
		return res, httpError{http.StatusConflict, "this approval expired"}
	}
	if frozen.Valid {
		return res, httpError{http.StatusConflict, "the org is frozen; nothing can be approved until it's unfrozen"}
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
	eligible, denied := canApprove(p, g, res2)
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

	// Only approvals from people who are still eligible count: someone who
	// approved and then lost the role (or left the org) no longer does.
	approvers, err := s.eligibleApprovers(tx, g, run, res2)
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
	var inc *incidentRow
	if run.IncidentID.Valid {
		if err := s.timeline(tx, run.IncidentID.String, "approval."+decision, p.actorType(), p.actor(), note,
			map[string]any{"run_id": res.Run, "step": g.StepID, "via": via}); err != nil {
			return res, err
		}
		i, err := s.loadIncident(tx, run.IncidentID.String, false)
		if err != nil {
			return res, err
		}
		inc = &i
	}
	if err := s.notifyApproval(tx, rb, inc, "update", map[string]any{"reason": fmt.Sprintf("%s (run of %s)", note, run.RunbookName)}); err != nil {
		return res, err
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

// canApprove reports whether p may decide gate g on resource res.
func canApprove(p principal, g gateRow, res resource) (bool, error) {
	var denied error
	for _, role := range g.FromRoles {
		if err := p.can(role, res); err == nil {
			return true, nil
		} else if denied == nil {
			denied = err
		}
	}
	return false, denied
}

// eligibleApprovers returns the emails of the gate's approvals whose
// approvers can still approve it now: active members whose current bindings
// satisfy fromRoles, and not the requester when that's excluded.
func (s *Server) eligibleApprovers(tx *db.Tx, g gateRow, run runRow, res resource) ([]string, error) {
	rows, err := tx.Query(`SELECT approver_id, approver_email FROM approvals WHERE gate_id = $1 AND decision = 'approved' ORDER BY decided_at`, g.ID)
	if err != nil {
		return nil, err
	}
	type vote struct{ id, email string }
	var votes []vote
	for rows.Next() {
		var v vote
		if err := rows.Scan(&v.id, &v.email); err != nil {
			rows.Close()
			return nil, err
		}
		votes = append(votes, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []string{}
	for _, v := range votes {
		userID, err := ids.Decode("usr", v.id)
		if err != nil {
			continue
		}
		if g.ExcludeRequester && run.RequestedBy == "user:"+v.id {
			continue
		}
		var status string
		if err := tx.QueryRow(`SELECT status FROM org_members WHERE org_id = $1 AND user_id = $2`, tx.OrgID, userID).Scan(&status); err != nil {
			if isNoRows(err) {
				continue
			}
			return nil, err
		}
		if status != "active" {
			continue
		}
		p := principal{Kind: "user", OrgID: tx.OrgID, UserID: userID}
		if err := s.loadUserBindings(tx, &p); err != nil {
			return nil, err
		}
		if ok, _ := canApprove(p, g, res); ok {
			out = append(out, v.email)
		}
	}
	return out, nil
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
	return s.drain(ctx, "nfx_claim_expired_gate", func(tx *db.Tx, id string) error {
		// The claim locked the run; lock the gate second, like everyone else.
		g, err := s.loadGate(tx, id, true)
		if err != nil {
			return err
		}
		if g.Status != "pending" {
			return nil // decided while we waited
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
		msg := fmt.Sprintf("approval for step %s expired with %d of %d approvals", g.StepID, len(approvers), g.Required)
		// Close the request where it was posted, so its buttons don't look live.
		if err := s.approvalClosed(tx, rb, run, fmt.Sprintf("Approval for %s expired with %d of %d approvals; the run of %s timed out",
			g.StepID, len(approvers), g.Required, run.RunbookName)); err != nil {
			return err
		}
		return s.finishRun(ctx, tx, run, rb, "timed_out", msg)
	})
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

func (s *Server) approvalRoutes(route routeFn) {
	route("GET /v1/approvals", "viewer", s.apiListApprovals)
	route("PUT /v1/approval-channels", "admin", s.apiPutApprovalChannel)
	route("GET /v1/approval-channels", "admin", s.apiListApprovalChannels)
	route("POST /v1/runs/{id}/steps/{step}/approve", "responder*", func(r *http.Request, p principal) (any, error) {
		return s.apiDecide(r, p, "approved")
	})
	route("POST /v1/runs/{id}/steps/{step}/reject", "responder*", func(r *http.Request, p principal) (any, error) {
		return s.apiDecide(r, p, "rejected")
	})
}

// apiPutApprovalChannel sets where approval requests go for a team (or, with
// no team, the org default). It replaces any existing channel for that team.
func (s *Server) apiPutApprovalChannel(r *http.Request, p principal) (any, error) {
	var req struct {
		Team string `json:"team"` // team slug; empty for the org default
		URL  string `json:"url"`  // Slack incoming-webhook URL
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if validateNotifyURL("slack", req.URL, s.Cfg.AllowPrivateTargets) != nil {
		return nil, httpError{400, "url must be a Slack incoming-webhook URL (https://hooks.slack.com/...)"}
	}
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var team any
		if req.Team != "" {
			var tid string
			if err := tx.QueryRow(`SELECT id FROM teams WHERE slug = $1 AND archived_at IS NULL`, req.Team).Scan(&tid); err != nil {
				if isNoRows(err) {
					return httpError{404, "no team " + req.Team}
				}
				return err
			}
			team = tid
		}
		sealed, err := s.Sealer.Seal([]byte(req.URL), p.OrgID)
		if err != nil {
			return err
		}
		// Replace the URL in place: notifications already sent reference the
		// channel row, so deleting it to insert a new one fails once the
		// channel has been used (and races with a concurrent PUT).
		if err := tx.QueryRow(`INSERT INTO approval_channels (id, org_id, team_id, credential, created_by) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (org_id, coalesce(team_id, '00000000-0000-0000-0000-000000000000'))
			DO UPDATE SET credential = EXCLUDED.credential, created_by = EXCLUDED.created_by, created_at = now()
			RETURNING id`, id, p.OrgID, team, sealed, p.actor()).Scan(&id); err != nil {
			return err
		}
		// The webhook URL is itself a credential: never logged or returned.
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "approval_channel.set", "approval_channel", id, map[string]string{"team": req.Team})
	})
	scope := req.Team
	if scope == "" {
		scope = "org default"
	}
	return map[string]string{"id": ids.Encode("apc", id), "for": scope}, err
}

func (s *Server) apiListApprovalChannels(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT c.id, coalesce(t.slug, ''), c.created_at FROM approval_channels c LEFT JOIN teams t ON t.id = c.team_id
			ORDER BY t.slug NULLS FIRST`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, team string
			var at time.Time
			rows.Scan(&id, &team, &at)
			if team == "" {
				team = "org default"
			}
			out = append(out, map[string]any{"id": ids.Encode("apc", id), "for": team, "created_at": at})
		}
		return rows.Err()
	})
	return out, err
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
