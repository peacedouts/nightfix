package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/runbook"
)

type incidentRow struct {
	ID               string
	Number           int64
	ServiceID        string
	Status           string
	Severity         string
	Title            string
	RemediationRunID sql.NullString
	PagedAt          sql.NullTime
	HoldUntil        sql.NullTime
	VerifyUntil      sql.NullTime
}

func (s *Server) loadIncident(tx *db.Tx, id string, lock bool) (incidentRow, error) {
	q := `SELECT id, number, service_id, status, severity, title, remediation_run_id, paged_at, hold_until, verify_until
		FROM incidents WHERE id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	var i incidentRow
	err := tx.QueryRow(q, id).Scan(&i.ID, &i.Number, &i.ServiceID, &i.Status, &i.Severity, &i.Title,
		&i.RemediationRunID, &i.PagedAt, &i.HoldUntil, &i.VerifyUntil)
	return i, err
}

// timeline appends to an incident's append-only timeline.
func (s *Server) timeline(tx *db.Tx, incidentID, typ, actorType, actorID, msg string, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	_, err := tx.Exec(`INSERT INTO incident_timeline (org_id, incident_id, type, actor_type, actor_id, message, data)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tx.OrgID, incidentID, typ, actorType, actorID, msg, db.JSON[map[string]any]{V: data})
	return err
}

// openOrJoinIncident groups an alert into an open incident with the same
// group key (within the grouping window) or opens a new one.
func (s *Server) openOrJoinIncident(ctx context.Context, tx *db.Tx, svc serviceRow, alertID string, a Alert) error {
	gk := groupKey(svc, a.Labels)
	var incID string
	var openedAt time.Time
	err := tx.QueryRow(`SELECT id, opened_at FROM incidents WHERE service_id = $1 AND group_key = $2 AND status <> 'resolved' FOR UPDATE`,
		svc.ID, gk).Scan(&incID, &openedAt)
	switch {
	case err == nil && time.Since(openedAt) < svc.GroupingWindow:
		return s.attachAlert(ctx, tx, incID, alertID, a)
	case err == nil:
		// Outside the grouping window: retire the old incident's group key so a
		// stuck incident doesn't absorb an unrelated problem.
		if _, err := tx.Exec(`UPDATE incidents SET group_key = group_key || '#' || id::text WHERE id = $1`, incID); err != nil {
			return err
		}
	case !isNoRows(err):
		return err
	}

	num, err := tx.NextCounter(ctx, "incident")
	if err != nil {
		return err
	}
	incID = ids.NewString()
	res, err := tx.Exec(`INSERT INTO incidents (id, org_id, number, service_id, group_key, status, severity, title)
		VALUES ($1,$2,$3,$4,$5,'triggered',$6,$7)
		ON CONFLICT (org_id, service_id, group_key) WHERE status <> 'resolved' DO NOTHING`,
		incID, tx.OrgID, num, svc.ID, gk, a.Severity, a.Summary)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if err := tx.QueryRow(`SELECT id FROM incidents WHERE service_id = $1 AND group_key = $2 AND status <> 'resolved'`, svc.ID, gk).Scan(&incID); err != nil {
			return err
		}
		return s.attachAlert(ctx, tx, incID, alertID, a)
	}
	if _, err := tx.Exec(`INSERT INTO incident_alerts (org_id, incident_id, alert_id) VALUES ($1,$2,$3)`, tx.OrgID, incID, alertID); err != nil {
		return err
	}
	if err := s.timeline(tx, incID, "incident.opened", "system", "",
		fmt.Sprintf("Incident #%d opened on %s by %s alert: %s", num, svc.Name, a.Severity, a.Summary),
		map[string]any{"group_key": gk, "fingerprint": a.Fingerprint}); err != nil {
		return err
	}
	inc, err := s.loadIncident(tx, incID, true)
	if err != nil {
		return err
	}
	return s.decideRemediation(ctx, tx, inc, svc, a)
}

func (s *Server) attachAlert(ctx context.Context, tx *db.Tx, incID, alertID string, a Alert) error {
	if _, err := tx.Exec(`INSERT INTO incident_alerts (org_id, incident_id, alert_id) VALUES ($1,$2,$3)
		ON CONFLICT (org_id, incident_id, alert_id) DO UPDATE SET detached_at = NULL`, tx.OrgID, incID, alertID); err != nil {
		return err
	}
	if err := s.timeline(tx, incID, "alert.joined", "system", "", "Alert joined incident: "+a.Summary,
		map[string]any{"fingerprint": a.Fingerprint}); err != nil {
		return err
	}
	return s.raiseSeverity(ctx, tx, incID, a.Severity)
}

func (s *Server) alertSeverityRaised(ctx context.Context, tx *db.Tx, alertID string, a Alert) error {
	var incID string
	err := tx.QueryRow(`SELECT ia.incident_id FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id
		WHERE ia.alert_id = $1 AND ia.detached_at IS NULL AND i.status <> 'resolved'`, alertID).Scan(&incID)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.raiseSeverity(ctx, tx, incID, a.Severity)
}

// raiseSeverity upgrades an incident to the highest alert severity. A
// critical upgrade during a held remediation pages immediately: critical
// incidents page in parallel with remediation by default.
func (s *Server) raiseSeverity(ctx context.Context, tx *db.Tx, incID, sev string) error {
	inc, err := s.loadIncident(tx, incID, true)
	if err != nil {
		return err
	}
	if severityRank(sev) <= severityRank(inc.Severity) {
		return nil
	}
	if _, err := tx.Exec(`UPDATE incidents SET severity = $2 WHERE id = $1`, incID, sev); err != nil {
		return err
	}
	if err := s.timeline(tx, incID, "incident.severity", "system", "", fmt.Sprintf("Severity raised from %s to %s", inc.Severity, sev), nil); err != nil {
		return err
	}
	if inc.Status == "remediating" && sev == "critical" {
		inc.Severity = sev
		return s.page(ctx, tx, inc, "Severity rose to critical; critical incidents page in parallel with remediation")
	}
	return nil
}

func (s *Server) reopenIncident(ctx context.Context, tx *db.Tx, incID, alertID string, a Alert) error {
	if _, err := tx.Exec(`UPDATE incidents SET status = 'triggered', resolved_at = NULL, resolution = NULL,
		hold_until = NULL, verify_until = NULL WHERE id = $1`, incID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO incident_alerts (org_id, incident_id, alert_id) VALUES ($1,$2,$3)
		ON CONFLICT (org_id, incident_id, alert_id) DO UPDATE SET detached_at = NULL`, tx.OrgID, incID, alertID); err != nil {
		return err
	}
	if err := s.timeline(tx, incID, "incident.reopened", "system", "", "Incident reopened: alert re-fired within the reopen window", nil); err != nil {
		return err
	}
	inc, err := s.loadIncident(tx, incID, true)
	if err != nil {
		return err
	}
	return s.page(ctx, tx, inc, "The alert re-fired shortly after the incident resolved, so the earlier fix didn't hold. Auto-remediation is not retried for this incident.")
}

// checkAlertsCleared resolves the incident when every attached alert has
// resolved — as auto-remediated if a held remediation run succeeded.
func (s *Server) checkAlertsCleared(ctx context.Context, tx *db.Tx, incID string) error {
	inc, err := s.loadIncident(tx, incID, true)
	if err != nil || inc.Status == "resolved" {
		return err
	}
	var firing int
	if err := tx.QueryRow(`SELECT count(*) FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id
		WHERE ia.incident_id = $1 AND ia.detached_at IS NULL AND a.status = 'firing'`, incID).Scan(&firing); err != nil {
		return err
	}
	if firing > 0 {
		return nil
	}
	svc, err := s.loadService(tx, inc.ServiceID)
	if err != nil {
		return err
	}
	if inc.Status == "remediating" && inc.RemediationRunID.Valid {
		var runStatus, name string
		if err := tx.QueryRow(`SELECT status, runbook_name FROM runbook_runs WHERE id = $1`, inc.RemediationRunID.String).Scan(&runStatus, &name); err != nil {
			return err
		}
		if runStatus == "running" {
			return s.timeline(tx, incID, "remediation.waiting", "system", "", "All alerts cleared while the remediation run is still in progress; waiting for it to finish", nil)
		}
		if runStatus == "succeeded" {
			if _, err := tx.Exec(`UPDATE runbook_runs SET verified = true WHERE id = $1`, inc.RemediationRunID.String); err != nil {
				return err
			}
			return s.resolveIncident(ctx, tx, inc, "auto_remediated",
				fmt.Sprintf("Auto-remediated by %s: the run succeeded and every alert cleared. Nobody was paged.", name))
		}
		return nil
	}
	if !svc.AutoResolve {
		return s.timeline(tx, incID, "alerts.cleared", "system", "", "All alerts cleared; auto-resolve is off for this service", nil)
	}
	return s.resolveIncident(ctx, tx, inc, "alerts_resolved", "All alerts resolved")
}

// triggerMatch is one runbook trigger that matched an incident's alert.
type triggerMatch struct {
	RunbookID, Name string
	Version         int
	Mode            string
	BeforePaging    bool
	Cooldown        time.Duration
	MaxRunsPerHour  int
}

func (s *Server) matchTriggers(tx *db.Tx, svc serviceRow, a Alert) ([]triggerMatch, error) {
	rows, err := tx.Query(`SELECT r.id, r.name, t.version, t.mode, t.match, t.before_paging,
			COALESCE(EXTRACT(EPOCH FROM t.cooldown), 0)::float8, COALESCE(t.max_runs_per_hour, 0)
		FROM runbook_triggers t JOIN runbooks r ON r.id = t.runbook_id
		WHERE t.type = 'alert' AND r.archived_at IS NULL AND t.version = r.latest_version
		  AND (t.services @> ARRAY[$1]::text[] OR (cardinality(t.services) = 0 AND t.mode <> 'auto'))
		ORDER BY r.name, t.idx`, svc.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vars := expr.Vars{"alert": alertVars(a)}
	var out []triggerMatch
	seen := map[string]bool{}
	for rows.Next() {
		var m triggerMatch
		var match string
		var cd float64
		if err := rows.Scan(&m.RunbookID, &m.Name, &m.Version, &m.Mode, &match, &m.BeforePaging, &cd, &m.MaxRunsPerHour); err != nil {
			return nil, err
		}
		m.Cooldown = secs(cd)
		ok, err := expr.EvalBool(match, vars)
		if err != nil || !ok {
			continue
		}
		key := m.RunbookID + m.Mode
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out, rows.Err()
}

// decideRemediation implements remediate-before-paging
// (alert-incident-model.md §8).
func (s *Server) decideRemediation(ctx context.Context, tx *db.Tx, inc incidentRow, svc serviceRow, a Alert) error {
	matches, err := s.matchTriggers(tx, svc, a)
	if err != nil {
		return err
	}
	var held, parallel []triggerMatch
	for _, m := range matches {
		switch m.Mode {
		case "auto":
			if m.BeforePaging {
				held = append(held, m)
			} else {
				parallel = append(parallel, m)
			}
		default:
			if err := s.timeline(tx, inc.ID, "runbook.suggested", "system", "",
				fmt.Sprintf("Runbook %s is available for this incident (%s)", m.Name, m.Mode), map[string]any{"runbook": m.Name}); err != nil {
				return err
			}
		}
	}
	alertCtx := alertVars(a)

	if len(held) > 1 {
		var names []string
		for _, m := range held {
			names = append(names, m.Name)
		}
		return s.page(ctx, tx, inc, "More than one auto-remediation runbook matched ("+strings.Join(names, ", ")+"); a human decides which to run")
	}

	pageReason := ""
	if len(held) == 1 {
		m := held[0]
		runID, reason, err := s.tryAutoRun(ctx, tx, inc, m, alertCtx, a.Fingerprint, true)
		if err != nil {
			return err
		}
		switch {
		case reason != "":
			pageReason = "Auto-remediation " + m.Name + " did not start: " + reason
		case inc.Severity == "critical":
			pageReason = "Auto-remediation " + m.Name + " is running; critical incidents page in parallel"
			if _, err := tx.Exec(`UPDATE incidents SET remediation_run_id = $2 WHERE id = $1`, inc.ID, runID); err != nil {
				return err
			}
		default:
			rb, _, _, err := s.loadVersion(tx, m.RunbookID, m.Version)
			if err != nil {
				return err
			}
			hold := rb.RunTimeout() + svc.Verification
			if hold > svc.MaxHold {
				hold = svc.MaxHold
			}
			if _, err := tx.Exec(`UPDATE incidents SET status = 'remediating', remediation_run_id = $2,
				hold_until = now() + $3::interval WHERE id = $1`, inc.ID, runID, pgInterval(hold)); err != nil {
				return err
			}
			msg := fmt.Sprintf("Auto-remediation started: %s for %s — paging held for up to %s", m.Name, svc.Name, roundDur(hold))
			if err := s.timeline(tx, inc.ID, "remediation.started", "system", "", msg, map[string]any{"run_id": runID, "hold": hold.String()}); err != nil {
				return err
			}
			if err := s.notifyUpdate(tx, inc, svc.Name, msg); err != nil {
				return err
			}
		}
	}
	for _, m := range parallel {
		if _, reason, err := s.tryAutoRun(ctx, tx, inc, m, alertCtx, a.Fingerprint, false); err != nil {
			return err
		} else if reason != "" {
			if err := s.timeline(tx, inc.ID, "remediation.skipped", "system", "", "Auto runbook "+m.Name+" did not start: "+reason, nil); err != nil {
				return err
			}
		}
		if pageReason == "" {
			pageReason = "Auto runbook " + m.Name + " runs alongside paging (beforePaging is off)"
		}
	}
	if len(held) == 1 && pageReason == "" {
		return nil // held: no page unless remediation fails or the hold expires
	}
	if pageReason == "" {
		pageReason = "No auto-remediation runbook matched"
	}
	return s.page(ctx, tx, inc, pageReason)
}

// tryAutoRun checks the guardrails and starts an auto run. It returns a
// non-empty reason, and no run, when a guardrail blocks it.
func (s *Server) tryAutoRun(ctx context.Context, tx *db.Tx, inc incidentRow, m triggerMatch, alertCtx map[string]any, fingerprint string, beforePaging bool) (runID, reason string, err error) {
	var frozen sql.NullTime
	if err := tx.QueryRow(`SELECT frozen_at FROM orgs`).Scan(&frozen); err != nil {
		return "", "", err
	}
	if frozen.Valid {
		return "", "the org is frozen (kill switch)", nil
	}
	rb, versionID, digest, err := s.loadVersion(tx, m.RunbookID, m.Version)
	if err != nil {
		return "", "", err
	}
	incCtx := map[string]any{"id": ids.Encode("inc", inc.ID), "number": inc.Number, "title": inc.Title, "severity": inc.Severity}
	params, perr := runbook.ResolveParams(rb, nil, expr.Vars{"alert": alertCtx, "incident": incCtx})
	if perr != nil {
		return "", "parameters could not be resolved from the alert: " + perr.Error(), nil
	}
	var healthy int
	if err := tx.QueryRow(`SELECT count(*) FROM agents WHERE status = 'online' AND revoked_at IS NULL AND NOT frozen_local
		AND last_seen_at > now() - interval '45 seconds' AND labels @> $1::jsonb`,
		db.JSON[map[string]string]{V: selector(rb)}).Scan(&healthy); err != nil {
		return "", "", err
	}
	if healthy == 0 {
		return "", "no healthy agent matches the runbook's target", nil
	}
	// Serializes the counts below with any concurrent start of this runbook
	// (several control-plane instances process events in parallel), so
	// cooldown, maxRunsPerHour and concurrency can't be exceeded by a race.
	if reason, err := s.concurrencyBlocked(tx, rb, params); err != nil || reason != "" {
		return "", reason, err
	}
	if m.Cooldown > 0 {
		var recent int
		if err := tx.QueryRow(`SELECT count(*) FROM runbook_runs WHERE runbook_name = $1 AND mode = 'auto'
			AND params = $2::jsonb AND started_at > now() - $3::interval`,
			m.Name, db.JSON[map[string]any]{V: params}, pgInterval(m.Cooldown)).Scan(&recent); err != nil {
			return "", "", err
		}
		if recent > 0 {
			return "", fmt.Sprintf("cooldown: it already ran for these parameters within %s", roundDur(m.Cooldown)), nil
		}
	}
	if m.MaxRunsPerHour > 0 {
		var lastHour int
		if err := tx.QueryRow(`SELECT count(*) FROM runbook_runs WHERE runbook_name = $1 AND mode = 'auto'
			AND started_at > now() - interval '1 hour'`, m.Name).Scan(&lastHour); err != nil {
			return "", "", err
		}
		if lastHour >= m.MaxRunsPerHour {
			return "", fmt.Sprintf("rate limit: maxRunsPerHour (%d) reached", m.MaxRunsPerHour), nil
		}
	}
	var fixes int
	if err := tx.QueryRow(`SELECT count(*) FROM runbook_runs WHERE fingerprint = $1 AND mode = 'auto' AND verified
		AND started_at > now() - interval '24 hours'`, fingerprint).Scan(&fixes); err != nil {
		return "", "", err
	}
	if fixes >= FlapGuardThreshold {
		return "", fmt.Sprintf("flap guard: this alert was auto-remediated %d times in 24h, so the real problem isn't being fixed", fixes), nil
	}

	runID, err = s.startRun(ctx, tx, startRunOpts{
		VersionID: versionID, Digest: digest, Runbook: rb, Params: params,
		IncidentID: inc.ID, Fingerprint: fingerprint, TriggerType: "alert", Mode: "auto",
		RequestedByType: "trigger", RequestedByID: m.Name + "@" + fmt.Sprint(m.Version),
		BeforePaging: beforePaging, Alert: alertCtx, Incident: incCtx,
	})
	return runID, "", err
}

// FlapGuardThreshold: verified auto-fixes of one alert in 24h before we stop
// auto-remediating it and page instead.
const FlapGuardThreshold = 3

// page moves the incident to triggered and sends pages to every escalation
// target on the service (falling back to the catch-all service's targets).
func (s *Server) page(ctx context.Context, tx *db.Tx, inc incidentRow, reason string) error {
	if _, err := tx.Exec(`UPDATE incidents SET status = CASE WHEN status = 'acknowledged' THEN status ELSE 'triggered' END,
		paged_at = now(), hold_until = NULL, verify_until = NULL WHERE id = $1`, inc.ID); err != nil {
		return err
	}
	if err := s.timeline(tx, inc.ID, "incident.paged", "system", "", "Paging on-call: "+reason, nil); err != nil {
		return err
	}
	svcName := s.serviceName(tx, inc.ServiceID)
	n, err := s.enqueue(tx, inc, "page", []string{"pagerduty", "slack"}, map[string]any{
		"title": inc.Title, "reason": reason, "service": svcName, "severity": inc.Severity,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return s.timeline(tx, inc.ID, "incident.page_undeliverable", "system", "",
			"No escalation targets on this service or the catch-all service; nobody could be paged", nil)
	}
	return nil
}

// resolveIncident resolves an incident and resolves any upstream pages.
func (s *Server) resolveIncident(ctx context.Context, tx *db.Tx, inc incidentRow, resolution, msg string) error {
	if _, err := tx.Exec(`UPDATE incidents SET status = 'resolved', resolved_at = now(), resolution = $2,
		hold_until = NULL, verify_until = NULL WHERE id = $1`, inc.ID, resolution); err != nil {
		return err
	}
	if err := s.timeline(tx, inc.ID, "incident.resolved", "system", "", msg, map[string]any{"resolution": resolution}); err != nil {
		return err
	}
	svcName := s.serviceName(tx, inc.ServiceID)
	payload := map[string]any{"title": inc.Title, "reason": msg, "service": svcName, "severity": inc.Severity, "resolution": resolution}
	if inc.PagedAt.Valid {
		if _, err := s.enqueue(tx, inc, "resolve", []string{"pagerduty", "slack"}, payload); err != nil {
			return err
		}
		return nil
	}
	_, err := s.enqueue(tx, inc, "resolve", []string{"slack"}, payload)
	return err
}

// notifyUpdate posts a progress message to Slack targets only.
func (s *Server) notifyUpdate(tx *db.Tx, inc incidentRow, svcName, msg string) error {
	_, err := s.enqueue(tx, inc, "update", []string{"slack"}, map[string]any{
		"title": inc.Title, "reason": msg, "service": svcName, "severity": inc.Severity,
	})
	return err
}

func (s *Server) serviceName(tx *db.Tx, id string) string {
	var n string
	tx.QueryRow(`SELECT name FROM services WHERE id = $1`, id).Scan(&n)
	return n
}

// enqueue writes notifications to the outbox for targets of the given types.
func (s *Server) enqueue(tx *db.Tx, inc incidentRow, kind string, types []string, payload map[string]any) (int, error) {
	payload["incident_id"] = inc.ID
	payload["incident_number"] = inc.Number
	payload["kind"] = kind
	targets := func(where string, arg any) ([]string, error) {
		rows, err := tx.Query(`SELECT id FROM escalation_targets t WHERE type = ANY($1) AND `+where, stringArray(types), arg)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			out = append(out, id)
		}
		return out, rows.Err()
	}
	ts, err := targets("service_id = $2", inc.ServiceID)
	if err != nil {
		return 0, err
	}
	if len(ts) == 0 {
		if ts, err = targets("service_id = (SELECT id FROM services WHERE is_catch_all) AND $2::text IS NOT NULL", "catch-all"); err != nil {
			return 0, err
		}
	}
	for _, t := range ts {
		if _, err := tx.Exec(`INSERT INTO notifications (id, org_id, incident_id, target_id, kind, payload) VALUES ($1,$2,$3,$4,$5,$6)`,
			ids.NewString(), tx.OrgID, inc.ID, t, kind, db.JSON[map[string]any]{V: payload}); err != nil {
			return 0, err
		}
	}
	return len(ts), nil
}

// ProcessDueIncidents pages remediating incidents whose hold or
// verification window expired.
func (s *Server) ProcessDueIncidents(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_due_incident", func(tx *db.Tx, id string) error {
			inc, err := s.loadIncident(tx, id, false)
			if err != nil {
				return err
			}
			reason := "The paging hold expired before remediation finished; the run continues and its result will be posted here"
			if inc.VerifyUntil.Valid && !inc.VerifyUntil.Time.After(time.Now()) {
				reason = "Remediation ran but the alert is still firing after the verification window"
			}
			return s.page(ctx, tx, inc, reason)
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

// onRunFinished updates the incident when a run ends.
func (s *Server) onRunFinished(ctx context.Context, tx *db.Tx, run runRow, rb *runbook.Runbook) error {
	if !run.IncidentID.Valid {
		return nil
	}
	inc, err := s.loadIncident(tx, run.IncidentID.String, true)
	if err != nil {
		return err
	}
	svc, err := s.loadService(tx, inc.ServiceID)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("Run of %s %s", run.RunbookName, describeRunOutcome(run))
	if err := s.timeline(tx, inc.ID, "run.finished", "system", "", msg, map[string]any{"run_id": run.ID, "status": run.Status}); err != nil {
		return err
	}
	if inc.Status == "resolved" {
		return nil
	}
	held := inc.Status == "remediating" && inc.RemediationRunID.Valid && inc.RemediationRunID.String == run.ID

	if run.Status == "succeeded" {
		if err := s.notifyUpdate(tx, inc, svc.Name, msg); err != nil {
			return err
		}
		if !held {
			return s.checkAlertsCleared(ctx, tx, inc.ID)
		}
		var firing int
		if err := tx.QueryRow(`SELECT count(*) FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id
			WHERE ia.incident_id = $1 AND ia.detached_at IS NULL AND a.status = 'firing'`, inc.ID).Scan(&firing); err != nil {
			return err
		}
		if firing == 0 {
			return s.checkAlertsCleared(ctx, tx, inc.ID)
		}
		verify := time.Now().Add(svc.Verification)
		if inc.HoldUntil.Valid && inc.HoldUntil.Time.Before(verify) {
			verify = inc.HoldUntil.Time
		}
		if _, err := tx.Exec(`UPDATE incidents SET verify_until = $2 WHERE id = $1`, inc.ID, verify); err != nil {
			return err
		}
		return s.timeline(tx, inc.ID, "remediation.verifying", "system", "",
			fmt.Sprintf("Waiting up to %s for the alerts to clear", roundDur(time.Until(verify))), nil)
	}

	// Failed, timed out, cancelled, or needs a human.
	action := "escalate"
	if rb.Spec.OnFailure != nil {
		action = rb.Spec.OnFailure.Action
	}
	reason := msg
	if rb.Spec.OnFailure != nil && rb.Spec.OnFailure.Message != "" {
		if m, err := expr.RenderString(rb.Spec.OnFailure.Message, expr.Vars{"params": run.Params}); err == nil {
			reason = fmt.Sprint(m)
			if run.Error.Valid {
				reason += " (" + run.Error.String + ")"
			}
		}
	}
	stepEscalated, _ := run.Context["escalate"].(bool) // a step with onFailure: escalate failed
	if held || action == "escalate" || stepEscalated || run.Status == "needs_human" {
		return s.page(ctx, tx, inc, reason)
	}
	if action == "notify" {
		return s.notifyUpdate(tx, inc, svc.Name, reason)
	}
	return nil
}

func describeRunOutcome(r runRow) string {
	switch r.Status {
	case "succeeded":
		return "succeeded"
	case "needs_human":
		return "needs a human: " + r.Error.String
	default:
		out := strings.ReplaceAll(r.Status, "_", " ")
		if r.Error.Valid {
			out += " (" + r.Error.String + ")"
		}
		return out
	}
}

func roundDur(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return strings.TrimSuffix(d.Round(time.Second).String(), "0s")
}
