package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/ids"
)

// ProcessAlertEvents drains unprocessed alert events. Each event is claimed
// with SKIP LOCKED, processed in one transaction, and marked processed, so
// processing is at-least-once and every step is idempotent on the alert
// fingerprint.
func (s *Server) ProcessAlertEvents(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_alert_event", func(tx *db.Tx, id string) error {
			perr := s.processEvent(ctx, tx, id)
			msg := sql.NullString{}
			if perr != nil && !errors.Is(perr, errIgnore) {
				// A malformed event is recorded and never retried; a database
				// error rolls back and the event is claimed again.
				var pe processError
				if !errors.As(perr, &pe) {
					return perr
				}
				msg = sql.NullString{String: pe.Error(), Valid: true}
				s.Log.Warn("alert event rejected", "event", id, "err", pe)
			}
			_, err := tx.Exec(`UPDATE alert_events SET processed_at = now(), error = $2 WHERE id = $1`, id, msg)
			return err
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

// processError is a permanent problem with an event's content.
type processError struct{ error }

type serviceRow struct {
	ID             string
	Name           string
	GroupingLabels []string
	GroupingWindow time.Duration
	MaxHold        time.Duration
	Verification   time.Duration
	Reopen         time.Duration
	AutoResolve    bool
}

const serviceCols = `id, name, grouping_labels,
	EXTRACT(EPOCH FROM grouping_window)::float8, EXTRACT(EPOCH FROM max_hold)::float8,
	EXTRACT(EPOCH FROM verification_window)::float8, EXTRACT(EPOCH FROM reopen_window)::float8, auto_resolve`

func scanService(row interface{ Scan(...any) error }) (serviceRow, error) {
	var s serviceRow
	var gl stringArray
	var gw, mh, vw, rw float64
	err := row.Scan(&s.ID, &s.Name, &gl, &gw, &mh, &vw, &rw, &s.AutoResolve)
	s.GroupingLabels = gl
	s.GroupingWindow = secs(gw)
	s.MaxHold = secs(mh)
	s.Verification = secs(vw)
	s.Reopen = secs(rw)
	return s, err
}

func secs(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

func (s *Server) loadService(tx *db.Tx, id string) (serviceRow, error) {
	return scanService(tx.QueryRow(`SELECT `+serviceCols+` FROM services WHERE id = $1`, id))
}

func (s *Server) processEvent(ctx context.Context, tx *db.Tx, eventID string) error {
	var integID, raw string
	if err := tx.QueryRow(`SELECT integration_id, raw FROM alert_events WHERE id = $1`, eventID).Scan(&integID, &raw); err != nil {
		return err
	}
	var typ, defaultSvc string
	var sevMap db.JSON[map[string]string]
	var dedupe stringArray
	if err := tx.QueryRow(`SELECT type, default_service_id, severity_map, dedupe_keys FROM integrations WHERE id = $1`, integID).
		Scan(&typ, &defaultSvc, &sevMap, &dedupe); err != nil {
		return err
	}

	var a Alert
	var err error
	switch typ {
	case "cloudwatch":
		var m snsMessage
		if m, err = parseSNS([]byte(raw)); err == nil {
			a, err = normalizeCloudWatch(m.Message, sevMap.V)
		}
	case "webhook":
		a, err = normalizeWebhook(integID, []byte(raw), dedupe)
	default:
		err = fmt.Errorf("unknown integration type %q", typ)
	}
	if errors.Is(err, errIgnore) {
		return errIgnore
	}
	if err != nil {
		return processError{err}
	}

	svcID, suppressed, err := s.route(tx, a, defaultSvc)
	if err != nil {
		return err
	}
	svc, err := s.loadService(tx, svcID)
	if err != nil {
		return err
	}
	if a.Status == "firing" {
		return s.alertFiring(ctx, tx, a, integID, svc, suppressed)
	}
	return s.alertResolved(ctx, tx, a)
}

// alertVars is how an alert appears to CEL (routing rules, trigger matches,
// runbook parameters).
func alertVars(a Alert) map[string]any {
	return map[string]any{
		"fingerprint": a.Fingerprint,
		"status":      a.Status,
		"severity":    a.Severity,
		"summary":     a.Summary,
		"source":      a.Source,
		"labels":      a.Labels,
		"annotations": a.Annotations,
	}
}

// route applies the org's ordered routing rules; first match wins. With no
// match, the integration's default service applies. No alert is unrouted.
func (s *Server) route(tx *db.Tx, a Alert, defaultSvc string) (serviceID string, suppressed bool, err error) {
	rows, err := tx.Query(`SELECT match, action, service_id FROM routing_rules ORDER BY priority, created_at`)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	vars := expr.Vars{"alert": alertVars(a)}
	for rows.Next() {
		var match, action string
		var svc sql.NullString
		if err := rows.Scan(&match, &action, &svc); err != nil {
			return "", false, err
		}
		ok, err := expr.EvalBool(match, vars)
		if err != nil || !ok {
			continue // a rule that errors on this alert simply doesn't match
		}
		if action == "suppress" {
			return defaultSvc, true, nil
		}
		return svc.String, false, nil
	}
	return defaultSvc, false, rows.Err()
}

func (s *Server) alertFiring(ctx context.Context, tx *db.Tx, a Alert, integID string, svc serviceRow, suppressed bool) error {
	labels := db.JSON[map[string]string]{V: a.Labels}
	ann := db.JSON[map[string]string]{V: a.Annotations}

	// Repeat firing of an open alert: update it, never page again.
	var openID, prevSev string
	err := tx.QueryRow(`SELECT id, severity FROM alerts WHERE fingerprint = $1 AND status = 'firing' FOR UPDATE`, a.Fingerprint).Scan(&openID, &prevSev)
	if err == nil {
		if _, err := tx.Exec(`UPDATE alerts SET last_seen_at = now(), event_count = event_count + 1,
			summary = $2, labels = $3, annotations = $4, severity = $5 WHERE id = $1`,
			openID, a.Summary, labels, ann, a.Severity); err != nil {
			return err
		}
		if severityRank(a.Severity) > severityRank(prevSev) {
			return s.alertSeverityRaised(ctx, tx, openID, a)
		}
		return nil
	}
	if !isNoRows(err) {
		return err
	}

	// Re-fire within the reopen window reopens the same alert.
	var reopenID string
	var prevIncident sql.NullString
	err = tx.QueryRow(`
		SELECT a.id, ia.incident_id FROM alerts a
		LEFT JOIN LATERAL (
			SELECT incident_id FROM incident_alerts WHERE alert_id = a.id ORDER BY attached_at DESC LIMIT 1
		) ia ON true
		WHERE a.fingerprint = $1 AND a.status = 'resolved' AND a.resolved_at > now() - $2::interval
		ORDER BY a.resolved_at DESC LIMIT 1 FOR UPDATE OF a`,
		a.Fingerprint, pgInterval(svc.Reopen)).Scan(&reopenID, &prevIncident)
	var alertID string
	reopened := false
	switch {
	case err == nil:
		alertID, reopened = reopenID, true
		if _, err := tx.Exec(`UPDATE alerts SET status = 'firing', resolved_at = NULL, last_seen_at = now(),
			event_count = event_count + 1, summary = $2, labels = $3, annotations = $4, severity = $5 WHERE id = $1`,
			alertID, a.Summary, labels, ann, a.Severity); err != nil {
			return err
		}
	case isNoRows(err):
		alertID = ids.NewString()
		res, err := tx.Exec(`INSERT INTO alerts (id, org_id, fingerprint, integration_id, service_id, status, severity,
				summary, source, labels, annotations, suppressed, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,'firing',$6,$7,$8,$9,$10,$11,$12,now())
			ON CONFLICT (org_id, fingerprint) WHERE status <> 'resolved' DO NOTHING`,
			alertID, tx.OrgID, a.Fingerprint, integID, svc.ID, a.Severity, a.Summary, a.Source, labels, ann, suppressed, a.OccurredAt)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // a concurrent event created it; that one owns the incident
		}
	default:
		return err
	}
	if suppressed {
		return nil
	}

	// A re-fire after an incident resolved within the reopen window reopens
	// that incident and pages. Auto-remediation is not retried for it.
	if reopened && prevIncident.Valid {
		var st string
		var resolvedAt sql.NullTime
		if err := tx.QueryRow(`SELECT status, resolved_at FROM incidents WHERE id = $1 FOR UPDATE`, prevIncident.String).
			Scan(&st, &resolvedAt); err != nil {
			return err
		}
		if st != "resolved" {
			return s.attachAlert(ctx, tx, prevIncident.String, alertID, a)
		}
		if resolvedAt.Valid && time.Since(resolvedAt.Time) < svc.Reopen {
			if err := s.reopenIncident(ctx, tx, prevIncident.String, alertID, a); err != nil {
				return err
			}
			return nil
		}
	}
	return s.openOrJoinIncident(ctx, tx, svc, alertID, a)
}

func (s *Server) alertResolved(ctx context.Context, tx *db.Tx, a Alert) error {
	var alertID string
	err := tx.QueryRow(`UPDATE alerts SET status = 'resolved', resolved_at = now(), last_seen_at = now(),
		event_count = event_count + 1 WHERE fingerprint = $1 AND status = 'firing' RETURNING id`, a.Fingerprint).Scan(&alertID)
	if isNoRows(err) {
		return nil // resolve for an alert we don't have open: nothing to do
	}
	if err != nil {
		return err
	}
	var incidentID string
	err = tx.QueryRow(`SELECT ia.incident_id FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id
		WHERE ia.alert_id = $1 AND ia.detached_at IS NULL AND i.status <> 'resolved'`, alertID).Scan(&incidentID)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.timeline(tx, incidentID, "alert.resolved", "integration", "", "Alert resolved: "+a.Summary, nil); err != nil {
		return err
	}
	return s.checkAlertsCleared(ctx, tx, incidentID)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

// pgInterval renders a duration for a $n::interval parameter.
func pgInterval(d time.Duration) string {
	return fmt.Sprintf("%d milliseconds", d.Milliseconds())
}

func groupKey(svc serviceRow, labels map[string]string) string {
	parts := []string{svc.Name}
	for _, l := range svc.GroupingLabels {
		parts = append(parts, labels[l])
	}
	return strings.Join(parts, "/")
}
