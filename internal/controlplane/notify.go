package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// PagerDutyEventsURL is the Events API v2 endpoint.
const PagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

const maxNotifyAttempts = 8

// DeliverNotifications sends pending outbox notifications. Pages use the
// incident ID as the PagerDuty dedup_key, so a later resolve closes the same
// upstream page and repeated pages update it instead of duplicating it.
func (s *Server) DeliverNotifications(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.DB.Claim(ctx, "nfx_claim_notification", func(tx *db.Tx, id string) error {
			var kind, typ string
			var payload db.JSON[map[string]any]
			var cfg db.JSON[map[string]string]
			var cred []byte
			var attempts int
			if err := tx.QueryRow(`SELECT n.kind, n.payload, n.attempts, coalesce(t.type, c.type), coalesce(t.config, '{}'),
					coalesce(t.credential, c.credential)
				FROM notifications n LEFT JOIN escalation_targets t ON t.id = n.target_id
				LEFT JOIN approval_channels c ON c.id = n.channel_id WHERE n.id = $1`, id).
				Scan(&kind, &payload, &attempts, &typ, &cfg, &cred); err != nil {
				return err
			}
			secret, err := s.Sealer.Open(cred, tx.OrgID)
			if err != nil {
				// A credential that can't be unsealed won't unseal next time
				// either; failing it keeps it from blocking the outbox.
				s.Log.Error("notification credential unreadable", "notification", id, "err", err)
				_, err := tx.Exec(`UPDATE notifications SET status = 'failed', attempts = attempts + 1, last_error = $2 WHERE id = $1`,
					id, "escalation target credential could not be decrypted")
				return err
			}
			sendErr := s.send(ctx, typ, kind, string(secret), cfg.V, payload.V)
			if sendErr == nil {
				_, err := tx.Exec(`UPDATE notifications SET status = 'sent', sent_at = now(), attempts = attempts + 1 WHERE id = $1`, id)
				return err
			}
			attempts++
			s.Log.Warn("notification delivery failed", "notification", id, "type", typ, "attempt", attempts, "err", sendErr)
			status := "pending"
			if attempts >= maxNotifyAttempts {
				status = "failed"
				if inc, ok := payload.V["incident_id"].(string); ok {
					s.timeline(tx, inc, "notification.failed", "system", "",
						fmt.Sprintf("Could not deliver %s to %s after %d attempts: %v", kind, typ, attempts, sendErr), nil)
				}
			}
			backoff := time.Duration(1<<min(attempts, 6)) * time.Second
			_, err = tx.Exec(`UPDATE notifications SET status = $2, attempts = $3, last_error = $4,
				next_attempt_at = now() + $5::interval WHERE id = $1`, id, status, attempts, sendErr.Error(), pgInterval(backoff))
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

func (s *Server) send(ctx context.Context, typ, kind, secret string, cfg map[string]string, p map[string]any) error {
	switch typ {
	case "slack":
		if kind == "approval" {
			return s.postJSON(ctx, secret, slackApprovalMessage(p))
		}
		return s.postJSON(ctx, secret, map[string]any{"text": slackText(kind, p)})
	case "pagerduty":
		url := cfg["events_url"]
		if url == "" {
			url = PagerDutyEventsURL
		}
		incID, _ := p["incident_id"].(string)
		ev := map[string]any{
			"routing_key":  secret,
			"dedup_key":    ids.Encode("inc", incID),
			"event_action": "trigger",
		}
		switch kind {
		case "resolve":
			ev["event_action"] = "resolve"
		case "page":
			ev["payload"] = map[string]any{
				"summary":  truncate(fmt.Sprintf("#%v %v", p["incident_number"], p["title"]), 1024),
				"source":   fmt.Sprintf("nightfix/%v", p["service"]),
				"severity": pagerDutySeverity(fmt.Sprint(p["severity"])),
				"custom_details": map[string]any{
					"reason": p["reason"], "service": p["service"], "incident": ids.Encode("inc", incID),
				},
			}
		default:
			return nil // progress updates go to Slack only
		}
		return s.postJSON(ctx, url, ev)
	}
	return fmt.Errorf("unknown target type %q", typ)
}

func pagerDutySeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "warning":
		return "warning"
	default:
		return "info"
	}
}

// slackEscape makes a value safe to put in Slack message text. Slack parses
// <…> as control sequences (<!channel>, <@U…>, <https://x|label>) even
// inside backticks, and alert summaries, run errors and approver comments
// are untrusted, so &, < and > are escaped as Slack documents.
func slackEscape(v any) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(fmt.Sprint(v))
}

func slackText(kind string, p map[string]any) string {
	num, title, svc, reason := p["incident_number"], slackEscape(p["title"]), slackEscape(p["service"]), slackEscape(p["reason"])
	if num == nil {
		return fmt.Sprintf(":gear: %v", reason) // approval updates for runs outside an incident
	}
	switch kind {
	case "page":
		return fmt.Sprintf(":rotating_light: <!here> *Incident #%v* on `%v` (%v): %v\n%v", num, svc, slackEscape(p["severity"]), title, reason)
	case "resolve":
		if p["resolution"] == "auto_remediated" {
			return fmt.Sprintf(":white_check_mark: *Incident #%v* on `%v` auto-remediated: %v", num, svc, reason)
		}
		return fmt.Sprintf(":white_check_mark: *Incident #%v* on `%v` resolved: %v", num, svc, reason)
	default:
		return fmt.Sprintf(":gear: *Incident #%v* on `%v`: %v", num, svc, reason)
	}
}

func (s *Server) postJSON(ctx context.Context, url string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Cfg.HTTPClient.Do(req)
	if err != nil {
		// Never log the URL: a Slack webhook URL is itself the credential.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %w", ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}
