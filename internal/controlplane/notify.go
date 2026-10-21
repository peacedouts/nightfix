package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// PagerDutyEventsURL is the Events API v2 endpoint.
const PagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

const (
	// notifyLease is how long a claimed notification stays with its worker.
	// It must outlast one request (notifyRequestTimeout) plus recording the
	// result; a worker that dies leaves the row claimable when it expires.
	notifyLease = time.Minute
	// notifySendWindow is how long after claiming a worker may still start
	// sending: a send that starts by then ends (notifyRequestTimeout) well
	// before the lease does, so a worker that stalled can't send after
	// another has taken the row over. The rest of the lease records it.
	notifySendWindow = notifyLease - 15*time.Second
	// notifyRecordTimeout bounds recording a result. It runs even during
	// shutdown, so a page that went out isn't sent again.
	notifyRecordTimeout = 10 * time.Second
	// pageResolvedGrace: a page whose incident has resolved stops after
	// maxNotifyAttempts failures or once it is this old, whichever is first
	// (a 429 doesn't use up an attempt).
	pageResolvedGrace = 10 * time.Minute
	// maxNotifyAttempts bounds retries of progress updates and approval
	// messages. Pages and resolves retry until notifyMaxAge instead (a page
	// stops early if its incident is resolved after this many attempts).
	maxNotifyAttempts = 8
	notifyMaxAge      = 24 * time.Hour
	// notifyMaxBackoff caps the retry interval of pages and resolves.
	notifyMaxBackoff = 5 * time.Minute
	maxRetryAfter    = 10 * time.Minute
	// maxNotifyErrorLen caps last_error and timeline reasons.
	maxNotifyErrorLen = 500
)

// The outbox (migration 0020): a worker claims one due notification with a
// lease and commits, sends it outside any transaction, then records the
// result in a new transaction fenced on the lease id. Notifications for the
// same destination (incident + escalation target, or approval channel) go
// out in creation order: a leased row is still pending, so its successors
// wait for it, and a row that backs off moves its successors back with it.
// Delivery is at least once; pages use the incident ID as the PagerDuty
// dedup_key, so a repeated page updates the upstream incident instead of
// duplicating it, and a later resolve closes it.

// DeliverNotifications delivers every due notification, Cfg.NotifyWorkers
// at a time, and returns once none is left. A notification that can't be
// delivered (or whose result can't be recorded) never stops the others;
// only an error claiming work (the database is unreachable, or ctx is
// done) is returned. RunWorkers runs the same workers continuously.
func (s *Server) DeliverNotifications(ctx context.Context) (int, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		total    int
		firstErr error
	)
	for range s.Cfg.NotifyWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.deliverDue(ctx)
			mu.Lock()
			defer mu.Unlock()
			total += n
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}()
	}
	wg.Wait()
	return total, firstErr
}

// notifyWorker is one of RunWorkers' delivery goroutines. Each claims and
// sends independently, so a slow endpoint holds up only its own worker.
func (s *Server) notifyWorker(ctx context.Context, tick time.Duration) {
	defer s.workers.Done()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if _, err := s.deliverDue(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("worker", "loop", "notifications", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) deliverDue(ctx context.Context) (int, error) {
	n := 0
	for {
		claimed, err := s.deliverOne(ctx)
		if err != nil {
			return n, err
		}
		if !claimed {
			return n, nil
		}
		n++
	}
}

// notifyJob is a claimed notification and its destination.
type notifyJob struct {
	OrgID, ID, LeaseID string
	Kind, Type         string
	Payload            map[string]any
	Config             map[string]string
	Credential         []byte
	Attempts           int
	LastError          string
	IncidentID         sql.NullString
	TargetID           sql.NullString
	ChannelID          sql.NullString
	IncidentStatus     string
	Age                time.Duration
}

// deliveryError is why a notification wasn't delivered. Its message is
// stored in last_error and shown in the incident timeline, which any viewer
// can read, so it never includes the URL or transport details; those go to
// the operator log only.
type deliveryError struct {
	msg        string
	detail     error // operator logs only
	permanent  bool  // retrying can't help
	throttled  bool  // HTTP 429: doesn't use up an attempt
	retryAfter time.Duration
}

func (e *deliveryError) Error() string { return e.msg }

// cleanNotifyError makes an error message storable and bounded.
func cleanNotifyError(s string) string {
	return truncate(cleanText(s), maxNotifyErrorLen)
}

// deliverOne claims, sends and records one notification. It reports
// whether anything was claimed; errors other than claim errors are logged
// and recorded on the row, never returned.
//
// Once claimed, a notification is seen through even if ctx is cancelled
// (shutdown): the send is bounded by notifyRequestTimeout, and recording
// its result is what keeps a page from going out twice. Stopping means
// claiming nothing more. A send is only started while the lease has
// comfortably longer to run than the request can take.
func (s *Server) deliverOne(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	lease := ids.NewString()
	claimed := time.Now()
	var org, id string
	err := s.DB.QueryRowContext(ctx, `SELECT org_id, id FROM nfx_claim_notification($1::interval, $2, $3)`,
		pgInterval(notifyLease), lease, s.notifyOrgLimit()).Scan(&org, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	work, cancel := context.WithDeadline(context.WithoutCancel(ctx), claimed.Add(notifySendWindow))
	defer cancel()
	j, err := s.loadNotification(work, org, id, lease)
	if err != nil {
		if work.Err() != nil {
			s.releaseNotification(ctx, org, id, lease)
			return true, nil
		}
		s.Log.Error("notification could not be loaded", "notification", id, "org", org, "err", err)
		s.recordBareFailure(ctx, org, id, lease, "internal error preparing the notification")
		return true, nil
	}
	if j == nil {
		return true, nil // lease lost, or too little of it left to send
	}
	if dl, _ := work.Deadline(); time.Until(dl) < notifyRequestTimeout {
		// Stalled since the claim: sending now could outlast the lease and
		// race whoever claims the row next. Give it back untried.
		s.Log.Warn("notification claim went stale before sending; released", "notification", id, "org", org)
		s.releaseNotification(ctx, org, id, lease)
		return true, nil
	}
	derr := s.attemptNotification(work, j)
	s.recordNotification(ctx, j, derr)
	return true, nil
}

// notifyOrgLimit is how many notifications of one org may be in flight at
// once (leased, across all instances), so one org's slow destinations or a
// burst of its updates can't occupy every worker.
func (s *Server) notifyOrgLimit() int {
	return max(1, s.Cfg.NotifyWorkers/4)
}

func (s *Server) loadNotification(ctx context.Context, org, id, lease string) (*notifyJob, error) {
	j := &notifyJob{OrgID: org, ID: id, LeaseID: lease}
	err := s.DB.WithOrg(ctx, org, func(tx *db.Tx) error {
		var payload db.JSON[map[string]any]
		var cfg db.JSON[map[string]string]
		var age float64
		err := tx.QueryRow(`SELECT n.kind, n.payload, n.attempts, coalesce(n.last_error, ''), n.incident_id, n.target_id, n.channel_id,
				extract(epoch FROM now() - n.created_at)::float8, coalesce(i.status, ''),
				coalesce(t.type, c.type), coalesce(t.config, '{}'), coalesce(t.credential, c.credential)
			FROM notifications n
			LEFT JOIN escalation_targets t ON t.id = n.target_id
			LEFT JOIN approval_channels c ON c.id = n.channel_id
			LEFT JOIN incidents i ON i.id = n.incident_id
			WHERE n.id = $1 AND n.lease_id = $2 AND n.lease_until > now() + $3::interval`, id, lease,
			pgInterval(notifyRequestTimeout+5*time.Second)).
			Scan(&j.Kind, &payload, &j.Attempts, &j.LastError, &j.IncidentID, &j.TargetID, &j.ChannelID,
				&age, &j.IncidentStatus, &j.Type, &cfg, &j.Credential)
		j.Payload, j.Config, j.Age = payload.V, cfg.V, time.Duration(age*float64(time.Second))
		return err
	})
	if isNoRows(err) {
		return nil, nil
	}
	return j, err
}

func (s *Server) attemptNotification(ctx context.Context, j *notifyJob) *deliveryError {
	if j.Kind == "page" && j.IncidentStatus == "resolved" && (j.Attempts >= maxNotifyAttempts || j.Age >= pageResolvedGrace) {
		// See recordFailure: past the short retry window, a page for an
		// incident that's over would only wake someone for nothing.
		return &deliveryError{msg: withLastError("stopped retrying: the incident was resolved before the page was delivered", j.LastError),
			permanent: true}
	}
	secret, err := s.Sealer.Open(j.Credential, j.OrgID)
	if err != nil {
		// It won't unseal next time either.
		return &deliveryError{msg: "escalation target credential could not be decrypted", detail: err, permanent: true}
	}
	return s.send(ctx, j.Type, j.Kind, string(secret), j.Config, j.Payload)
}

func withLastError(msg, last string) string {
	if last == "" {
		return msg
	}
	return msg + " (last error: " + last + ")"
}

var errLeaseLost = errors.New("notification lease lost")

// recordNotification stores a delivery result. It never fails the loop: if
// the result can't be written, it falls back to recording a bare failure,
// and failing that the lease expires and the row is retried.
func (s *Server) recordNotification(ctx context.Context, j *notifyJob, derr *deliveryError) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyRecordTimeout)
	defer cancel()
	if derr != nil {
		s.Log.Warn("notification delivery failed", "notification", j.ID, "org", j.OrgID, "type", j.Type, "kind", j.Kind,
			"attempt", j.Attempts+1, "err", derr.msg, "detail", derr.detail)
	}
	err := s.DB.WithOrg(ctx, j.OrgID, func(tx *db.Tx) error {
		if derr == nil {
			res, err := tx.Exec(`UPDATE notifications SET status = 'sent', sent_at = now(), attempts = attempts + 1,
				last_error = NULL, lease_until = NULL, lease_id = NULL WHERE id = $1 AND lease_id = $2`, j.ID, j.LeaseID)
			return leaseHeld(res, err)
		}
		return s.recordFailure(tx, j, derr)
	})
	switch {
	case err == nil:
	case errors.Is(err, errLeaseLost):
		s.Log.Warn("notification lease expired before its result was recorded", "notification", j.ID, "org", j.OrgID)
	default:
		s.Log.Error("notification result could not be recorded", "notification", j.ID, "org", j.OrgID, "err", err)
		msg := "delivery result could not be recorded"
		if derr != nil {
			msg = derr.msg
		}
		s.recordBareFailure(ctx, j.OrgID, j.ID, j.LeaseID, msg)
	}
}

func (s *Server) recordFailure(tx *db.Tx, j *notifyJob, derr *deliveryError) error {
	attempts := j.Attempts
	if !derr.throttled {
		attempts++
	}
	msg := derr.msg
	failed := derr.permanent
	switch {
	case failed:
	case j.Age >= notifyMaxAge:
		failed, msg = true, "gave up after 24 hours: "+msg
	case j.Kind != "page" && j.Kind != "resolve":
		failed = attempts >= maxNotifyAttempts
	case j.Kind == "page" && (attempts >= maxNotifyAttempts || j.Age >= pageResolvedGrace) && j.IncidentID.Valid:
		// Pages retry until delivered (or notifyMaxAge), but once a page
		// has failed for longer than the short retry window (8 attempts,
		// about 8 minutes) and its incident has been resolved, it stops:
		// on-call shouldn't be woken for an incident that's over. Within
		// that window a late page is still delivered, followed by its
		// resolve, so the upstream record of a brief outage is complete.
		var st string
		if err := tx.QueryRow(`SELECT status FROM incidents WHERE id = $1`, j.IncidentID.String).Scan(&st); err != nil && !isNoRows(err) {
			return err
		}
		if st == "resolved" {
			failed, msg = true, withLastError("stopped retrying: the incident was resolved before the page was delivered", msg)
		}
	}
	msg = cleanNotifyError(msg)
	status, delay := "pending", time.Duration(0)
	if failed {
		status = "failed"
	} else {
		delay = notifyRetryDelay(j.Kind, attempts, derr)
	}
	res, err := tx.Exec(`UPDATE notifications SET status = $3, attempts = $4, last_error = $5,
		next_attempt_at = now() + $6::interval, lease_until = NULL, lease_id = NULL
		WHERE id = $1 AND lease_id = $2`, j.ID, j.LeaseID, status, attempts, msg, pgInterval(delay))
	if err := leaseHeld(res, err); err != nil {
		return err
	}
	if !failed {
		// Notifications queued behind this one for the same destination
		// can't go before it, so move them back too; otherwise every claim
		// re-checks the whole blocked backlog.
		q := `UPDATE notifications p SET next_attempt_at = greatest(p.next_attempt_at, h.next_attempt_at)
			FROM notifications h
			WHERE h.org_id = $2 AND h.id = $1 AND p.org_id = h.org_id AND p.status = 'pending'
			  AND p.incident_id = h.incident_id AND p.target_id = h.target_id AND (p.created_at, p.id) > (h.created_at, h.id)`
		if !j.TargetID.Valid {
			q = `UPDATE notifications p SET next_attempt_at = greatest(p.next_attempt_at, h.next_attempt_at)
			FROM notifications h
			WHERE h.org_id = $2 AND h.id = $1 AND p.org_id = h.org_id AND p.status = 'pending'
			  AND p.channel_id = h.channel_id AND (p.created_at, p.id) > (h.created_at, h.id)`
		}
		_, err := tx.Exec(q, j.ID, j.OrgID)
		return err
	}
	s.Log.Error("notification abandoned", "notification", j.ID, "org", j.OrgID, "type", j.Type, "kind", j.Kind,
		"incident", j.IncidentID.String, "channel", j.ChannelID.String, "attempts", attempts, "reason", msg)
	if j.IncidentID.Valid {
		// The status update above must stick even if the timeline entry
		// can't be written.
		if _, err := tx.Exec(`SAVEPOINT notify_timeline`); err != nil {
			return err
		}
		if err := s.timeline(tx, j.IncidentID.String, "notification.failed", "system", "",
			fmt.Sprintf("Could not deliver %s to %s after %d attempts: %s", j.Kind, notifyServiceName(j.Type), attempts, msg), nil); err != nil {
			s.Log.Error("notification failure could not be added to the timeline", "notification", j.ID, "err", err)
			if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT notify_timeline`); err != nil {
				return err
			}
		}
	}
	return nil
}

func leaseHeld(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errLeaseLost
	}
	return nil
}

// recordBareFailure is the fallback when a notification can't be loaded or
// its result can't be recorded normally: count an attempt with backoff, so
// the row neither blocks the queue nor retries hot.
func (s *Server) recordBareFailure(ctx context.Context, org, id, lease, msg string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyRecordTimeout)
	defer cancel()
	err := s.DB.WithOrg(ctx, org, func(tx *db.Tx) error {
		res, err := tx.Exec(`UPDATE notifications SET attempts = attempts + 1, last_error = $3,
			status = CASE WHEN created_at < now() - interval '24 hours'
			                OR (kind NOT IN ('page','resolve') AND attempts + 1 >= $4) THEN 'failed' ELSE 'pending' END,
			next_attempt_at = now() + least(interval '1 second' * power(2, least(attempts + 1, 9)), interval '5 minutes'),
			lease_until = NULL, lease_id = NULL
			WHERE id = $1 AND lease_id = $2`, id, lease, cleanNotifyError(msg), maxNotifyAttempts)
		return leaseHeld(res, err)
	})
	if err != nil && !errors.Is(err, errLeaseLost) {
		s.Log.Error("notification failure could not be recorded; retrying when its lease expires", "notification", id, "org", org, "err", err)
	}
}

// releaseNotification gives a claimed notification back untried.
func (s *Server) releaseNotification(ctx context.Context, org, id, lease string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	s.DB.WithOrg(ctx, org, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE notifications SET lease_until = NULL, lease_id = NULL WHERE id = $1 AND lease_id = $2`, id, lease)
		return err
	})
}

// notifyRetryDelay is the wait before the next attempt, with ±20% jitter.
// Pages and resolves back off to notifyMaxBackoff; other kinds have a
// bounded number of attempts. A 429 waits as long as Retry-After asks.
func notifyRetryDelay(kind string, attempts int, derr *deliveryError) time.Duration {
	if derr.throttled && derr.retryAfter > 0 {
		return derr.retryAfter + time.Duration(rand.Float64()*0.1*float64(derr.retryAfter))
	}
	var d time.Duration
	if kind == "page" || kind == "resolve" {
		d = min(time.Duration(1<<min(attempts, 9))*time.Second, notifyMaxBackoff)
	} else {
		d = time.Duration(1<<min(attempts, 6)) * time.Second
	}
	if derr.throttled {
		d = max(d, 10*time.Second)
	}
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// parseRetryAfter reads the delay-seconds form of Retry-After.
func parseRetryAfter(h string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || n <= 0 {
		return 0
	}
	return min(time.Duration(n)*time.Second, maxRetryAfter)
}

func notifyServiceName(typ string) string {
	switch typ {
	case "slack":
		return "Slack"
	case "pagerduty":
		return "PagerDuty"
	}
	return "the endpoint"
}

var errTargetNotAllowed = &deliveryError{msg: "target URL is not allowed; recreate the escalation target or approval channel", permanent: true}

func (s *Server) send(ctx context.Context, typ, kind, secret string, cfg map[string]string, p map[string]any) *deliveryError {
	switch typ {
	case "slack":
		// Also checked at creation; rows from before that check get it here.
		if validateNotifyURL("slack", secret, s.Cfg.AllowPrivateTargets) != nil {
			return errTargetNotAllowed
		}
		if kind == "approval" {
			return s.postNotification(ctx, "Slack", secret, slackApprovalMessage(p))
		}
		return s.postNotification(ctx, "Slack", secret, map[string]any{"text": slackText(kind, p)})
	case "pagerduty":
		url := cfg["events_url"]
		if url == "" {
			url = PagerDutyEventsURL
		}
		if validateNotifyURL("pagerduty", url, s.Cfg.AllowPrivateTargets) != nil {
			return errTargetNotAllowed
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
		return s.postNotification(ctx, "PagerDuty", url, ev)
	}
	return &deliveryError{msg: "unknown target type", permanent: true}
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

// postNotification sends one notification with the tenant-URL client. The
// URL is never logged or returned: a Slack webhook URL is itself the
// credential.
func (s *Server) postNotification(ctx context.Context, service, url string, body any) *deliveryError {
	b, err := json.Marshal(body)
	if err != nil {
		return &deliveryError{msg: "message could not be encoded", detail: err, permanent: true}
	}
	ctx, cancel := context.WithTimeout(ctx, notifyRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return &deliveryError{msg: "invalid target URL", permanent: true} // err quotes the URL
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Cfg.NotifyHTTPClient.Do(req)
	if err != nil {
		// Dial errors and HTTP statuses of arbitrary hosts would make the
		// timeline a port scanner, so the stored reason stays generic.
		detail := err
		var ue *neturl.Error
		if errors.As(err, &ue) {
			detail = ue.Err
		}
		return &deliveryError{msg: "could not connect to " + service, detail: detail}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return &deliveryError{msg: service + " rate limited the request (HTTP 429)", throttled: true,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		return &deliveryError{msg: fmt.Sprintf("%s returned HTTP %d", service, resp.StatusCode)}
	}
}

// postJSON posts to a fixed, prefix-checked host (Slack interaction
// replies) with Cfg.HTTPClient.
func (s *Server) postJSON(ctx context.Context, url string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return errTargetURL // err quotes the URL
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Cfg.HTTPClient.Do(req)
	if err != nil {
		// Never log the URL: a Slack response_url is itself a credential.
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
