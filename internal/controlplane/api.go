package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// APIHandler serves the REST API under /v1.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	var route routeFn = func(pattern, minRole string, fn func(r *http.Request, p principal) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, err := s.authenticate(r)
			if err != nil {
				var ae authError
				if errors.As(err, &ae) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": ae.Error()})
				} else {
					s.reply(w, nil, err) // httpError keeps its status; anything else is a logged 500
				}
				return
			}
			// Don't reassign minRole: it's shared by every request on this route.
			need, check := minRole, p.atLeast
			if r, ok := strings.CutSuffix(minRole, "*"); ok {
				need, check = r, p.atLeastSomewhere // resource-scoped; the handler calls p.can
			}
			if err := check(need); err != nil {
				s.reply(w, nil, err)
				return
			}
			if key := r.Header.Get(idempotencyHeader); key != "" && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
				s.withIdempotency(w, r, p, key, func(w http.ResponseWriter) {
					v, err := fn(r, p)
					s.reply(w, v, err)
				})
				return
			}
			v, err := fn(r, p)
			s.reply(w, v, err)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", s.readyz)
	// The agent gateway's CA certificate (public). Fetched over the API's
	// publicly trusted TLS, so installing an agent needs no file copying.
	mux.HandleFunc("GET /v1/agent-ca.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.CA.CertPEM)
	})
	route("GET /v1/me", "viewer", func(_ *http.Request, p principal) (any, error) {
		out := map[string]any{"org": ids.Encode("org", p.OrgID), "principal": p.actor(), "kind": p.Kind, "bindings": p.Bindings}
		if p.Kind == "user" {
			out["email"], out["teams"] = p.Email, p.Teams
		}
		return out, nil
	})
	s.identityRoutes(route)
	route("POST /v1/services", "admin", s.apiCreateService)
	route("GET /v1/services", "viewer", s.apiListServices)
	route("POST /v1/services/{name}/escalation-targets", "admin", s.apiCreateTarget)
	route("POST /v1/integrations", "admin", s.apiCreateIntegration)
	route("GET /v1/integrations", "admin", s.apiListIntegrations)
	route("GET /v1/alert-events/failed", "admin", s.apiFailedAlertEvents)
	route("PUT /v1/integrations/{id}/topic", "admin", s.apiSetIntegrationTopic)
	route("PUT /v1/routing-rules", "admin", s.apiPutRoutingRules)
	route("POST /v1/enrollment-rules", "admin", s.apiCreateEnrollmentRule)
	route("GET /v1/enrollment-rules", "admin", s.apiListEnrollmentRules)
	route("POST /v1/enrollment-rules/{id}/revoke", "admin", s.apiRevokeEnrollmentRule)
	route("GET /v1/agents", "viewer", s.apiListAgents)
	route("POST /v1/agents/{id}/revoke", "admin", s.apiRevokeAgent)
	route("GET /v1/signing-keys", "viewer", s.apiSigningKeys)
	route("POST /v1/runbooks/validate", "responder*", s.apiValidateRunbook)
	route("PUT /v1/runbooks/{name}", "responder*", s.apiPublishRunbook)
	route("GET /v1/runbooks/{name}", "viewer", s.apiGetRunbook)
	route("POST /v1/runs", "responder*", s.apiStartRun)
	s.approvalRoutes(route)
	s.slackRoutes(route, mux)
	route("GET /v1/runs/{id}", "viewer", s.apiGetRun)
	route("GET /v1/runs/{id}/steps/{step}/attempts/{n}/output", "viewer", s.apiAttemptOutput)
	route("GET /v1/incidents", "viewer", s.apiListIncidents)
	route("GET /v1/incidents/{number}", "viewer", s.apiGetIncident)
	route("GET /v1/incidents/{number}/timeline", "viewer", s.apiTimeline)
	route("POST /v1/incidents/{number}/acknowledge", "responder*", s.apiAck)
	route("POST /v1/incidents/{number}/resolve", "responder*", s.apiResolve)
	route("POST /v1/org/freeze", "admin", func(r *http.Request, p principal) (any, error) { return s.setFrozen(r.Context(), p, true) })
	route("POST /v1/org/unfreeze", "admin", func(r *http.Request, p principal) (any, error) { return s.setFrozen(r.Context(), p, false) })
	route("GET /v1/audit-events", "admin", s.apiAudit)
	return mux
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return httpError{http.StatusBadRequest, "invalid JSON body: " + err.Error()}
	}
	return nil
}

func parseDur(field, v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, httpError{http.StatusBadRequest, field + " must be a positive duration like 10m"}
	}
	return d, nil
}

var serviceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ---------------------------------------------------------------------------
// Services, targets, integrations, routing, enrollment
// ---------------------------------------------------------------------------

func (s *Server) apiCreateService(r *http.Request, p principal) (any, error) {
	var req struct {
		Name               string   `json:"name"`
		Team               string   `json:"team"`
		GroupingLabels     []string `json:"grouping_labels"`
		GroupingWindow     string   `json:"grouping_window"`
		MaxHold            string   `json:"max_hold"`
		VerificationWindow string   `json:"verification_window"`
		ReopenWindow       string   `json:"reopen_window"`
		AutoResolve        *bool    `json:"auto_resolve"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if !serviceNameRe.MatchString(req.Name) {
		return nil, httpError{400, "name must match " + serviceNameRe.String()}
	}
	gw, err := parseDur("grouping_window", req.GroupingWindow, 2*time.Hour)
	if err != nil {
		return nil, err
	}
	mh, err := parseDur("max_hold", req.MaxHold, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if mh > 30*time.Minute {
		return nil, httpError{400, "max_hold cannot exceed 30m"}
	}
	vw, err := parseDur("verification_window", req.VerificationWindow, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	rw, err := parseDur("reopen_window", req.ReopenWindow, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	auto := true
	if req.AutoResolve != nil {
		auto = *req.AutoResolve
	}
	id := ids.NewString()
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`INSERT INTO services (id, org_id, name, team, grouping_labels, grouping_window, max_hold,
				verification_window, reopen_window, auto_resolve)
			VALUES ($1,$2,$3,NULLIF($4,''),$5,$6::interval,$7::interval,$8::interval,$9::interval,$10)`,
			id, p.OrgID, req.Name, req.Team, stringArray(req.GroupingLabels), pgInterval(gw), pgInterval(mh),
			pgInterval(vw), pgInterval(rw), auto); err != nil {
			if db.IsUniqueViolation(err) {
				return httpError{409, "service " + req.Name + " already exists"}
			}
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "service.create", "service", id, req)
	})
	return map[string]string{"id": ids.Encode("svc", id), "name": req.Name}, err
}

func (s *Server) apiListServices(r *http.Request, p principal) (any, error) {
	var out []map[string]any
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT ` + serviceCols + ` FROM services WHERE archived_at IS NULL ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			svc, err := scanService(rows)
			if err != nil {
				return err
			}
			out = append(out, map[string]any{"id": ids.Encode("svc", svc.ID), "name": svc.Name,
				"max_hold": svc.MaxHold.String(), "verification_window": svc.Verification.String()})
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) serviceIDByName(tx *db.Tx, name string) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT id FROM services WHERE name = $1 AND archived_at IS NULL`, name).Scan(&id)
	if isNoRows(err) {
		return "", httpError{404, "no service named " + name}
	}
	return id, err
}

func (s *Server) apiCreateTarget(r *http.Request, p principal) (any, error) {
	var req struct {
		Type       string `json:"type"`
		URL        string `json:"url"`         // slack webhook URL
		RoutingKey string `json:"routing_key"` // pagerduty
		EventsURL  string `json:"events_url"`  // pagerduty endpoint override (testing)
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var secret string
	cfg := map[string]string{}
	switch req.Type {
	case "slack":
		if validateNotifyURL("slack", req.URL, s.Cfg.AllowPrivateTargets) != nil {
			return nil, httpError{400, "url must be a Slack incoming-webhook URL (https://hooks.slack.com/...)"}
		}
		secret = req.URL
	case "pagerduty":
		if req.RoutingKey == "" {
			return nil, httpError{400, "routing_key is required"}
		}
		secret = req.RoutingKey
		if req.EventsURL != "" {
			if validateNotifyURL("pagerduty", req.EventsURL, s.Cfg.AllowPrivateTargets) != nil {
				return nil, httpError{400, "events_url must be https://events.pagerduty.com/... or https://events.eu.pagerduty.com/... (or omitted)"}
			}
			cfg["events_url"] = req.EventsURL
		}
	default:
		return nil, httpError{400, "type must be slack or pagerduty"}
	}
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		svc, err := s.serviceIDByName(tx, r.PathValue("name"))
		if err != nil {
			return err
		}
		sealed, err := s.Sealer.Seal([]byte(secret), p.OrgID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO escalation_targets (id, org_id, service_id, type, config, credential) VALUES ($1,$2,$3,$4,$5,$6)`,
			id, p.OrgID, svc, req.Type, db.JSON[map[string]string]{V: cfg}, sealed); err != nil {
			return err
		}
		// The credential itself is never logged or returned.
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "escalation_target.create", "escalation_target", id,
			map[string]string{"type": req.Type, "service": r.PathValue("name")})
	})
	return map[string]string{"id": ids.Encode("tgt", id), "type": req.Type}, err
}

// apiSetIntegrationTopic pins the SNS topic of an existing CloudWatch
// integration. Ingest refuses SNS messages when no topic is pinned, so
// integrations created before topic_arn was required need this to work.
func (s *Server) apiSetIntegrationTopic(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("int", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	var req struct {
		TopicArn string `json:"topic_arn"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if !snsTopicArnRe.MatchString(req.TopicArn) {
		return nil, httpError{400, "topic_arn must be an SNS topic ARN (arn:aws:sns:<region>:<account>:<topic>)"}
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var typ string
		if err := tx.QueryRow(`SELECT type FROM integrations WHERE id = $1 FOR UPDATE`, id).Scan(&typ); err != nil {
			return err
		}
		if typ != "cloudwatch" {
			return httpError{400, "only cloudwatch integrations have an SNS topic"}
		}
		if _, err := tx.Exec(`UPDATE integrations SET config = config || jsonb_build_object('topic_arn', $2::text) WHERE id = $1`,
			id, req.TopicArn); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "integration.topic_set", "integration", id,
			map[string]string{"topic_arn": req.TopicArn})
	})
	return map[string]string{"id": ids.Encode("int", id), "topic_arn": req.TopicArn}, err
}

func (s *Server) apiCreateIntegration(r *http.Request, p principal) (any, error) {
	var req struct {
		Type           string            `json:"type"`
		Name           string            `json:"name"`
		DefaultService string            `json:"default_service"`
		TopicArn       string            `json:"topic_arn"`
		SeverityMap    map[string]string `json:"severity_map"`
		DedupeKeys     []string          `json:"dedupe_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Type != "cloudwatch" && req.Type != "webhook" {
		return nil, httpError{400, "type must be cloudwatch or webhook"}
	}
	// Without a pinned topic, any AWS account could subscribe this URL to its
	// own topic and publish validly signed, forged alarms.
	if req.Type == "cloudwatch" && !snsTopicArnRe.MatchString(req.TopicArn) {
		return nil, httpError{400, "topic_arn is required for cloudwatch integrations (arn:aws:sns:<region>:<account>:<topic>)"}
	}
	for k, v := range req.SeverityMap {
		if !validSeverity[v] {
			return nil, httpError{400, "severity_map." + k + " must be critical, high, warning or info"}
		}
	}
	if req.SeverityMap == nil {
		req.SeverityMap = map[string]string{"ALARM": "high"}
	}
	if len(req.DedupeKeys) == 0 {
		req.DedupeKeys = []string{"alertname", "service", "instance"}
	}
	id := ids.NewString()
	var secret string
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		svcName := req.DefaultService
		if svcName == "" {
			svcName = "catch-all"
		}
		svc, err := s.serviceIDByName(tx, svcName)
		if err != nil {
			return err
		}
		var sealed []byte
		if req.Type == "webhook" {
			secret, _, _ = newSecret("whsec")
			if sealed, err = s.Sealer.Seal([]byte(secret), p.OrgID); err != nil {
				return err
			}
		}
		cfg := map[string]string{}
		if req.TopicArn != "" {
			cfg["topic_arn"] = req.TopicArn
		}
		if _, err := tx.Exec(`INSERT INTO integrations (id, org_id, type, name, default_service_id, severity_map, dedupe_keys, config, credential)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, p.OrgID, req.Type, req.Name, svc,
			db.JSON[map[string]string]{V: req.SeverityMap}, stringArray(req.DedupeKeys), db.JSON[map[string]string]{V: cfg}, sealed); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "integration.create", "integration", id,
			map[string]string{"type": req.Type, "name": req.Name, "default_service": svcName})
	})
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		"id":         ids.Encode("int", id),
		"ingest_url": strings.TrimSuffix(s.Cfg.PublicIngestURL, "/") + "/v1/i/" + ids.Encode("int", id),
	}
	if secret != "" {
		out["signing_secret"] = secret // shown once
	}
	return out, nil
}

// apiListIntegrations shows each integration's ingest URL and, for
// CloudWatch, its pinned topic and the last topic it refused: a CloudWatch
// integration with no pinned topic (one created before pinning was
// required) accepts nothing, and SNS doesn't tell anyone.
func (s *Server) apiListIntegrations(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT i.id, i.type, i.name, s.name, i.config, i.created_at FROM integrations i
			JOIN services s ON s.id = i.default_service_id WHERE i.archived_at IS NULL ORDER BY i.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, typ, name, svc string
			var cfg db.JSON[map[string]string]
			var created time.Time
			if err := rows.Scan(&id, &typ, &name, &svc, &cfg, &created); err != nil {
				return err
			}
			it := map[string]any{"id": ids.Encode("int", id), "type": typ, "name": name, "default_service": svc,
				"ingest_url": strings.TrimSuffix(s.Cfg.PublicIngestURL, "/") + "/v1/i/" + ids.Encode("int", id),
				"created_at": created}
			if typ == "cloudwatch" {
				it["topic_arn"] = cfg.V["topic_arn"]
				if cfg.V["topic_arn"] == "" {
					it["problem"] = "no SNS topic is pinned, so every delivery is refused; set it with PUT /v1/integrations/{id}/topic"
				}
				if t := cfg.V["last_rejected_topic"]; t != "" && t != cfg.V["topic_arn"] {
					it["last_rejected_topic"] = t
					it["last_rejected_at"] = cfg.V["last_rejected_at"]
				}
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

// apiFailedAlertEvents lists the last week's events that were received but
// could not be processed (malformed, or an error that retrying wouldn't fix).
// They are stored with their error rather than retried, since a stuck event
// would hold up the org's later alerts; this is where they show.
func (s *Server) apiFailedAlertEvents(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT e.id, e.received_at, e.integration_id, COALESCE(i.name, ''), e.error FROM alert_events e
			LEFT JOIN integrations i ON i.id = e.integration_id
			WHERE e.received_at > now() - interval '7 days' AND e.error IS NOT NULL
			ORDER BY e.received_at DESC LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, integ, name, msg string
			var at time.Time
			if err := rows.Scan(&id, &at, &integ, &name, &msg); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": ids.Encode("evt", id), "received_at": at,
				"integration": ids.Encode("int", integ), "integration_name": name, "error": msg})
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) apiPutRoutingRules(r *http.Request, p principal) (any, error) {
	var req []struct {
		Match   string `json:"match"`
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`DELETE FROM routing_rules`); err != nil {
			return err
		}
		for i, rule := range req {
			if err := expr.Check(rule.Match); err != nil {
				return httpError{400, fmt.Sprintf("rule %d: %v", i, err)}
			}
			action := rule.Action
			if action == "" {
				action = "route"
			}
			var svc sql.NullString
			if action == "route" {
				id, err := s.serviceIDByName(tx, rule.Service)
				if err != nil {
					return err
				}
				svc = sql.NullString{String: id, Valid: true}
			} else if action != "suppress" {
				return httpError{400, fmt.Sprintf("rule %d: action must be route or suppress", i)}
			}
			if _, err := tx.Exec(`INSERT INTO routing_rules (id, org_id, priority, match, action, service_id) VALUES ($1,$2,$3,$4,$5,$6)`,
				ids.NewString(), p.OrgID, i, rule.Match, action, svc); err != nil {
				return err
			}
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "routing_rules.replace", "routing_rules", "org", req)
	})
	return map[string]int{"rules": len(req)}, err
}

// maxEnrollTokenLife caps how long an enrollment token stays usable.
const maxEnrollTokenLife = 7 * 24 * time.Hour

func (s *Server) apiCreateEnrollmentRule(r *http.Request, p principal) (any, error) {
	var req struct {
		Method       string            `json:"method"` // iam (default) | token
		RoleArn      string            `json:"role_arn"`
		AWSAccountID string            `json:"aws_account_id"`
		RoleName     string            `json:"role_name"`
		Labels       map[string]string `json:"labels"`
		MaxAgents    int               `json:"max_agents"`
		ExpiresIn    string            `json:"expires_in"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if len(req.Labels) == 0 {
		return nil, httpError{400, "labels are required (agents get their labels from the rule, never from themselves)"}
	}
	if req.MaxAgents <= 0 {
		req.MaxAgents = 2
	}
	if req.Method == "" {
		req.Method = "iam"
	}
	id := ids.NewString()
	out := map[string]string{"id": ids.Encode("enr", id), "method": req.Method, "org": ids.Encode("org", p.OrgID)}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		switch req.Method {
		case "iam":
			account, name := req.AWSAccountID, req.RoleName
			if req.RoleArn != "" {
				a, n, err := roleNameFromARN(req.RoleArn)
				if err != nil {
					return httpError{400, err.Error()}
				}
				account, name = a, n
			}
			if !regexp.MustCompile(`^\d{12}$`).MatchString(account) || name == "" {
				return httpError{400, "iam rules need role_arn (arn:aws:iam::<12-digit account>:role/<name>), or aws_account_id and role_name"}
			}
			var exp sql.NullString
			if req.ExpiresIn != "" {
				d, err := parseDur("expires_in", req.ExpiresIn, 0)
				if err != nil {
					return err
				}
				exp = sql.NullString{String: pgInterval(d), Valid: true}
			}
			if _, err := tx.Exec(`INSERT INTO enrollment_rules (id, org_id, method, aws_account_id, role_name, labels, max_agents, expires_at)
				VALUES ($1,$2,'iam',$3,$4,$5,$6, now() + $7::interval)`,
				id, p.OrgID, account, name, db.JSON[map[string]string]{V: req.Labels}, req.MaxAgents, exp); err != nil {
				return err
			}
			out["aws_account_id"], out["role_name"] = account, name
			return tx.Audit(r.Context(), p.actorType(), p.actor(), "enrollment_rule.create", "enrollment_rule", id,
				map[string]any{"labels": req.Labels, "max_agents": req.MaxAgents, "method": "iam", "account": account, "role": name})
		case "token":
			exp, err := parseDur("expires_in", req.ExpiresIn, time.Hour)
			if err != nil {
				return err
			}
			// A token is a bearer secret that works from anywhere; keep its
			// window short. IAM enrollment is the long-lived option.
			if exp > maxEnrollTokenLife {
				return httpError{400, "expires_in for token rules can be at most " + maxEnrollTokenLife.String()}
			}
			token, _, hash := newSecret("nfxenroll")
			if _, err := tx.Exec(`INSERT INTO enrollment_rules (id, org_id, method, token_hash, labels, max_agents, expires_at)
				VALUES ($1,$2,'token',$3,$4,$5, now() + $6::interval)`,
				id, p.OrgID, hash, db.JSON[map[string]string]{V: req.Labels}, req.MaxAgents, pgInterval(exp)); err != nil {
				return err
			}
			out["token"] = token
			out["note"] = "token shown once; expires in " + exp.String()
			return tx.Audit(r.Context(), p.actorType(), p.actor(), "enrollment_rule.create", "enrollment_rule", id,
				map[string]any{"labels": req.Labels, "max_agents": req.MaxAgents, "method": "token"})
		default:
			return httpError{400, "method must be iam or token"}
		}
	})
	return out, err
}

func (s *Server) apiListEnrollmentRules(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT e.id, e.method, COALESCE(e.aws_account_id, ''), COALESCE(e.role_name, ''), e.labels,
				e.max_agents, e.expires_at, e.created_at,
				(SELECT count(*) FROM agents a WHERE a.enrollment_rule_id = e.id AND a.revoked_at IS NULL)
			FROM enrollment_rules e WHERE e.revoked_at IS NULL ORDER BY e.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, method, account, role string
			var labels db.JSON[map[string]string]
			var maxAgents, agents int
			var expires sql.NullTime
			var created time.Time
			if err := rows.Scan(&id, &method, &account, &role, &labels, &maxAgents, &expires, &created, &agents); err != nil {
				return err
			}
			e := map[string]any{"id": ids.Encode("enr", id), "method": method, "labels": labels.V, "max_agents": maxAgents,
				"agents": agents, "created_at": created}
			if method == "iam" {
				e["aws_account_id"], e["role_name"] = account, role
			}
			if expires.Valid {
				e["expires_at"] = expires.Time
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// apiRevokeEnrollmentRule stops a rule enrolling agents and renewing their
// certificates, so its agents lapse when their current certificate expires.
// With {"revoke_agents": true} they are cut off at once (a leaked token: the
// agents it enrolled can't be told apart from a rogue one).
func (s *Server) apiRevokeEnrollmentRule(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("enr", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	var req struct {
		RevokeAgents bool `json:"revoke_agents"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			return nil, err
		}
	}
	var n int64
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		res, err := tx.Exec(`UPDATE enrollment_rules SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return httpError{404, "no active enrollment rule with that id"}
		}
		if req.RevokeAgents {
			res, err := tx.Exec(`UPDATE agents SET revoked_at = now(), status = 'revoked' WHERE enrollment_rule_id = $1 AND revoked_at IS NULL`, id)
			if err != nil {
				return err
			}
			n, _ = res.RowsAffected()
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "enrollment_rule.revoke", "enrollment_rule", id,
			map[string]any{"revoked_agents": n})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": ids.Encode("enr", id), "revoked": true, "revoked_agents": n}, nil
}

// apiRevokeAgent cuts an agent off: its certificate stops authenticating at
// once, and work leased to it is recovered when the lease expires.
func (s *Server) apiRevokeAgent(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("agt", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		res, err := tx.Exec(`UPDATE agents SET revoked_at = now(), status = 'revoked' WHERE id = $1 AND revoked_at IS NULL`, id)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return httpError{404, "no active agent with that id"}
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "agent.revoke", "agent", id, nil)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": ids.Encode("agt", id), "revoked": true}, nil
}

func (s *Server) apiListAgents(r *http.Request, p principal) (any, error) {
	var out []map[string]any
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT id, labels, status, COALESCE(version,''), last_seen_at, frozen_local FROM agents
			WHERE revoked_at IS NULL ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, status, version string
			var labels db.JSON[map[string]string]
			var seen sql.NullTime
			var frozen bool
			if err := rows.Scan(&id, &labels, &status, &version, &seen, &frozen); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": ids.Encode("agt", id), "labels": labels.V, "status": status,
				"version": version, "last_seen_at": seen.Time, "frozen_local": frozen})
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Runbooks
// ---------------------------------------------------------------------------

func readRunbook(r *http.Request) (*runbook.Runbook, []byte, error) {
	const maxRunbook = 512 << 10
	src, err := io.ReadAll(io.LimitReader(r.Body, maxRunbook+1))
	if err != nil {
		return nil, nil, err
	}
	// Refuse rather than cut: a truncated runbook can still parse and lint,
	// and would then be signed and executed missing its last lines.
	if len(src) > maxRunbook {
		return nil, nil, httpError{http.StatusRequestEntityTooLarge, "runbook exceeds 512 KiB"}
	}
	rb, err := runbook.Parse(src)
	if err != nil {
		return nil, nil, httpError{400, err.Error()}
	}
	return rb, src, nil
}

// lintWithOrg adds checks that need the database: every service an auto
// trigger names must exist.
func (s *Server) lintWithOrg(tx *db.Tx, rb *runbook.Runbook) runbook.Issues {
	is := runbook.Lint(rb)
	for i, t := range rb.Spec.Triggers {
		for _, name := range t.Services {
			var ok bool
			tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM services WHERE name = $1 AND archived_at IS NULL)`, name).Scan(&ok)
			if !ok {
				is = append(is, runbook.Issue{Path: fmt.Sprintf("spec.triggers[%d].services", i), Message: "no service named " + name})
			}
		}
	}
	return is
}

func (s *Server) apiValidateRunbook(r *http.Request, p principal) (any, error) {
	rb, _, err := readRunbook(r)
	if err != nil {
		return map[string]any{"valid": false, "issues": []runbook.Issue{{Path: "", Message: err.Error()}}}, nil
	}
	var is runbook.Issues
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error { is = s.lintWithOrg(tx, rb); return nil })
	_, digest, _ := runbook.Canonical(rb)
	return map[string]any{"valid": len(is) == 0, "issues": is, "digest": digest}, err
}

// apiPublishRunbook validates, canonicalizes, signs and stores a new
// immutable version. Publishing identical content is a no-op.
func (s *Server) apiPublishRunbook(r *http.Request, p principal) (any, error) {
	rb, src, err := readRunbook(r)
	if err != nil {
		return nil, err
	}
	if rb.Metadata.Name != r.PathValue("name") {
		return nil, httpError{400, "metadata.name must match the URL"}
	}
	canon, digest, err := runbook.Canonical(rb)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if is := s.lintWithOrg(tx, rb); len(is) > 0 {
			b, _ := json.Marshal(is)
			return httpError{422, "runbook is not publishable: " + string(b)}
		}
		// The publisher must be allowed on the new content...
		if err := p.can("responder", runbookResource(rb.Metadata.Team, rb.Metadata.Tags, selector(rb))); err != nil {
			return err
		}
		// ...and on every service its triggers act on: an alert trigger
		// changes how that service's incidents page (beforePaging holds the
		// page), so it can't be attached to another team's service.
		for _, t := range rb.Spec.Triggers {
			for _, name := range t.Services {
				var team sql.NullString
				if err := tx.QueryRow(`SELECT team FROM services WHERE name = $1 AND archived_at IS NULL`, name).Scan(&team); err != nil {
					return err
				}
				if err := p.can("responder", resource{Kind: "service", Team: team.String}); err != nil {
					return httpError{403, "you can't attach triggers to service " + name}
				}
			}
		}
		var rbID string
		var latest int
		err := tx.QueryRow(`SELECT id, latest_version FROM runbooks WHERE name = $1 FOR UPDATE`, rb.Metadata.Name).Scan(&rbID, &latest)
		if err == nil && latest > 0 {
			// ...and on the version it replaces, so nobody can take over
			// another team's runbook by republishing it under their own scope.
			prev, _, _, err := s.loadVersion(tx, rbID, latest)
			if err != nil {
				return err
			}
			if err := p.can("responder", runbookResource(prev.Metadata.Team, prev.Metadata.Tags, selector(prev))); err != nil {
				return err
			}
		}
		if isNoRows(err) {
			rbID = ids.NewString()
			_, err = tx.Exec(`INSERT INTO runbooks (id, org_id, name, title, team, tags) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6)`,
				rbID, p.OrgID, rb.Metadata.Name, rb.Metadata.Title, rb.Metadata.Team, stringArray(rb.Metadata.Tags))
		}
		if err != nil {
			return err
		}
		if latest > 0 {
			var latestDigest string
			if err := tx.QueryRow(`SELECT digest FROM runbook_versions WHERE runbook_id = $1 AND version = $2`, rbID, latest).Scan(&latestDigest); err != nil {
				return err
			}
			if latestDigest == digest {
				out = map[string]any{"name": rb.Metadata.Name, "version": latest, "digest": digest, "unchanged": true}
				return nil
			}
		}
		version := latest + 1
		vid := ids.NewString()
		if _, err := tx.Exec(`INSERT INTO runbook_versions (id, org_id, runbook_id, version, digest, canonical_json, source_yaml, published_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, vid, p.OrgID, rbID, version, digest, string(canon), string(src), p.actor()); err != nil {
			return err
		}
		key, err := s.signingKey(tx)
		if err != nil {
			return err
		}
		sig := signing.SignDigest(key, digest)
		raw, _ := decodeB64(sig.Signature)
		if _, err := tx.Exec(`INSERT INTO runbook_signatures (org_id, version_id, key_id, signature) VALUES ($1,$2,$3,$4)`,
			p.OrgID, vid, sig.KeyID, raw); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE runbooks SET latest_version = $2, title = $3, team = NULLIF($4,''), tags = $5 WHERE id = $1`,
			rbID, version, rb.Metadata.Title, rb.Metadata.Team, stringArray(rb.Metadata.Tags)); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM runbook_triggers WHERE runbook_id = $1`, rbID); err != nil {
			return err
		}
		for i, t := range rb.Spec.Triggers {
			var cooldown sql.NullString
			if t.Cooldown != "" {
				d, _ := time.ParseDuration(t.Cooldown)
				cooldown = sql.NullString{String: pgInterval(d), Valid: true}
			}
			var maxRuns sql.NullInt64
			if t.MaxRunsPerHour > 0 {
				maxRuns = sql.NullInt64{Int64: int64(t.MaxRunsPerHour), Valid: true}
			}
			if _, err := tx.Exec(`INSERT INTO runbook_triggers (org_id, runbook_id, version, idx, type, mode, match, services,
					before_paging, cooldown, max_runs_per_hour)
				VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10::interval,$11)`,
				p.OrgID, rbID, version, i, t.Type, t.Mode, t.Match, stringArray(t.Services), t.BeforePaging, cooldown, maxRuns); err != nil {
				return err
			}
		}
		out = map[string]any{"name": rb.Metadata.Name, "version": version, "digest": digest, "signed_by": []string{sig.KeyID}}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "runbook.publish", "runbook", rb.Metadata.Name,
			map[string]any{"version": version, "digest": digest})
	})
	return out, err
}

func (s *Server) apiGetRunbook(r *http.Request, p principal) (any, error) {
	var out map[string]any
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var title string
		var version int
		var digest, src string
		if err := tx.QueryRow(`SELECT r.title, r.latest_version, v.digest, v.source_yaml FROM runbooks r
			JOIN runbook_versions v ON v.runbook_id = r.id AND v.version = r.latest_version WHERE r.name = $1`,
			r.PathValue("name")).Scan(&title, &version, &digest, &src); err != nil {
			return err
		}
		out = map[string]any{"name": r.PathValue("name"), "title": title, "version": version, "digest": digest, "source_yaml": src}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

func (s *Server) apiStartRun(r *http.Request, p principal) (any, error) {
	var req struct {
		Runbook  string         `json:"runbook"`
		Version  int            `json:"version"`
		Params   map[string]any `json:"params"`
		Incident int64          `json:"incident"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var runID string
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		// The kill switch blocks manual runs too; otherwise a run requested
		// while frozen would queue and execute the moment someone unfreezes.
		var frozen sql.NullTime
		if err := tx.QueryRow(`SELECT frozen_at FROM orgs FOR SHARE`).Scan(&frozen); err != nil {
			return err
		}
		if frozen.Valid {
			return httpError{409, "the org is frozen (kill switch); unfreeze it before starting runs"}
		}
		var rbID string
		var latest int
		if err := tx.QueryRow(`SELECT id, latest_version FROM runbooks WHERE name = $1 AND archived_at IS NULL`, req.Runbook).Scan(&rbID, &latest); err != nil {
			if isNoRows(err) {
				return httpError{404, "no runbook named " + req.Runbook}
			}
			return err
		}
		v := req.Version
		if v == 0 {
			v = latest
		}
		rb, vid, digest, err := s.loadVersion(tx, rbID, v)
		if err != nil {
			return err
		}
		// The runbook's policy.allowedRoles decides who may start it by hand
		// (default: responders); scope still applies to whichever role is used.
		res := runbookResource(rb.Metadata.Team, rb.Metadata.Tags, selector(rb))
		var startErr error
		mayStart := false
		for _, role := range rb.StartRoles() {
			if err := p.can(role, res); err == nil {
				mayStart = true
				break
			} else if startErr == nil {
				startErr = err
			}
		}
		if !mayStart {
			if len(rb.Spec.Policy.AllowedRoles) > 0 {
				return httpError{http.StatusForbidden, "this runbook can only be started by " + roleList(rb.StartRoles()) + ": " + startErr.Error()}
			}
			return startErr
		}
		allowed := false
		for _, t := range rb.Spec.Triggers {
			if t.Type == "manual" || t.Type == "api" {
				allowed = true
			}
		}
		if !allowed {
			return httpError{403, "runbook has no manual or api trigger"}
		}
		// An API key doesn't say which person is behind it, so it can't
		// satisfy "approved by someone other than whoever started it".
		if p.Kind == "api_key" {
			for _, st := range rb.Spec.Steps {
				if st.Type == "approval" && st.ExcludeRequester {
					return httpError{403, "this runbook needs approval from someone other than whoever starts it, " +
						"so a person has to start it (an API key doesn't identify who is behind it)"}
				}
			}
		}
		opts := startRunOpts{VersionID: vid, Digest: digest, Runbook: rb, TriggerType: "api", Mode: "manual",
			RequestedByType: p.actorType(), RequestedByID: p.actor()}
		vars := expr.Vars{}
		if req.Incident > 0 {
			inc, err := s.incidentByNumber(tx, req.Incident, false)
			if err != nil {
				return err
			}
			// Linking a run writes to the incident's timeline and pages from it.
			if err := p.can("responder", s.incidentResource(tx, inc)); err != nil {
				return err
			}
			opts.IncidentID = inc.ID
			opts.Incident = map[string]any{"id": ids.Encode("inc", inc.ID), "number": inc.Number, "title": inc.Title, "severity": inc.Severity}
			vars["incident"] = opts.Incident
		}
		params, err := runbook.ResolveParams(rb, req.Params, vars)
		if err != nil {
			return httpError{400, err.Error()}
		}
		opts.Params = params
		if reason, err := s.concurrencyBlocked(tx, rb, params); err != nil {
			return err
		} else if reason != "" {
			return httpError{409, reason}
		}
		runID, err = s.startRun(r.Context(), tx, opts)
		return err
	})
	return map[string]string{"id": ids.Encode("run", runID)}, err
}

func (s *Server) apiGetRun(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("run", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	var out map[string]any
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		run, err := s.loadRun(tx, id, false)
		if err != nil {
			return err
		}
		var verified sql.NullBool
		var started time.Time
		var finished sql.NullTime
		tx.QueryRow(`SELECT verified, started_at, finished_at FROM runbook_runs WHERE id = $1`, id).Scan(&verified, &started, &finished)
		var steps []map[string]any
		rows, err := tx.Query(`SELECT id, step_id, attempt_number, state, exit_code, outputs, error FROM step_attempts
			WHERE run_id = $1 ORDER BY step_index, attempt_number`, id)
		if err != nil {
			return err
		}
		var attemptIDs []string
		for rows.Next() {
			var aid, sid, state string
			var n int
			var exit sql.NullInt64
			var outputs db.JSON[map[string]any]
			var e sql.NullString
			if err := rows.Scan(&aid, &sid, &n, &state, &exit, &outputs, &e); err != nil {
				rows.Close()
				return err
			}
			st := map[string]any{"step": sid, "attempt": n, "state": state, "outputs": outputs.V}
			if exit.Valid {
				st["exit_code"] = exit.Int64
			}
			if e.Valid {
				st["error"] = e.String
			}
			steps = append(steps, st)
			attemptIDs = append(attemptIDs, aid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// One statement at a time per transaction: read outputs after the
		// attempts cursor is closed.
		// The view shows the tail of each attempt's output, newest attempts
		// first within a response budget; a run with many retried steps
		// would otherwise return up to 1 MiB per attempt. The full output of
		// one attempt is at .../steps/{step}/attempts/{n}/output.
		budget := maxRunViewOutput
		for i := len(attemptIDs) - 1; i >= 0; i-- {
			limit := min(maxAttemptTail, budget)
			text, total, err := s.attemptOutput(tx, attemptIDs[i], limit)
			if err != nil {
				return err
			}
			budget -= len(text)
			steps[i]["output"] = text
			steps[i]["output_bytes"] = total
			if len(text) < total {
				steps[i]["output_truncated"] = true
			}
		}
		approvals, err := s.runApprovals(tx, id)
		if err != nil {
			return err
		}
		out = map[string]any{"id": ids.Encode("run", id), "runbook": run.RunbookName, "digest": run.Digest,
			"status": run.Status, "params": run.Params, "error": run.Error.String, "verified": verified.Bool,
			"started_at": started, "finished_at": finished.Time, "attempts": steps, "approvals": approvals}
		return nil
	})
	return out, err
}

// Bounds on run output returned by the API.
const (
	maxAttemptTail   = 64 << 10 // per attempt in the run view
	maxRunViewOutput = 1 << 20  // across all attempts in the run view
)

// attemptOutput returns the last limit bytes (at most) of an attempt's
// output, cut at a chunk or rune boundary, and the attempt's total output
// size. A negative limit means all of it.
func (s *Server) attemptOutput(tx *db.Tx, attemptID string, limit int) (string, int, error) {
	var total int
	if err := tx.QueryRow(`SELECT COALESCE(sum(octet_length(data)), 0) FROM step_output_chunks WHERE attempt_id = $1`,
		attemptID).Scan(&total); err != nil {
		return "", 0, err
	}
	if limit == 0 || total == 0 {
		return "", total, nil
	}
	rows, err := tx.Query(`SELECT data FROM step_output_chunks WHERE attempt_id = $1 ORDER BY seq DESC`, attemptID)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	var parts []string
	n := 0
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return "", 0, err
		}
		if limit >= 0 && n+len(d) > limit {
			// Keep the end of this chunk, starting on a rune boundary.
			d = d[len(d)-(limit-n):]
			for len(d) > 0 && !utf8.RuneStart(d[0]) {
				d = d[1:]
			}
			parts = append(parts, d)
			break
		}
		parts = append(parts, d)
		n += len(d)
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteString(parts[i])
	}
	return b.String(), total, nil
}

func (s *Server) apiAttemptOutput(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("run", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	var out map[string]any
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var aid string
		err := tx.QueryRow(`SELECT id FROM step_attempts WHERE run_id = $1 AND step_id = $2 AND attempt_number = $3`,
			id, r.PathValue("step"), n).Scan(&aid)
		if errors.Is(err, sql.ErrNoRows) {
			return httpError{404, "not found"}
		}
		if err != nil {
			return err
		}
		text, total, err := s.attemptOutput(tx, aid, -1)
		if err != nil {
			return err
		}
		out = map[string]any{"step": r.PathValue("step"), "attempt": n, "output": text, "output_bytes": total}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

// maxTimelinePage bounds one page of an incident's timeline.
const maxTimelinePage = 1000

// incidentByNumber loads an incident by its number. Only actions that change
// it take the row lock: a viewer polling an incident must not queue behind
// (or hold up) alert processing on it.
func (s *Server) incidentByNumber(tx *db.Tx, n int64, lock bool) (incidentRow, error) {
	var id string
	if err := tx.QueryRow(`SELECT id FROM incidents WHERE number = $1`, n).Scan(&id); err != nil {
		if isNoRows(err) {
			return incidentRow{}, httpError{404, fmt.Sprintf("no incident #%d", n)}
		}
		return incidentRow{}, err
	}
	return s.loadIncident(tx, id, lock)
}

func incidentNumber(r *http.Request) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimPrefix(r.PathValue("number"), "#"), 10, 64)
	if err != nil {
		return 0, httpError{404, "incident number must be an integer"}
	}
	return n, nil
}

func (s *Server) incidentJSON(tx *db.Tx, inc incidentRow) map[string]any {
	var resolution sql.NullString
	var opened time.Time
	var resolved sql.NullTime
	tx.QueryRow(`SELECT resolution, opened_at, resolved_at FROM incidents WHERE id = $1`, inc.ID).Scan(&resolution, &opened, &resolved)
	out := map[string]any{
		"id": ids.Encode("inc", inc.ID), "number": inc.Number, "service": s.serviceName(tx, inc.ServiceID),
		"status": inc.Status, "severity": inc.Severity, "title": inc.Title, "opened_at": opened,
		"paged": inc.PagedAt.Valid, "resolution": resolution.String,
	}
	if resolved.Valid {
		out["resolved_at"] = resolved.Time
	}
	if inc.RemediationRunID.Valid {
		out["remediation_run"] = ids.Encode("run", inc.RemediationRunID.String)
	}
	if inc.HoldUntil.Valid {
		out["hold_until"] = inc.HoldUntil.Time
	}
	return out
}

func (s *Server) apiListIncidents(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT id FROM incidents ORDER BY number DESC LIMIT 50`)
		if err != nil {
			return err
		}
		var list []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			list = append(list, id)
		}
		rows.Close()
		for _, id := range list {
			inc, err := s.loadIncident(tx, id, false)
			if err != nil {
				return err
			}
			out = append(out, s.incidentJSON(tx, inc))
		}
		return nil
	})
	return out, err
}

func (s *Server) apiGetIncident(r *http.Request, p principal) (any, error) {
	n, err := incidentNumber(r)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		inc, err := s.incidentByNumber(tx, n, false)
		if err != nil {
			return err
		}
		out = s.incidentJSON(tx, inc)
		return nil
	})
	return out, err
}

func (s *Server) apiTimeline(r *http.Request, p principal) (any, error) {
	n, err := incidentNumber(r)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		inc, err := s.incidentByNumber(tx, n, false)
		if err != nil {
			return err
		}
		// Paged: ?after=<id of the last entry seen>&limit=<n> (default and
		// maximum 1000). A busy incident's whole timeline was returned at once.
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > maxTimelinePage {
			limit = maxTimelinePage
		}
		rows, err := tx.Query(`SELECT id, at, type, actor_type, message FROM incident_timeline WHERE incident_id = $1 AND id > $2
			ORDER BY id LIMIT $3`, inc.ID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var at time.Time
			var typ, actor, msg string
			if err := rows.Scan(&id, &at, &typ, &actor, &msg); err != nil {
				return err
			}
			out = append(out, map[string]any{"id": id, "at": at, "type": typ, "actor": actor, "message": msg})
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) apiAck(r *http.Request, p principal) (any, error) {
	n, err := incidentNumber(r)
	if err != nil {
		return nil, err
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		inc, err := s.incidentByNumber(tx, n, true)
		if err != nil {
			return err
		}
		if err := p.can("responder", s.incidentResource(tx, inc)); err != nil {
			return err
		}
		if inc.Status == "resolved" {
			return httpError{409, "incident is resolved"}
		}
		if _, err := tx.Exec(`UPDATE incidents SET status = 'acknowledged', ack_at = now(), hold_until = NULL, verify_until = NULL WHERE id = $1`, inc.ID); err != nil {
			return err
		}
		return s.timeline(tx, inc.ID, "incident.acknowledged", p.actorType(), p.actor(), "Acknowledged", nil)
	})
	return map[string]bool{"ok": err == nil}, err
}

func (s *Server) apiResolve(r *http.Request, p principal) (any, error) {
	n, err := incidentNumber(r)
	if err != nil {
		return nil, err
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		inc, err := s.incidentByNumber(tx, n, true)
		if err != nil {
			return err
		}
		if err := p.can("responder", s.incidentResource(tx, inc)); err != nil {
			return err
		}
		if inc.Status == "resolved" {
			return nil
		}
		// Alerts still firing are detached; if they keep firing they open a new incident.
		if _, err := tx.Exec(`UPDATE incident_alerts ia SET detached_at = now() FROM alerts a
			WHERE ia.alert_id = a.id AND ia.incident_id = $1 AND a.status = 'firing' AND ia.detached_at IS NULL`, inc.ID); err != nil {
			return err
		}
		return s.resolveIncident(r.Context(), tx, inc, "human", "Resolved by "+p.display())
	})
	return map[string]bool{"ok": err == nil}, err
}

func (s *Server) setFrozen(ctx context.Context, p principal, frozen bool) (any, error) {
	err := s.DB.WithOrg(ctx, p.OrgID, func(tx *db.Tx) error {
		if frozen {
			if _, err := tx.Exec(`UPDATE orgs SET frozen_at = now(), frozen_by = $2 WHERE id = $1`, p.OrgID, p.actor()); err != nil {
				return err
			}
			// Stop everything in flight. Agents also see Frozen on their next poll.
			rows, err := tx.Query(`SELECT id FROM runbook_runs WHERE status IN ('running','awaiting_approval')`)
			if err != nil {
				return err
			}
			var running []string
			for rows.Next() {
				var id string
				rows.Scan(&id)
				running = append(running, id)
			}
			rows.Close()
			for _, id := range running {
				run, err := s.loadRun(tx, id, true)
				if err != nil {
					return err
				}
				if run.Status != "running" && run.Status != "awaiting_approval" {
					continue // finished between the list and the lock
				}
				rb, err := s.loadVersionByID(tx, run.VersionID)
				if err != nil {
					return err
				}
				if err := s.finishRun(ctx, tx, run, rb, "cancelled", "org frozen by "+p.display()); err != nil {
					return err
				}
			}
		} else if _, err := tx.Exec(`UPDATE orgs SET frozen_at = NULL, frozen_by = NULL WHERE id = $1`, p.OrgID); err != nil {
			return err
		}
		action := "org.unfreeze"
		if frozen {
			action = "org.freeze"
		}
		return tx.Audit(ctx, p.actorType(), p.actor(), action, "org", p.OrgID, nil)
	})
	return map[string]bool{"frozen": frozen}, err
}

func (s *Server) apiAudit(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var broken sql.NullInt64
		if err := tx.QueryRow(`SELECT nfx_verify_audit_chain()`).Scan(&broken); err != nil {
			return err
		}
		if broken.Valid {
			return httpError{500, fmt.Sprintf("audit chain verification failed at seq %d", broken.Int64)}
		}
		rows, err := tx.Query(`SELECT seq, at, actor_type, actor_id, action, resource_type, resource_id FROM audit_events ORDER BY seq DESC LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var seq int64
			var at time.Time
			var at1, aid, action, rt, rid string
			if err := rows.Scan(&seq, &at, &at1, &aid, &action, &rt, &rid); err != nil {
				return err
			}
			out = append(out, map[string]any{"seq": seq, "at": at, "actor": at1 + ":" + aid, "action": action, "resource": rt + ":" + rid})
		}
		return rows.Err()
	})
	return out, err
}

// apiSigningKeys lists the org's runbook signing keys (public halves only)
// and the value to pin in agents: with key_id=public-key pinned, an agent
// refuses runbooks unless that exact key signed them, whatever the control
// plane later claims.
func (s *Server) apiSigningKeys(r *http.Request, p principal) (any, error) {
	var out map[string]any
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT key_id, owner, state, public_key, created_at FROM signing_keys
			WHERE state <> 'retired' ORDER BY created_at`)
		if err != nil {
			return err
		}
		keys := []map[string]any{}
		pub := map[string]string{}
		for rows.Next() {
			var id, owner, state string
			var pk []byte
			var at time.Time
			if err := rows.Scan(&id, &owner, &state, &pk, &at); err != nil {
				rows.Close()
				return err
			}
			b64 := base64.StdEncoding.EncodeToString(pk)
			pub[id] = b64
			keys = append(keys, map[string]any{"key_id": id, "owner": owner, "state": state, "public_key": b64, "created_at": at})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var required stringArray
		if err := tx.QueryRow(`SELECT required_signers FROM org_trust_config`).Scan(&required); err != nil {
			return err
		}
		var pins []string
		for _, id := range required {
			if b64, ok := pub[id]; ok {
				pins = append(pins, id+"="+b64)
			}
		}
		out = map[string]any{"keys": keys, "required_signers": []string(required), "agent_pin": strings.Join(pins, ",")}
		return nil
	})
	return out, err
}
