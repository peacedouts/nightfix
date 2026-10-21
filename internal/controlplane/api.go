package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

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
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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
			v, err := fn(r, p)
			s.reply(w, v, err)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
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
	route("PUT /v1/routing-rules", "admin", s.apiPutRoutingRules)
	route("POST /v1/enrollment-rules", "admin", s.apiCreateEnrollmentRule)
	route("GET /v1/agents", "viewer", s.apiListAgents)
	route("POST /v1/runbooks/validate", "responder*", s.apiValidateRunbook)
	route("PUT /v1/runbooks/{name}", "responder*", s.apiPublishRunbook)
	route("GET /v1/runbooks/{name}", "viewer", s.apiGetRunbook)
	route("POST /v1/runs", "responder*", s.apiStartRun)
	s.approvalRoutes(route)
	s.slackRoutes(route, mux)
	route("GET /v1/runs/{id}", "viewer", s.apiGetRun)
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
		if !strings.HasPrefix(req.URL, "https://") && !strings.HasPrefix(req.URL, "http://127.0.0.1") && !strings.HasPrefix(req.URL, "http://localhost") {
			return nil, httpError{400, "url must be an https Slack incoming-webhook URL"}
		}
		secret = req.URL
	case "pagerduty":
		if req.RoutingKey == "" {
			return nil, httpError{400, "routing_key is required"}
		}
		secret = req.RoutingKey
		if req.EventsURL != "" {
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
		if err := p.can("responder", runbookResource(rb.Metadata.Team, rb.Metadata.Tags, selector(rb))); err != nil {
			return err
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
			inc, err := s.incidentByNumber(tx, req.Incident)
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
		for i, aid := range attemptIDs {
			steps[i]["output"] = s.attemptOutput(tx, aid)
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

func (s *Server) attemptOutput(tx *db.Tx, attemptID string) string {
	rows, err := tx.Query(`SELECT data FROM step_output_chunks WHERE attempt_id = $1 ORDER BY seq`, attemptID)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var d string
		rows.Scan(&d)
		b.WriteString(d)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

func (s *Server) incidentByNumber(tx *db.Tx, n int64) (incidentRow, error) {
	var id string
	if err := tx.QueryRow(`SELECT id FROM incidents WHERE number = $1`, n).Scan(&id); err != nil {
		if isNoRows(err) {
			return incidentRow{}, httpError{404, fmt.Sprintf("no incident #%d", n)}
		}
		return incidentRow{}, err
	}
	return s.loadIncident(tx, id, true)
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
		inc, err := s.incidentByNumber(tx, n)
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
		inc, err := s.incidentByNumber(tx, n)
		if err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT at, type, actor_type, message FROM incident_timeline WHERE incident_id = $1 ORDER BY id`, inc.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var at time.Time
			var typ, actor, msg string
			if err := rows.Scan(&at, &typ, &actor, &msg); err != nil {
				return err
			}
			out = append(out, map[string]any{"at": at, "type": typ, "actor": actor, "message": msg})
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
		inc, err := s.incidentByNumber(tx, n)
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
		inc, err := s.incidentByNumber(tx, n)
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
