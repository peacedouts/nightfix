package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// Slack approvals. Approval messages go out through the org's incoming
// webhooks with Approve and Reject buttons. Clicking one makes Slack POST a
// request signed with the Slack app's signing secret to
// /v1/slack/interactions/{app}. We verify the signature and timestamp before
// doing anything else, map the Slack user to a Nightfix user, and record the
// decision as that user, with exactly the same checks as the API.
//
// Mapping is never taken from Slack profile data such as email. A signed-in
// Nightfix user gets a one-time code (POST /v1/me/slack-link-code) and types
// `/nightfix link CODE` in Slack; Slack's signed slash-command request then
// names the Slack user. To get their Slack account linked to someone else's
// Nightfix identity, an attacker would need that person to hand over their
// own code, rather than merely entering one (the device-code phishing
// pattern a code-shown-in-Slack flow would allow).

const (
	slackSigVersion   = "v0"
	slackMaxSkew      = 5 * time.Minute
	slackMaxBody      = 64 << 10
	slackLinkCodeTTL  = 10 * time.Minute
	slackApproveID    = "nfx_approve"
	slackRejectID     = "nfx_reject"
	slackResponseHost = "https://hooks.slack.com/"
)

func (s *Server) slackRoutes(route routeFn, mux *http.ServeMux) {
	// Owner only: a Slack app's signing secret authenticates approval clicks,
	// so whoever holds it speaks for the people linked through that app.
	route("POST /v1/slack-apps", "owner", s.apiCreateSlackApp)
	route("GET /v1/slack-apps", "admin", s.apiListSlackApps)
	route("POST /v1/slack-apps/{id}/archive", "owner", s.apiArchiveSlackApp)
	route("POST /v1/me/slack-link-code", "viewer", s.apiSlackLinkCode)
	// Authenticated by Slack's request signature, not a bearer token.
	mux.HandleFunc("POST /v1/slack/interactions/{id}", s.handleSlackInteraction)
	mux.HandleFunc("POST /v1/slack/commands/{id}", s.handleSlackCommand)
}

func (s *Server) apiCreateSlackApp(r *http.Request, p principal) (any, error) {
	var req struct {
		SigningSecret string `json:"signing_secret"`
		TeamID        string `json:"team_id"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if len(req.SigningSecret) < 16 {
		return nil, httpError{400, "signing_secret is required (Slack app → Basic Information → Signing Secret)"}
	}
	if !slackTeamRe.MatchString(req.TeamID) {
		return nil, httpError{400, "team_id is required: your Slack workspace ID (T…, not an Enterprise Grid E… ID), so requests from any other workspace are refused"}
	}
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		sealed, err := s.seal([]byte(req.SigningSecret), p.OrgID, sealSlackSigning)
		if err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO slack_apps (id, org_id, team_id, signing_secret)
			SELECT $1,$2,$3,$4 WHERE NOT EXISTS (SELECT 1 FROM slack_apps WHERE team_id = $3 AND archived_at IS NULL)`,
			id, p.OrgID, req.TeamID, sealed)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // a concurrent registration won
			return httpError{409, "this workspace already has an active Slack app; archive it first (POST /v1/slack-apps/{id}/archive)"}
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return httpError{409, "this workspace already has an active Slack app; archive it first (POST /v1/slack-apps/{id}/archive)"}
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "slack_app.create", "slack_app", id, map[string]string{"team_id": req.TeamID})
	})
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(s.Cfg.PublicAPIURL, "/")
	return map[string]string{
		"id":                ids.Encode("slk", id),
		"interactivity_url": base + "/v1/slack/interactions/" + ids.Encode("slk", id),
		"commands_url":      base + "/v1/slack/commands/" + ids.Encode("slk", id),
	}, nil
}

// Workspace IDs start with T. Requests carry the workspace's ID even on
// Enterprise Grid, so an organization's E… ID would never match.
var slackTeamRe = regexp.MustCompile(`^T[A-Z0-9]{2,20}$`)

// apiListSlackApps lists the org's Slack apps (never their secrets), so a
// stray or leaked one can be found and archived.
func (s *Server) apiListSlackApps(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT a.id, coalesce(a.team_id, ''), a.created_at, a.archived_at,
				(SELECT count(*) FROM slack_user_links l WHERE l.slack_app_id = a.id)
			FROM slack_apps a ORDER BY a.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, team string
			var created time.Time
			var archived *time.Time
			var links int
			if err := rows.Scan(&id, &team, &created, &archived, &links); err != nil {
				return err
			}
			a := map[string]any{"id": ids.Encode("slk", id), "team_id": team, "created_at": created, "linked_users": links}
			if archived != nil {
				a["archived_at"] = *archived
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return map[string]any{"slack_apps": out}, err
}

// apiArchiveSlackApp stops a Slack app's requests at once: clicks and
// commands signed with its secret are refused, and links made through it
// no longer count.
func (s *Server) apiArchiveSlackApp(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("slk", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "no such Slack app"}
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		res, err := tx.Exec(`UPDATE slack_apps SET archived_at = now() WHERE id = $1 AND archived_at IS NULL`, id)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // a concurrent registration won
			return httpError{409, "this workspace already has an active Slack app; archive it first (POST /v1/slack-apps/{id}/archive)"}
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var exists bool
			if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM slack_apps WHERE id = $1)`, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return httpError{404, "no such Slack app"}
			}
			return nil // already archived
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "slack_app.archive", "slack_app", id, nil)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": ids.Encode("slk", id), "archived": true}, nil
}

// apiSlackLinkCode issues a one-time code for the signed-in user to type into
// Slack. Only the person it was issued to should ever see it.
func (s *Server) apiSlackLinkCode(r *http.Request, p principal) (any, error) {
	if p.Kind != "user" {
		return nil, httpError{403, "sign in as yourself (not with an API key) to link your Slack account"}
	}
	display, norm := newLinkCode()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`DELETE FROM slack_link_codes WHERE expires_at < now() OR user_id = $1`, p.UserID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO slack_link_codes (code_hash, org_id, user_id, expires_at) VALUES ($1,$2,$3,$4)`,
			hashSecret(norm), p.OrgID, p.UserID, time.Now().Add(slackLinkCodeTTL))
		return err
	})
	return map[string]string{
		"code":       display,
		"expires_in": roundDur(slackLinkCodeTTL),
		"next":       "In Slack, type: /nightfix link " + display + "  (never share this code; it makes a Slack account act as you)",
	}, err
}

func normalizeCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func newLinkCode() (display, normalized string) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	c := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:12] // 60 bits
	return c[:4] + "-" + c[4:8] + "-" + c[8:], c
}

// verifySlackSignature checks Slack's v0 request signature.
func verifySlackSignature(secret string, body []byte, ts, sig string, now time.Time) error {
	if ts == "" || sig == "" {
		return errors.New("missing Slack signature headers")
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > slackMaxSkew || d < -slackMaxSkew {
		return errors.New("request timestamp is too old or in the future")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s:%s:", slackSigVersion, ts)
	mac.Write(body)
	want := slackSigVersion + "=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errors.New("signature mismatch")
	}
	return nil
}

// slackRequest authenticates a request from Slack: routes the app, verifies
// the signature over the raw body before any transaction, and parses the
// form. It writes the HTTP error itself and returns ok=false on failure.
func (s *Server) slackRequest(w http.ResponseWriter, r *http.Request) (orgID, appID string, team *string, form url.Values, ok bool) {
	appID, err := ids.Decode("slk", r.PathValue("id"))
	if err != nil {
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, slackMaxBody+1))
	if err != nil || len(body) > slackMaxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var sealed []byte
	if err := s.DB.QueryRowContext(r.Context(), `SELECT org_id, signing_secret, team_id FROM nfx_route_slack_app($1)`, appID).
		Scan(&orgID, &sealed, &team); err != nil {
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}
	secret, err := s.unseal(sealed, orgID, sealSlackSigning)
	if err != nil {
		s.Log.Error("slack: unseal signing secret", "app", appID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := verifySlackSignature(string(secret), body, r.Header.Get("X-Slack-Request-Timestamp"),
		r.Header.Get("X-Slack-Signature"), time.Now()); err != nil {
		http.Error(w, "Slack signature: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if form, err = url.ParseQuery(string(body)); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	return orgID, appID, team, form, true
}

type slackInteraction struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	ResponseURL string `json:"response_url"`
}

func (s *Server) handleSlackInteraction(w http.ResponseWriter, r *http.Request) {
	orgID, appID, team, form, ok := s.slackRequest(w, r)
	if !ok {
		return
	}
	var in slackInteraction
	if json.Unmarshal([]byte(form.Get("payload")), &in) != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if team != nil && *team != in.Team.ID {
		http.Error(w, "this Slack app is set up for a different workspace", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	if in.Type != "block_actions" || len(in.Actions) == 0 || in.User.ID == "" {
		return // other interaction types aren't used
	}
	act := in.Actions[0]
	decision := map[string]string{slackApproveID: "approved", slackRejectID: "rejected"}[act.ActionID]
	gateID, gerr := ids.Decode("apr", act.Value)
	if decision == "" || gerr != nil {
		return
	}

	var reply string
	err := s.DB.WithOrg(r.Context(), orgID, func(tx *db.Tx) error {
		var userID string
		// Only a link made through this same app counts: another app's
		// signing secret mustn't be able to speak for people linked elsewhere.
		err := tx.QueryRow(`SELECT user_id FROM slack_user_links WHERE slack_app_id = $1 AND slack_team_id = $2 AND slack_user_id = $3`,
			appID, in.Team.ID, in.User.ID).Scan(&userID)
		if isNoRows(err) {
			reply = ":link: Your Slack account isn't linked to Nightfix yet, so nothing was recorded. Link it once: " +
				"signed in to Nightfix, get a code (`POST /v1/me/slack-link-code`), then type `/nightfix link <code>` here. Then click again."
			return nil
		}
		if err != nil {
			return err
		}
		p, err := s.memberPrincipal(tx, userID)
		if err != nil {
			return err
		}
		res, err := s.decide(r.Context(), tx, p, gateID, decision, "", "slack")
		if err != nil {
			return err
		}
		switch res.Status {
		case "approved":
			reply = fmt.Sprintf(":white_check_mark: You approved `%s`. The run continues.", res.Step)
		case "rejected":
			reply = fmt.Sprintf(":no_entry: You rejected `%s`. The run was cancelled.", res.Step)
		default:
			reply = fmt.Sprintf(":ballot_box_with_check: You approved `%s` (%d of %d). Waiting for more approvals.", res.Step, res.Approvals, res.Required)
		}
		return nil
	})
	var he httpError
	switch {
	case errors.As(err, &he):
		reply = ":warning: " + he.msg // genuine click, decision not allowed: tell the clicker
	case err != nil:
		s.Log.Error("slack interaction", "org", orgID, "err", err)
		reply = ":warning: Nightfix couldn't record that. Try again, or use the API."
	}
	if reply != "" && in.ResponseURL != "" {
		go s.slackRespond(in.ResponseURL, reply)
	}
}

// handleSlackCommand serves the /nightfix slash command. Its reply is the
// HTTP response, shown only to the person who typed it.
func (s *Server) handleSlackCommand(w http.ResponseWriter, r *http.Request) {
	orgID, appID, team, form, ok := s.slackRequest(w, r)
	if !ok {
		return
	}
	teamID, slackUser, slackName := form.Get("team_id"), form.Get("user_id"), form.Get("user_name")
	if team != nil && *team != teamID {
		http.Error(w, "this Slack app is set up for a different workspace", http.StatusForbidden)
		return
	}
	reply := func(text string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"response_type": "ephemeral", "text": text})
	}
	verb, arg, _ := strings.Cut(strings.TrimSpace(form.Get("text")), " ")
	if verb != "link" || arg == "" || slackUser == "" || teamID == "" {
		reply("Usage: `/nightfix link <code>`. Get a code while signed in to Nightfix: `POST /v1/me/slack-link-code`.")
		return
	}
	var email string
	err := s.DB.WithOrg(r.Context(), orgID, func(tx *db.Tx) error {
		var userID string
		err := tx.QueryRow(`DELETE FROM slack_link_codes WHERE code_hash = $1 AND expires_at > now() RETURNING user_id`,
			hashSecret(normalizeCode(arg))).Scan(&userID)
		if isNoRows(err) {
			return httpError{400, "That code is unknown or expired. Get a new one while signed in to Nightfix."}
		}
		if err != nil {
			return err
		}
		p, err := s.memberPrincipal(tx, userID)
		if err != nil {
			return err
		}
		email = p.Email
		// One Slack account per person per workspace; the latest link wins.
		if _, err := tx.Exec(`DELETE FROM slack_user_links WHERE slack_team_id = $1 AND (user_id = $2 OR slack_user_id = $3)`,
			teamID, userID, slackUser); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO slack_user_links (org_id, slack_team_id, slack_user_id, user_id, slack_app_id) VALUES ($1,$2,$3,$4,$5)`,
			orgID, teamID, slackUser, userID, appID); err != nil {
			return err
		}
		return tx.Audit(r.Context(), "user", p.actor(), "slack.linked", "user", userID,
			map[string]string{"slack_team": teamID, "slack_user": slackUser, "slack_username": slackName})
	})
	var he httpError
	switch {
	case errors.As(err, &he):
		reply(":warning: " + he.msg)
	case err != nil:
		s.Log.Error("slack command", "org", orgID, "err", err)
		reply(":warning: Nightfix couldn't link your account. Try again.")
	default:
		reply(fmt.Sprintf(":link: Linked. Your Slack account now approves as %s in Nightfix.", slackEscape(email)))
	}
}

// slackRespond posts an ephemeral reply to the user who clicked. Only Slack's
// own response hosts are accepted, so a request can't aim us elsewhere.
func (s *Server) slackRespond(responseURL, text string) {
	ok := strings.HasPrefix(responseURL, slackResponseHost)
	for _, p := range s.Cfg.SlackResponseURLPrefixes {
		ok = ok || (p != "" && strings.HasPrefix(responseURL, p))
	}
	if !ok {
		s.Log.Warn("slack interaction: refusing unexpected response_url host")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.postJSON(ctx, responseURL, map[string]any{"response_type": "ephemeral", "replace_original": false, "text": text}); err != nil {
		s.Log.Warn("slack interaction: reply failed", "err", err)
	}
}

// slackApprovalMessage renders an approval request with buttons when the org
// has a Slack app for interactivity, or API instructions when it doesn't.
func slackApprovalMessage(p map[string]any) map[string]any {
	a, _ := p["approval"].(map[string]any)
	text := fmt.Sprintf(":raised_hand: *Approval needed* — incident #%v on `%v`: %v", p["incident_number"], slackEscape(p["service"]), slackEscape(p["reason"]))
	if p["incident_number"] == nil {
		text = fmt.Sprintf(":raised_hand: *Approval needed* — %v started `%v`. %v", slackEscape(a["requested_by"]), slackEscape(a["runbook"]), slackEscape(p["reason"]))
	}
	blocks := []any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}}
	if a["interactive"] == true {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "style": "primary", "action_id": slackApproveID, "value": a["gate"],
				"text": map[string]any{"type": "plain_text", "text": "Approve"},
				"confirm": map[string]any{
					"title":   map[string]any{"type": "plain_text", "text": "Approve this step?"},
					"text":    map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("`%v` will continue with *%v*.", slackEscape(a["runbook"]), slackEscape(a["step_name"]))},
					"confirm": map[string]any{"type": "plain_text", "text": "Approve"},
					"deny":    map[string]any{"type": "plain_text", "text": "Cancel"},
				}},
			map[string]any{"type": "button", "style": "danger", "action_id": slackRejectID, "value": a["gate"],
				"text": map[string]any{"type": "plain_text", "text": "Reject"}},
		}})
	} else {
		blocks = append(blocks, map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn",
			"text": fmt.Sprintf("Approve with `POST /v1/runs/%v/steps/%v/approve`, or reject with `…/reject`.", slackEscape(a["run"]), slackEscape(a["step"]))}}})
	}
	return map[string]any{"text": text, "blocks": blocks}
}
