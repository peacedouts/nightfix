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
	"strconv"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// Slack approvals. Approval messages go out through the org's incoming
// webhooks with Approve and Reject buttons. Clicking one makes Slack POST a
// request signed with the Slack app's signing secret to
// /v1/slack/interactions/{app}. We verify the signature and timestamp, map
// the Slack user to a Nightfix user, and record the decision as that user,
// with exactly the same checks as the API.
//
// Mapping is never trusted from Slack profile data such as email. The first
// time an unlinked Slack user clicks, they get a one-time code (shown only
// to them); redeeming it while signed in to Nightfix links the two accounts.
// That proves both identities: Slack's signed request vouches for the Slack
// user, and the Auth0 login vouches for the Nightfix user.

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
	route("POST /v1/slack-apps", "admin", s.apiCreateSlackApp)
	route("POST /v1/me/slack-link", "viewer", s.apiLinkSlack)
	// Authenticated by Slack's request signature, not a bearer token.
	mux.HandleFunc("POST /v1/slack/interactions/{id}", s.handleSlackInteraction)
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
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		sealed, err := s.Sealer.Seal([]byte(req.SigningSecret), p.OrgID)
		if err != nil {
			return err
		}
		var team any
		if req.TeamID != "" {
			team = req.TeamID
		}
		if _, err := tx.Exec(`INSERT INTO slack_apps (id, org_id, team_id, signing_secret) VALUES ($1,$2,$3,$4)`, id, p.OrgID, team, sealed); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "slack_app.create", "slack_app", id, map[string]string{"team_id": req.TeamID})
	})
	if err != nil {
		return nil, err
	}
	path := "/v1/slack/interactions/" + ids.Encode("slk", id)
	return map[string]string{"id": ids.Encode("slk", id), "interactivity_url": strings.TrimSuffix(s.Cfg.PublicAPIURL, "/") + path}, nil
}

// apiLinkSlack redeems a link code for the signed-in user.
func (s *Server) apiLinkSlack(r *http.Request, p principal) (any, error) {
	if p.Kind != "user" {
		return nil, httpError{403, "sign in as yourself (not with an API key) to link your Slack account"}
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var out map[string]string
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var team, user, username string
		err := tx.QueryRow(`DELETE FROM slack_link_codes WHERE code_hash = $1 AND expires_at > now()
			RETURNING slack_team_id, slack_user_id, slack_username`, hashSecret(normalizeCode(req.Code))).Scan(&team, &user, &username)
		if isNoRows(err) {
			return httpError{400, "unknown or expired code; click the button in Slack again for a new one"}
		}
		if err != nil {
			return err
		}
		// One Slack account per person per workspace, and the latest proof wins.
		if _, err := tx.Exec(`DELETE FROM slack_user_links WHERE slack_team_id = $1 AND (user_id = $2 OR slack_user_id = $3)`,
			team, p.UserID, user); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO slack_user_links (org_id, slack_team_id, slack_user_id, user_id) VALUES ($1,$2,$3,$4)`,
			p.OrgID, team, user, p.UserID); err != nil {
			return err
		}
		out = map[string]string{"linked": "true", "slack_team": team, "slack_user": user, "slack_username": username, "nightfix_user": p.Email}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "slack.linked", "user", p.UserID,
			map[string]string{"slack_team": team, "slack_user": user, "slack_username": username})
	})
	return out, err
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
	ctx := r.Context()
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
	var orgID string
	if err := s.DB.QueryRowContext(ctx, `SELECT org_id FROM nfx_route_slack_app($1)`, appID).Scan(&orgID); err != nil {
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}

	var in slackInteraction
	var reply string
	verified := false // after this, errors go back to the clicker, not to Slack
	err = s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		var sealed []byte
		var team *string
		if err := tx.QueryRow(`SELECT signing_secret, team_id FROM slack_apps WHERE id = $1`, appID).Scan(&sealed, &team); err != nil {
			return err
		}
		secret, err := s.Sealer.Open(sealed, orgID)
		if err != nil {
			return err
		}
		if err := verifySlackSignature(string(secret), body, r.Header.Get("X-Slack-Request-Timestamp"),
			r.Header.Get("X-Slack-Signature"), time.Now()); err != nil {
			return httpError{http.StatusUnauthorized, "Slack signature: " + err.Error()}
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || json.Unmarshal([]byte(form.Get("payload")), &in) != nil {
			return httpError{http.StatusBadRequest, "bad payload"}
		}
		if team != nil && *team != in.Team.ID {
			return httpError{http.StatusForbidden, "this Slack app is set up for a different workspace"}
		}
		verified = true
		if in.Type != "block_actions" || len(in.Actions) == 0 || in.User.ID == "" {
			return nil // other interaction types aren't used
		}
		act := in.Actions[0]
		decision := map[string]string{slackApproveID: "approved", slackRejectID: "rejected"}[act.ActionID]
		gateID, gerr := ids.Decode("apr", act.Value)
		if decision == "" || gerr != nil {
			return nil
		}

		var userID string
		err = tx.QueryRow(`SELECT user_id FROM slack_user_links WHERE slack_team_id = $1 AND slack_user_id = $2`,
			in.Team.ID, in.User.ID).Scan(&userID)
		if isNoRows(err) {
			display, norm := newLinkCode()
			if _, err := tx.Exec(`DELETE FROM slack_link_codes WHERE expires_at < now()`); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO slack_link_codes (code_hash, org_id, slack_team_id, slack_user_id, slack_username, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6)`, hashSecret(norm), orgID, in.Team.ID, in.User.ID, in.User.Username,
				time.Now().Add(slackLinkCodeTTL)); err != nil {
				return err
			}
			reply = fmt.Sprintf(":link: Your Slack account isn't linked to Nightfix yet, so nothing was recorded.\n"+
				"Link it once: while signed in to Nightfix, submit the code `%s` (`POST /v1/me/slack-link`). "+
				"It's for you only and expires in %s. Then click the button again.", display, roundDur(slackLinkCodeTTL))
			return nil
		}
		if err != nil {
			return err
		}
		p, err := s.memberPrincipal(tx, userID)
		if err != nil {
			return err
		}
		res, err := s.decide(ctx, tx, p, gateID, decision, "", "slack")
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
	case err != nil && !verified:
		code, msg := http.StatusInternalServerError, "internal error"
		if errors.As(err, &he) {
			code, msg = he.code, he.msg
		} else {
			s.Log.Error("slack interaction", "app", appID, "err", err)
		}
		http.Error(w, msg, code)
		return
	case errors.As(err, &he):
		// The click was genuine but the decision isn't allowed: tell the clicker.
		reply = ":warning: " + he.msg
	case err != nil:
		s.Log.Error("slack interaction", "app", appID, "err", err)
		reply = ":warning: Nightfix couldn't record that. Try again, or use the API."
	}
	w.WriteHeader(http.StatusOK)
	if reply != "" && in.ResponseURL != "" {
		go s.slackRespond(in.ResponseURL, reply)
	}
}

// slackRespond posts an ephemeral reply to the user who clicked. Only Slack's
// own response hosts are accepted, so a request can't aim us elsewhere.
func (s *Server) slackRespond(responseURL, text string) {
	ok := strings.HasPrefix(responseURL, slackResponseHost)
	for _, p := range s.Cfg.SlackResponseURLPrefixes {
		ok = ok || strings.HasPrefix(responseURL, p)
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
	text := fmt.Sprintf(":raised_hand: *Approval needed* — incident #%v on `%v`: %v", p["incident_number"], p["service"], p["reason"])
	blocks := []any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}}
	if a["interactive"] == true {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "style": "primary", "action_id": slackApproveID, "value": a["gate"],
				"text": map[string]any{"type": "plain_text", "text": "Approve"},
				"confirm": map[string]any{
					"title":   map[string]any{"type": "plain_text", "text": "Approve this step?"},
					"text":    map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("`%v` will continue with *%v*.", a["runbook"], a["step_name"])},
					"confirm": map[string]any{"type": "plain_text", "text": "Approve"},
					"deny":    map[string]any{"type": "plain_text", "text": "Cancel"},
				}},
			map[string]any{"type": "button", "style": "danger", "action_id": slackRejectID, "value": a["gate"],
				"text": map[string]any{"type": "plain_text", "text": "Reject"}},
		}})
	} else {
		blocks = append(blocks, map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn",
			"text": fmt.Sprintf("Approve with `POST /v1/runs/%v/steps/%v/approve`, or reject with `…/reject`.", a["run"], a["step"])}}})
	}
	return map[string]any{"text": text, "blocks": blocks}
}
