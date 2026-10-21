package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// Authorization model (data-model.md §5): org → teams → roles → scopes.
// A principal's permissions are the union of the role bindings that reach
// it: its own, and (for users) its teams'.

var roleRank = map[string]int{"viewer": 1, "responder": 2, "admin": 3, "owner": 4}

// Scope narrows where a binding applies. An omitted field means "any".
type Scope struct {
	Teams []string `json:"teams,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Env   []string `json:"env,omitempty"`
}

func (s Scope) empty() bool { return len(s.Teams) == 0 && len(s.Tags) == 0 && len(s.Env) == 0 }

func (s Scope) String() string {
	if s.empty() {
		return "org-wide"
	}
	var parts []string
	if len(s.Teams) > 0 {
		parts = append(parts, "teams="+strings.Join(s.Teams, ","))
	}
	if len(s.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(s.Tags, ","))
	}
	if len(s.Env) > 0 {
		parts = append(parts, "env="+strings.Join(s.Env, ","))
	}
	return strings.Join(parts, " ")
}

// resource describes what an action touches. A dimension a scope restricts
// must apply to the resource and match; an empty team or env on a resource
// where the dimension applies never matches a restricted scope (so an
// untagged runbook, or one that targets every environment, isn't open to a
// team-scoped responder).
type resource struct {
	Kind    string
	Team    string
	Tags    []string
	Env     string
	HasTags bool // runbooks have tags; incidents don't
	HasEnv  bool // runs target an environment; incidents don't
}

func (s Scope) matches(r resource) bool {
	if len(s.Teams) > 0 && !contains(s.Teams, r.Team) {
		return false
	}
	if len(s.Tags) > 0 {
		if !r.HasTags {
			return false
		}
		hit := false
		for _, t := range r.Tags {
			if contains(s.Tags, t) {
				hit = true
			}
		}
		if !hit {
			return false
		}
	}
	if len(s.Env) > 0 && (!r.HasEnv || !contains(s.Env, r.Env)) {
		return false
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

type binding struct {
	Role   string `json:"role"`
	Scope  Scope  `json:"scope"`
	Source string `json:"source"` // api_key | user | team:<slug> | default
}

// principal is an authenticated caller.
type principal struct {
	OrgID    string
	Kind     string // api_key | user
	KeyID    string
	UserID   string
	Email    string
	Teams    []string
	Bindings []binding
}

func (p principal) actor() string {
	if p.Kind == "user" {
		return ids.Encode("usr", p.UserID)
	}
	return ids.Encode("key", p.KeyID)
}

func (p principal) actorType() string { return p.Kind }

// atLeast requires an org-wide binding of at least role. Viewer access is
// granted by any binding, scoped or not.
func (p principal) atLeast(role string) error {
	for _, b := range p.Bindings {
		if roleRank[b.Role] >= roleRank[role] && (role == "viewer" || b.Scope.empty()) {
			return nil
		}
	}
	if role == "viewer" {
		return httpError{http.StatusForbidden, "no access to this org"}
	}
	return httpError{http.StatusForbidden, "requires an org-wide " + role + " role"}
}

// atLeastSomewhere requires role in at least one scope; endpoints using it
// then check the specific resource with can.
func (p principal) atLeastSomewhere(role string) error {
	for _, b := range p.Bindings {
		if roleRank[b.Role] >= roleRank[role] {
			return nil
		}
	}
	return httpError{http.StatusForbidden, "requires the " + role + " role"}
}

// can checks role on a specific resource.
func (p principal) can(role string, r resource) error {
	for _, b := range p.Bindings {
		if roleRank[b.Role] >= roleRank[role] && b.Scope.matches(r) {
			return nil
		}
	}
	desc := r.Kind
	if r.Team != "" {
		desc += " owned by team " + r.Team
	}
	if r.HasEnv {
		env := r.Env
		if env == "" {
			env = "any environment"
		}
		desc += " targeting " + env
	}
	return httpError{http.StatusForbidden, fmt.Sprintf("your roles don't allow %s on this %s", role, desc)}
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// Auth0Config configures user login. Leave Verifier nil to accept API keys only.
type Auth0Config struct {
	Verifier    *auth0.Verifier
	OrgClaim    string // Auth0 Organizations: "org_id"
	EmailClaim  string // custom claim added by an Auth0 Action
	GroupsClaim string // custom claim with the user's IdP groups
}

func (c Auth0Config) orgClaim() string    { return or(c.OrgClaim, "org_id") }
func (c Auth0Config) emailClaim() string  { return or(c.EmailClaim, "https://nightfix.dev/email") }
func (c Auth0Config) groupsClaim() string { return or(c.GroupsClaim, "https://nightfix.dev/groups") }

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (s *Server) authenticate(r *http.Request) (principal, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case ok && strings.HasPrefix(tok, "nfx_"):
		return s.authAPIKey(r.Context(), tok)
	case ok && auth0.LooksLikeJWT(tok) && s.Cfg.Auth0.Verifier != nil:
		return s.authUser(r.Context(), tok)
	default:
		return principal{}, fmt.Errorf("missing credentials (Authorization: Bearer <Auth0 access token or nfx_ API key>)")
	}
}

func (s *Server) authAPIKey(ctx context.Context, tok string) (principal, error) {
	p := principal{Kind: "api_key"}
	var role string
	if err := s.DB.QueryRowContext(ctx, `SELECT org_id, key_id, role FROM nfx_route_api_key($1)`, hashSecret(tok)).
		Scan(&p.OrgID, &p.KeyID, &role); err != nil {
		return p, fmt.Errorf("invalid API key")
	}
	p.Bindings = []binding{{Role: role, Source: "api_key"}}
	err := s.DB.WithOrg(ctx, p.OrgID, func(tx *db.Tx) error {
		extra, err := s.bindingsFor(tx, "api_key", p.KeyID, "api_key")
		p.Bindings = append(p.Bindings, extra...)
		return err
	})
	return p, err
}

// authUser verifies an Auth0 access token, maps its Auth0 Organization to our
// org, provisions the user just in time, syncs IdP group → team membership,
// and loads the user's bindings.
func (s *Server) authUser(ctx context.Context, tok string) (principal, error) {
	cfg := s.Cfg.Auth0
	claims, err := cfg.Verifier.Verify(ctx, tok)
	if err != nil {
		return principal{}, fmt.Errorf("invalid token: %v", err)
	}
	authOrg := claims.String(cfg.orgClaim())
	if authOrg == "" {
		return principal{}, fmt.Errorf("token has no %s claim; log in through your organization", cfg.orgClaim())
	}
	p := principal{Kind: "user"}
	if err := s.DB.QueryRowContext(ctx, `SELECT org_id FROM nfx_route_auth0_org($1)`, authOrg).Scan(&p.OrgID); err != nil {
		return p, fmt.Errorf("this Auth0 organization is not linked to a Nightfix org")
	}
	email := claims.String(cfg.emailClaim())
	if email == "" {
		email = claims.String("email")
	}
	if email == "" {
		return p, fmt.Errorf("token has no email claim (%s)", cfg.emailClaim())
	}
	p.Email = email
	groups := claims.Strings(cfg.groupsClaim())

	err = s.DB.WithOrg(ctx, p.OrgID, func(tx *db.Tx) error {
		if err := tx.QueryRow(`SELECT nfx_upsert_user($1,$2,$3)`, claims.String("sub"), email, claims.String("name")).Scan(&p.UserID); err != nil {
			return err
		}
		var status string
		err := tx.QueryRow(`INSERT INTO org_members (org_id, user_id, last_login_at) VALUES ($1,$2,now())
			ON CONFLICT (org_id, user_id) DO UPDATE SET last_login_at = now() RETURNING status`, p.OrgID, p.UserID).Scan(&status)
		if err != nil {
			return err
		}
		if status != "active" {
			return httpError{403, "you have been removed from this org"}
		}
		if err := s.syncIdPTeams(ctx, tx, p.UserID, groups); err != nil {
			return err
		}
		return s.loadUserBindings(tx, &p)
	})
	return p, err
}

// loadUserBindings fills in a user's teams and the bindings that reach them.
func (s *Server) loadUserBindings(tx *db.Tx, p *principal) error {
	rows, err := tx.Query(`SELECT t.id, t.slug FROM team_members m JOIN teams t ON t.id = m.team_id
		WHERE m.user_id = $1 AND t.archived_at IS NULL ORDER BY t.slug`, p.UserID)
	if err != nil {
		return err
	}
	type team struct{ id, slug string }
	var teams []team
	for rows.Next() {
		var t team
		rows.Scan(&t.id, &t.slug)
		teams = append(teams, t)
	}
	rows.Close()
	own, err := s.bindingsFor(tx, "user", p.UserID, "user")
	if err != nil {
		return err
	}
	p.Bindings, p.Teams = own, nil
	for _, t := range teams {
		p.Teams = append(p.Teams, t.slug)
		tb, err := s.bindingsFor(tx, "team", t.id, "team:"+t.slug)
		if err != nil {
			return err
		}
		p.Bindings = append(p.Bindings, tb...)
	}
	if len(p.Bindings) == 0 {
		// Org members without a binding are viewers (free seats).
		p.Bindings = []binding{{Role: "viewer", Source: "default"}}
	}
	return nil
}

// memberPrincipal builds the principal for an existing, active org member
// without a token (a linked Slack user). Team membership is as of the
// member's last login, when IdP groups were last synced.
func (s *Server) memberPrincipal(tx *db.Tx, userID string) (principal, error) {
	p := principal{Kind: "user", OrgID: tx.OrgID, UserID: userID}
	var status string
	var lastLogin sql.NullTime
	err := tx.QueryRow(`SELECT u.email, m.status, m.last_login_at FROM nfx_org_users() u JOIN org_members m ON m.user_id = u.id
		WHERE u.id = $1`, userID).Scan(&p.Email, &status, &lastLogin)
	if isNoRows(err) || (err == nil && status != "active") {
		return p, httpError{http.StatusForbidden, "your Nightfix account is no longer a member of this org"}
	}
	if err != nil {
		return p, err
	}
	if !lastLogin.Valid || time.Since(lastLogin.Time) > s.Cfg.SlackMaxLoginAge {
		return p, httpError{http.StatusForbidden, fmt.Sprintf(
			"you haven't signed in to Nightfix in the last %s; sign in once to refresh your access, then click again", roundDur(s.Cfg.SlackMaxLoginAge))}
	}
	return p, s.loadUserBindings(tx, &p)
}

// syncIdPTeams makes the user's idp-sourced team memberships match the
// groups claim. Manual memberships are left alone.
func (s *Server) syncIdPTeams(ctx context.Context, tx *db.Tx, userID string, groups []string) error {
	rows, err := tx.Query(`SELECT id, auth0_group FROM teams WHERE auth0_group IS NOT NULL AND archived_at IS NULL`)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	var all []string
	for rows.Next() {
		var id, g string
		rows.Scan(&id, &g)
		all = append(all, id)
		if contains(groups, g) {
			want[id] = true
		}
	}
	rows.Close()
	for _, id := range all {
		if want[id] {
			if _, err := tx.Exec(`INSERT INTO team_members (org_id, team_id, user_id, source) VALUES ($1,$2,$3,'idp')
				ON CONFLICT (org_id, team_id, user_id) DO NOTHING`, tx.OrgID, id, userID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2 AND source = 'idp'`, id, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) bindingsFor(tx *db.Tx, subjectType, subjectID, source string) ([]binding, error) {
	rows, err := tx.Query(`SELECT role, scope FROM role_bindings WHERE subject_type = $1 AND subject_id = $2`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []binding
	for rows.Next() {
		var b binding
		var sc db.JSON[Scope]
		if err := rows.Scan(&b.Role, &sc); err != nil {
			return nil, err
		}
		b.Scope, b.Source = sc.V, source
		out = append(out, b)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

func runbookResource(team string, tags []string, selector map[string]string) resource {
	return resource{Kind: "runbook", Team: team, Tags: tags, HasTags: true, Env: selector["env"], HasEnv: true}
}

func (s *Server) incidentResource(tx *db.Tx, inc incidentRow) resource {
	var team sql.NullString
	tx.QueryRow(`SELECT team FROM services WHERE id = $1`, inc.ServiceID).Scan(&team)
	return resource{Kind: "incident", Team: team.String}
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}
