package controlplane

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// display is how a principal appears in timelines and messages.
func (p principal) display() string {
	if p.Kind == "user" && p.Email != "" {
		return p.Email
	}
	return p.actor()
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type routeFn func(pattern, minRole string, fn func(r *http.Request, p principal) (any, error))

func (s *Server) identityRoutes(route routeFn) {
	route("PUT /v1/org/auth0", "owner", s.apiLinkAuth0)
	route("POST /v1/teams", "admin", s.apiCreateTeam)
	route("GET /v1/teams", "viewer", s.apiListTeams)
	route("POST /v1/teams/{slug}/members", "admin", s.apiAddTeamMember)
	route("GET /v1/members", "viewer", s.apiListMembers)
	route("POST /v1/role-bindings", "admin", s.apiCreateBinding)
	route("GET /v1/role-bindings", "admin", s.apiListBindings)
	route("DELETE /v1/role-bindings/{id}", "admin", s.apiDeleteBinding)
}

// apiLinkAuth0 connects an Auth0 Organization (org_…) to this org, so its
// members can log in.
func (s *Server) apiLinkAuth0(r *http.Request, p principal) (any, error) {
	var req struct {
		Auth0OrgID string `json:"auth0_org_id"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(req.Auth0OrgID, "org_") {
		return nil, httpError{400, "auth0_org_id must be an Auth0 Organization id (org_…)"}
	}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`UPDATE orgs SET auth0_org_id = $2 WHERE id = $1`, p.OrgID, req.Auth0OrgID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpError{409, "that Auth0 organization is linked to another org"}
			}
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "org.link_auth0", "org", p.OrgID, req)
	})
	return map[string]string{"auth0_org_id": req.Auth0OrgID}, err
}

func (s *Server) apiCreateTeam(r *http.Request, p principal) (any, error) {
	var req struct {
		Slug       string `json:"slug"`
		Name       string `json:"name"`
		Auth0Group string `json:"auth0_group"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if !slugRe.MatchString(req.Slug) {
		return nil, httpError{400, "slug must match " + slugRe.String()}
	}
	if req.Name == "" {
		req.Name = req.Slug
	}
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`INSERT INTO teams (id, org_id, slug, name, auth0_group) VALUES ($1,$2,$3,$4,NULLIF($5,''))`,
			id, p.OrgID, req.Slug, req.Name, req.Auth0Group); err != nil {
			if db.IsUniqueViolation(err) {
				return httpError{409, "a team with that slug or Auth0 group already exists"}
			}
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "team.create", "team", id, req)
	})
	return map[string]string{"id": ids.Encode("team", id), "slug": req.Slug}, err
}

func (s *Server) apiListTeams(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT t.slug, t.name, COALESCE(t.auth0_group,''), count(m.user_id)
			FROM teams t LEFT JOIN team_members m ON m.team_id = t.id
			WHERE t.archived_at IS NULL GROUP BY t.id ORDER BY t.slug`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var slug, name, group string
			var n int
			rows.Scan(&slug, &name, &group, &n)
			out = append(out, map[string]any{"slug": slug, "name": name, "auth0_group": group, "members": n})
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) apiAddTeamMember(r *http.Request, p principal) (any, error) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		teamID, err := s.teamIDBySlug(tx, r.PathValue("slug"))
		if err != nil {
			return err
		}
		var userID string
		if err := tx.QueryRow(`SELECT id FROM nfx_org_user_by_email($1)`, req.Email).Scan(&userID); err != nil {
			return httpError{404, "no member with that email has logged in yet"}
		}
		if _, err := tx.Exec(`INSERT INTO team_members (org_id, team_id, user_id, source) VALUES ($1,$2,$3,'manual')
			ON CONFLICT (org_id, team_id, user_id) DO UPDATE SET source = 'manual'`, p.OrgID, teamID, userID); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "team.member_add", "team", teamID, map[string]string{"user": userID})
	})
	return map[string]bool{"ok": err == nil}, err
}

func (s *Server) teamIDBySlug(tx *db.Tx, slug string) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT id FROM teams WHERE slug = $1 AND archived_at IS NULL`, slug).Scan(&id)
	if isNoRows(err) {
		return "", httpError{404, "no team " + slug}
	}
	return id, err
}

func (s *Server) apiListMembers(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT id, email, name, status FROM nfx_org_users() ORDER BY email`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, email, name, status string
			rows.Scan(&id, &email, &name, &status)
			out = append(out, map[string]any{"id": ids.Encode("usr", id), "email": email, "name": name, "status": status})
		}
		return rows.Err()
	})
	return out, err
}

// apiCreateBinding grants a role, optionally scoped, to a user (by email),
// a team (by slug) or an API key (by id).
func (s *Server) apiCreateBinding(r *http.Request, p principal) (any, error) {
	var req struct {
		SubjectType string `json:"subject_type"`
		Subject     string `json:"subject"`
		Role        string `json:"role"`
		Scope       Scope  `json:"scope"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if _, ok := roleRank[req.Role]; !ok {
		return nil, httpError{400, "role must be owner, admin, responder or viewer"}
	}
	// Only owners can mint owners or admins, so an admin can't escalate.
	if roleRank[req.Role] >= roleRank["admin"] {
		if err := p.atLeast("owner"); err != nil {
			return nil, httpError{403, "only an owner can grant the " + req.Role + " role"}
		}
	}
	if req.Role == "owner" && !req.Scope.empty() {
		return nil, httpError{400, "the owner role is always org-wide"}
	}
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var subjectID string
		var err error
		switch req.SubjectType {
		case "user":
			err = tx.QueryRow(`SELECT id FROM nfx_org_user_by_email($1)`, req.Subject).Scan(&subjectID)
			if err != nil {
				return httpError{404, "no member with that email has logged in yet"}
			}
		case "team":
			if subjectID, err = s.teamIDBySlug(tx, req.Subject); err != nil {
				return err
			}
		case "api_key":
			if subjectID, err = ids.Decode("key", req.Subject); err != nil {
				return httpError{400, "api_key subjects are key ids (key_…)"}
			}
		default:
			return httpError{400, "subject_type must be user, team or api_key"}
		}
		if _, err := tx.Exec(`INSERT INTO role_bindings (id, org_id, subject_type, subject_id, role, scope, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, p.OrgID, req.SubjectType, subjectID, req.Role,
			db.JSON[Scope]{V: Scope{Teams: sortedCopy(req.Scope.Teams), Tags: sortedCopy(req.Scope.Tags), Env: sortedCopy(req.Scope.Env)}},
			p.actor()); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "role_binding.create", "role_binding", id, req)
	})
	return map[string]string{"id": ids.Encode("rb", id), "scope": req.Scope.String()}, err
}

func (s *Server) apiListBindings(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT b.id, b.subject_type, b.role, b.scope,
				COALESCE(t.slug, u.email, b.subject_id::text)
			FROM role_bindings b
			LEFT JOIN teams t ON b.subject_type = 'team' AND t.id = b.subject_id
			LEFT JOIN nfx_org_users() u ON b.subject_type = 'user' AND u.id = b.subject_id
			ORDER BY b.created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, st, role, subj string
			var sc db.JSON[Scope]
			rows.Scan(&id, &st, &role, &sc, &subj)
			out = append(out, map[string]any{"id": ids.Encode("rb", id), "subject_type": st, "subject": subj,
				"role": role, "scope": sc.V})
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) apiDeleteBinding(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("rb", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "not found"}
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		var role string
		if err := tx.QueryRow(`SELECT role FROM role_bindings WHERE id = $1`, id).Scan(&role); err != nil {
			return err
		}
		if roleRank[role] >= roleRank["admin"] {
			if err := p.atLeast("owner"); err != nil {
				return httpError{403, "only an owner can remove an " + role + " binding"}
			}
		}
		if _, err := tx.Exec(`DELETE FROM role_bindings WHERE id = $1`, id); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "role_binding.delete", "role_binding", id, nil)
	})
	return map[string]bool{"ok": err == nil}, err
}
