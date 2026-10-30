package controlplane

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// API keys: an org starts with one owner key (CreateOrg). These endpoints let
// an admin issue more, list them and revoke them, so a leaked key can be
// replaced without touching the database. Keys are shown once and stored as
// a SHA-256 hash; revoking one takes effect on its next request.
func (s *Server) apiKeyRoutes(route routeFn) {
	route("POST /v1/api-keys", "admin", s.apiCreateAPIKey)
	route("GET /v1/api-keys", "admin", s.apiListAPIKeys)
	route("POST /v1/api-keys/{id}/revoke", "admin", s.apiRevokeAPIKey)
}

func (s *Server) apiCreateAPIKey(r *http.Request, p principal) (any, error) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		return nil, httpError{400, "name is required (at most 100 characters)"}
	}
	if _, ok := roleRank[req.Role]; !ok {
		return nil, httpError{400, "role must be owner, admin, responder or viewer"}
	}
	// As with role bindings: only owners can mint owner or admin keys, so an
	// admin can't escalate.
	if roleRank[req.Role] >= roleRank["admin"] {
		if err := p.atLeast("owner"); err != nil {
			return nil, httpError{403, "only an owner can create a key with the " + req.Role + " role"}
		}
	}
	key, prefix, hash := newSecret("nfx")
	id := ids.NewString()
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if _, err := tx.Exec(`INSERT INTO api_keys (id, org_id, name, prefix, hash, role) VALUES ($1,$2,$3,$4,$5,$6)`,
			id, p.OrgID, req.Name, prefix, hash, req.Role); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "api_key.create", "api_key", id,
			map[string]string{"name": req.Name, "role": req.Role, "prefix": prefix})
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"id": ids.Encode("key", id), "name": req.Name, "role": req.Role, "prefix": prefix,
		"key": key, "note": "shown once; store it now"}, nil
}

func (s *Server) apiListAPIKeys(r *http.Request, p principal) (any, error) {
	out := []map[string]any{}
	err := s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`SELECT id, name, prefix, role, created_at, revoked_at FROM api_keys ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name, prefix, role string
			var created time.Time
			var revoked *time.Time
			if err := rows.Scan(&id, &name, &prefix, &role, &created, &revoked); err != nil {
				return err
			}
			k := map[string]any{"id": ids.Encode("key", id), "name": name, "prefix": prefix, "role": role, "created_at": created}
			if revoked != nil {
				k["revoked_at"] = *revoked
			}
			if id == p.KeyID {
				k["current"] = true
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return map[string]any{"keys": out}, err
}

func (s *Server) apiRevokeAPIKey(r *http.Request, p principal) (any, error) {
	id, err := ids.Decode("key", r.PathValue("id"))
	if err != nil {
		return nil, httpError{404, "no such API key"}
	}
	err = s.DB.WithOrg(r.Context(), p.OrgID, func(tx *db.Tx) error {
		if err := lockOwners(tx); err != nil {
			return err
		}
		var role string
		var revoked *time.Time
		var bindOwner, bindAdmin bool
		if err := tx.QueryRow(`SELECT k.role, k.revoked_at,
				EXISTS (SELECT 1 FROM role_bindings b WHERE b.subject_type = 'api_key' AND b.subject_id = k.id AND b.role = 'owner'),
				EXISTS (SELECT 1 FROM role_bindings b WHERE b.subject_type = 'api_key' AND b.subject_id = k.id AND b.role = 'admin')
			FROM api_keys k WHERE k.id = $1 FOR UPDATE OF k`, id).Scan(&role, &revoked, &bindOwner, &bindAdmin); err != nil {
			if isNoRows(err) {
				return httpError{404, "no such API key"}
			}
			return err
		}
		// What the key can do: its own role, or more through a binding.
		switch {
		case bindOwner:
			role = "owner"
		case bindAdmin && roleRank[role] < roleRank["admin"]:
			role = "admin"
		}
		if revoked != nil {
			return nil // already revoked
		}
		if roleRank[role] >= roleRank["admin"] {
			if err := p.atLeast("owner"); err != nil {
				return httpError{403, "only an owner can revoke a key with the " + role + " role"}
			}
		}
		if role == "owner" {
			if err := s.lastOwnerCheck(tx, id, ""); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE api_keys SET revoked_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		return tx.Audit(r.Context(), p.actorType(), p.actor(), "api_key.revoke", "api_key", id, map[string]string{"role": role})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": ids.Encode("key", id), "revoked": true}, nil
}

// lockOwners serializes the changes that can remove an owner credential
// (revoking a key, deleting a binding), so two of them can't each leave the
// other as the last one and both pass. Call it first in the transaction.
func lockOwners(tx *db.Tx) error {
	_, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended('nfx_owners:' || $1, 0))`, tx.OrgID)
	return err
}

// lastOwnerCheck refuses to remove the org's last usable owner credential
// (without one, only an operator could recover the org). It counts what
// someone can actually use, leaving out the key or binding being removed:
// unrevoked keys that are owners by role or binding, and, when the org's
// members can sign in (Auth0 linked, or the org generic OIDC maps to),
// owner bindings of active members or of teams with an active member. An
// owner binding to an empty team doesn't count.
func (s *Server) lastOwnerCheck(tx *db.Tx, exceptKey, exceptBinding string) error {
	users, err := s.usersCanSignIn(tx)
	if err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(`
		SELECT (SELECT count(*) FROM api_keys k
		        WHERE k.revoked_at IS NULL AND k.id IS DISTINCT FROM $1::uuid
		          AND (k.role = 'owner' OR EXISTS (SELECT 1 FROM role_bindings b WHERE b.subject_type = 'api_key'
		               AND b.subject_id = k.id AND b.role = 'owner' AND b.id IS DISTINCT FROM $2::uuid)))
		     + CASE WHEN $3::boolean THEN
		         (SELECT count(*) FROM role_bindings b JOIN org_members m ON m.user_id = b.subject_id AND m.status = 'active'
		          WHERE b.subject_type = 'user' AND b.role = 'owner' AND b.id IS DISTINCT FROM $2::uuid)
		       + (SELECT count(*) FROM role_bindings b
		          WHERE b.subject_type = 'team' AND b.role = 'owner' AND b.id IS DISTINCT FROM $2::uuid
		            AND EXISTS (SELECT 1 FROM team_members tm JOIN org_members m ON m.user_id = tm.user_id AND m.status = 'active'
		                        WHERE tm.team_id = b.subject_id))
		       ELSE 0 END`, nullable(exceptKey), nullable(exceptBinding), users).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return httpError{409, "this is the org's last owner credential; create another owner key (or owner binding) first, then remove this one"}
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// NewOwnerKey issues a new owner key for an org. It's the operator's
// recovery path (nightfix org new-owner-key) when an org has lost or leaked
// its owner key; after the key has been handed over, RevokeOtherKeys revokes
// the rest.
func (s *Server) NewOwnerKey(ctx context.Context, orgID, actor string) (key, keyID, slug string, err error) {
	key, prefix, hash := newSecret("nfx")
	keyID = ids.NewString()
	err = s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		if err := tx.QueryRow(`SELECT slug FROM orgs WHERE id = $1`, orgID).Scan(&slug); err != nil {
			if isNoRows(err) {
				return httpError{404, "no such org"}
			}
			return err
		}
		if _, err := tx.Exec(`INSERT INTO api_keys (id, org_id, name, prefix, hash, role) VALUES ($1,$2,'operator-issued owner key',$3,$4,'owner')`,
			keyID, orgID, prefix, hash); err != nil {
			return err
		}
		return tx.Audit(ctx, "operator", actor, "api_key.create", "api_key", keyID, map[string]any{"role": "owner", "prefix": prefix})
	})
	return key, keyID, slug, err
}

// RevokeOtherKeys revokes every key of the org except keep (the response to
// a leaked key, once the new one is safely stored).
func (s *Server) RevokeOtherKeys(ctx context.Context, orgID, keep, actor string) (int, error) {
	var n int64
	err := s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		res, err := tx.Exec(`UPDATE api_keys SET revoked_at = now() WHERE revoked_at IS NULL AND id <> $1`, keep)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return tx.Audit(ctx, "operator", actor, "api_key.revoke_all", "org", orgID, map[string]any{"kept": ids.Encode("key", keep), "revoked": n})
	})
	return int(n), err
}
