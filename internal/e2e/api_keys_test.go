package e2e_test

// API key management: a leaked key can be replaced and revoked through the
// API, roles can't be escalated, and an org can't lock itself out by
// revoking its last owner credential. The operator path (NewOwnerKey) can
// revoke everything and issue a fresh owner key.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

func TestAPIKeyLifecycle(t *testing.T) {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{}, log)
	api := httptest.NewServer(srv.APIHandler())
	defer api.Close()
	ctx := context.Background()
	org, err := srv.CreateOrg(ctx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := srv.CreateOrg(ctx, "Other", "other")

	do := func(tok, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, api.URL+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		json.Unmarshal(raw, &out)
		if out == nil || len(out) == 0 {
			out = map[string]any{"raw": string(raw)}
		}
		return resp.StatusCode, out
	}
	mint := func(tok, name, role string) (int, string, string) {
		t.Helper()
		code, out := do(tok, "POST", "/v1/api-keys", map[string]string{"name": name, "role": role})
		key, _ := out["key"].(string)
		id, _ := out["id"].(string)
		return code, key, id
	}
	owner := org.APIKey

	// An owner mints an admin key; the admin can mint responder and viewer
	// keys but not admin or owner ones (no escalation).
	code, admin, adminID := mint(owner, "ci", "admin")
	if code != 200 || !strings.HasPrefix(admin, "nfx_") || !strings.HasPrefix(adminID, "key_") {
		t.Fatalf("owner minting an admin key: %d %q %q", code, admin, adminID)
	}
	if code, _, _ := mint(admin, "escalate", "owner"); code != 403 {
		t.Fatalf("admin minting an owner key: %d, want 403", code)
	}
	if code, _, _ := mint(admin, "escalate", "admin"); code != 403 {
		t.Fatalf("admin minting an admin key: %d, want 403", code)
	}
	code, viewer, viewerID := mint(admin, "dashboards", "viewer")
	if code != 200 {
		t.Fatalf("admin minting a viewer key: %d", code)
	}
	if code, _ := do(viewer, "GET", "/v1/me", nil); code != 200 {
		t.Fatalf("new viewer key doesn't authenticate: %d", code)
	}
	if code, _, _ := mint(viewer, "x", "viewer"); code != 403 {
		t.Fatalf("viewer minting a key: %d, want 403", code)
	}
	if code, _, _ := mint(owner, "", "viewer"); code != 400 {
		t.Fatalf("key without a name: %d, want 400", code)
	}
	if code, _, _ := mint(owner, "x", "superuser"); code != 400 {
		t.Fatalf("unknown role: %d, want 400", code)
	}

	// The list shows every key without its secret, and marks the caller's.
	code, list := do(owner, "GET", "/v1/api-keys", nil)
	keys, _ := list["keys"].([]any)
	if code != 200 || len(keys) != 3 {
		t.Fatalf("list: %d %v", code, list)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), admin) || strings.Contains(string(raw), viewer) || strings.Contains(string(raw), owner) {
		t.Fatal("the list returns key secrets")
	}
	current := 0
	for _, k := range keys {
		if k.(map[string]any)["current"] == true {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("list marks %d keys as the caller's, want 1", current)
	}

	// Another org can't see or revoke these keys.
	if code, _ := do(other.APIKey, "POST", "/v1/api-keys/"+viewerID+"/revoke", nil); code != 404 {
		t.Fatalf("another org revoking a key: %d, want 404", code)
	}
	if code, l := do(other.APIKey, "GET", "/v1/api-keys", nil); code != 200 || len(l["keys"].([]any)) != 1 {
		t.Fatalf("another org's list: %d %v", code, l)
	}

	// An admin can't revoke the owner key; revoking the viewer key stops it
	// at once, and revoking again is a no-op.
	ownerID := ""
	for _, k := range keys {
		if m := k.(map[string]any); m["role"] == "owner" {
			ownerID = m["id"].(string)
		}
	}
	if code, _ := do(admin, "POST", "/v1/api-keys/"+ownerID+"/revoke", nil); code != 403 {
		t.Fatalf("admin revoking the owner key: %d, want 403", code)
	}
	if code, _ := do(admin, "POST", "/v1/api-keys/"+viewerID+"/revoke", nil); code != 200 {
		t.Fatalf("revoking the viewer key: %d", code)
	}
	if code, _ := do(viewer, "GET", "/v1/me", nil); code != 401 {
		t.Fatalf("revoked key still authenticates: %d, want 401", code)
	}
	if code, _ := do(admin, "POST", "/v1/api-keys/"+viewerID+"/revoke", nil); code != 200 {
		t.Fatalf("revoking twice: %d, want 200", code)
	}
	if code, _ := do(admin, "POST", "/v1/api-keys/key_nonsense/revoke", nil); code != 404 {
		t.Fatalf("revoking a malformed id: %d, want 404", code)
	}

	// The org's only owner credential can't be revoked; rotating (new owner
	// key first, then revoke the old one with it) works.
	if code, out := do(owner, "POST", "/v1/api-keys/"+ownerID+"/revoke", nil); code != 409 {
		t.Fatalf("revoking the last owner key: %d %v, want 409", code, out)
	}
	code, owner2, _ := mint(owner, "rotated owner", "owner")
	if code != 200 {
		t.Fatalf("minting a second owner key: %d", code)
	}
	if code, _ := do(owner2, "POST", "/v1/api-keys/"+ownerID+"/revoke", nil); code != 200 {
		t.Fatalf("rotating out the old owner key: %d", code)
	}
	if code, _ := do(owner, "GET", "/v1/me", nil); code != 401 {
		t.Fatalf("rotated-out owner key still works: %d", code)
	}

	// Operator recovery after a leak: revoke everything, issue a new owner key.
	orgID := org.OrgID
	if _, err := ids.Decode("org", ids.Encode("org", orgID)); err != nil {
		t.Fatal(err)
	}
	fresh, freshID, slug, err := srv.NewOwnerKey(ctx, orgID, "test")
	if err != nil || slug != "acme" {
		t.Fatalf("NewOwnerKey: %q %v", slug, err)
	}
	revoked, err := srv.RevokeOtherKeys(ctx, orgID, freshID, "test")
	if err != nil || revoked != 2 {
		t.Fatalf("RevokeOtherKeys: %d %v (want 2: owner2 and admin)", revoked, err)
	}
	for name, k := range map[string]string{"admin": admin, "owner2": owner2} {
		if code, _ := do(k, "GET", "/v1/me", nil); code != 401 {
			t.Fatalf("%s key works after operator revoke-all: %d", name, code)
		}
	}
	if code, _ := do(fresh, "GET", "/v1/me", nil); code != 200 {
		t.Fatalf("operator-issued key doesn't work: %d", code)
	}

	// Every change is audited, and audit metadata never holds a secret.
	code, audit := do(fresh, "GET", "/v1/audit-events", nil)
	ab, _ := json.Marshal(audit)
	for _, want := range []string{"api_key.create", "api_key.revoke"} {
		if code != 200 || !strings.Contains(string(ab), want) {
			t.Fatalf("audit log lacks %s: %d %s", want, code, ab)
		}
	}
	for _, secret := range []string{admin, viewer, owner2, fresh} {
		if strings.Contains(string(ab), secret) {
			t.Fatal("a key secret is in the audit log")
		}
	}
}
