-- Idempotency-Key on API writes (data-model.md §8.1; QA follow-up).
--
-- A POST or PUT carrying an Idempotency-Key is recorded per org, principal
-- (usr_… / key_…) and key. A retry within 24h gets the first response back
-- without running again; the same key with a different method, path or body
-- is refused. Request bodies are never stored, only their SHA-256. The
-- response body is sealed with the org's credential key, since some
-- responses carry a secret that is otherwise shown once.
--
-- The row is claimed (status NULL) before the request runs, so a concurrent
-- duplicate sees it in flight and is turned away instead of running too. A
-- claim whose request died is taken over after a lease (see idempotency.go).

SET ROLE nfx_owner;

CREATE TABLE idempotency_keys (
  org_id      uuid NOT NULL REFERENCES orgs(id),
  principal   text NOT NULL,
  key         text NOT NULL,
  method      text NOT NULL,
  path        text NOT NULL,
  body_hash   bytea NOT NULL,
  request_id  uuid NOT NULL,          -- the request holding the claim
  status      int,                    -- NULL while that request runs
  response    bytea,                  -- sealed response body
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (org_id, principal, key)
);
CREATE INDEX idempotency_keys_expiry ON idempotency_keys (expires_at);

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency_keys USING (org_id = nfx_org() OR current_user = 'nfx_owner') WITH CHECK (org_id = nfx_org() OR current_user = 'nfx_owner');

-- DELETE releases a claim whose request failed with a server error.
GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_keys TO nfx_app;

-- Delete keys past their 24h, across every org.
CREATE FUNCTION nfx_expire_idempotency_keys()
RETURNS int LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  WITH d AS (DELETE FROM idempotency_keys WHERE expires_at < now() RETURNING 1)
  SELECT count(*)::int FROM d
$$;
GRANT EXECUTE ON FUNCTION nfx_expire_idempotency_keys() TO nfx_app;

RESET ROLE;
