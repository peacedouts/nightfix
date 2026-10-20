-- Identity: users (global), org membership, teams, scoped role bindings,
-- the Auth0 org link, and single-use challenges for IAM agent enrollment.

SET ROLE nfx_owner;

-- Users are global (one person can belong to several orgs). The app role has
-- no direct access to this table; it goes through the SECURITY DEFINER
-- functions below, which only ever expose members of the current org.
CREATE TABLE users (
  id          uuid PRIMARY KEY,
  auth0_sub   text NOT NULL UNIQUE,
  email       text NOT NULL,
  name        text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);
CREATE INDEX users_email ON users (lower(email));

ALTER TABLE orgs ADD COLUMN auth0_org_id text UNIQUE;

CREATE TABLE org_members (
  org_id      uuid NOT NULL REFERENCES orgs(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed')),
  joined_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE teams (
  id          uuid NOT NULL,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  slug        text NOT NULL,
  name        text NOT NULL,
  auth0_group text,             -- IdP group claim value mapped to this team
  archived_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, slug)
);
CREATE UNIQUE INDEX teams_auth0_group ON teams (org_id, auth0_group) WHERE auth0_group IS NOT NULL;

CREATE TABLE team_members (
  org_id   uuid NOT NULL,
  team_id  uuid NOT NULL,
  user_id  uuid NOT NULL REFERENCES users(id),
  source   text NOT NULL CHECK (source IN ('manual','idp')),
  added_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, team_id, user_id),
  FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id),
  FOREIGN KEY (org_id, user_id) REFERENCES org_members(org_id, user_id)
);

-- role → scope bindings (data-model.md §5). Empty scope fields mean "any".
CREATE TABLE role_bindings (
  id            uuid NOT NULL,
  org_id        uuid NOT NULL REFERENCES orgs(id),
  subject_type  text NOT NULL CHECK (subject_type IN ('user','team','api_key')),
  subject_id    uuid NOT NULL,
  role          text NOT NULL CHECK (role IN ('owner','admin','responder','viewer')),
  scope         jsonb NOT NULL DEFAULT '{}',
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);
CREATE INDEX role_bindings_subject ON role_bindings (org_id, subject_type, subject_id);

-- IAM enrollment: a nonce the agent must sign into its STS request.
CREATE TABLE enrollment_challenges (
  nonce_hash  bytea PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  expires_at  timestamptz NOT NULL
);

ALTER TABLE enrollment_rules ADD COLUMN role_name text;
ALTER TABLE enrollment_rules ADD CONSTRAINT enrollment_rules_iam_fields
  CHECK (method <> 'iam' OR (aws_account_id IS NOT NULL AND role_name IS NOT NULL));

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_members','teams','team_members','role_bindings'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nfx_org()) WITH CHECK (org_id = nfx_org())', t);
  END LOOP;
END $$;
-- Challenges are only reached through the functions below.
ALTER TABLE enrollment_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_challenges FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE ON org_members, teams, team_members TO nfx_app;
GRANT DELETE ON team_members TO nfx_app;
GRANT SELECT, INSERT, DELETE ON role_bindings TO nfx_app;

-- ---------------------------------------------------------------------------
-- Functions
-- ---------------------------------------------------------------------------

-- Map an Auth0 Organization to our org.
CREATE FUNCTION nfx_route_auth0_org(p_auth0_org text)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id FROM orgs o WHERE o.auth0_org_id = p_auth0_org
$$;

-- Create or refresh a user from a verified token. Returns the user id.
CREATE FUNCTION nfx_upsert_user(p_sub text, p_email text, p_name text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_id uuid;
BEGIN
  INSERT INTO users (id, auth0_sub, email, name, last_login_at)
  VALUES (gen_random_uuid(), p_sub, p_email, coalesce(p_name, ''), now())
  ON CONFLICT (auth0_sub) DO UPDATE
    SET email = EXCLUDED.email, name = EXCLUDED.name, last_login_at = now()
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;

-- Members of the current org only.
CREATE FUNCTION nfx_org_users()
RETURNS TABLE (id uuid, email text, name text, status text, last_login_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.id, u.email, u.name, m.status, u.last_login_at
  FROM users u JOIN org_members m ON m.user_id = u.id
  WHERE m.org_id = nfx_org()
$$;

CREATE FUNCTION nfx_org_user_by_email(p_email text)
RETURNS TABLE (id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.id FROM users u JOIN org_members m ON m.user_id = u.id
  WHERE m.org_id = nfx_org() AND m.status = 'active' AND lower(u.email) = lower(p_email)
$$;

-- Issue a challenge for an org that exists. The caller stores only the hash.
CREATE FUNCTION nfx_create_enroll_challenge(p_org uuid, p_nonce_hash bytea, p_ttl interval)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM orgs WHERE id = p_org AND frozen_at IS NULL) THEN
    RETURN false;
  END IF;
  DELETE FROM enrollment_challenges WHERE expires_at < now();
  INSERT INTO enrollment_challenges (nonce_hash, org_id, expires_at) VALUES (p_nonce_hash, p_org, now() + p_ttl);
  RETURN true;
END $$;

-- Consume a challenge exactly once; returns its org if still valid.
CREATE FUNCTION nfx_consume_enroll_challenge(p_nonce_hash bytea)
RETURNS TABLE (org_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM enrollment_challenges c WHERE c.nonce_hash = p_nonce_hash AND c.expires_at > now()
  RETURNING c.org_id
$$;

GRANT EXECUTE ON FUNCTION
  nfx_route_auth0_org(text), nfx_upsert_user(text, text, text), nfx_org_users(), nfx_org_user_by_email(text),
  nfx_create_enroll_challenge(uuid, bytea, interval), nfx_consume_enroll_challenge(bytea)
TO nfx_app;

RESET ROLE;
