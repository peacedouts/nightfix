-- Only verified emails identify people (QA follow-up).
--
-- Auth0 can issue a token for an email nobody has verified (a database or
-- social connection where anyone may sign up), and emails are how admins
-- name people in role bindings and team membership. Login now refuses a
-- token whose email isn't verified, so such a user never becomes a member,
-- and users.email_verified records what the IdP said at the last login.
-- Email lookups match verified users only, and a member whose email isn't
-- verified can't link or act through Slack.
--
-- Users who signed in before this change are unverified until their next
-- sign-in refreshes the flag.
--
-- The three functions below are 0002's definitions with the search_path
-- 0006 set on every SECURITY DEFINER function, plus email_verified.

SET ROLE nfx_owner;

ALTER TABLE users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;

-- Takes the verification flag now. The old signature is dropped rather than
-- kept, so nothing can provision a user without saying whether the email
-- was verified.
DROP FUNCTION nfx_upsert_user(text, text, text);
CREATE FUNCTION nfx_upsert_user(p_sub text, p_email text, p_name text, p_email_verified boolean)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_id uuid;
BEGIN
  INSERT INTO users (id, auth0_sub, email, name, email_verified, last_login_at)
  VALUES (gen_random_uuid(), p_sub, p_email, coalesce(p_name, ''), p_email_verified, now())
  ON CONFLICT (auth0_sub) DO UPDATE
    SET email = EXCLUDED.email, name = EXCLUDED.name, email_verified = EXCLUDED.email_verified, last_login_at = now()
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;

-- Members of the current org only. Returns email_verified as well, so the
-- return type changes: drop and recreate.
DROP FUNCTION nfx_org_users();
CREATE FUNCTION nfx_org_users()
RETURNS TABLE (id uuid, email text, name text, status text, last_login_at timestamptz, email_verified boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT u.id, u.email, u.name, m.status, u.last_login_at, u.email_verified
  FROM users u JOIN org_members m ON m.user_id = u.id
  WHERE m.org_id = nfx_org()
$$;

-- Unverified emails never match.
CREATE OR REPLACE FUNCTION nfx_org_user_by_email(p_email text)
RETURNS TABLE (id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT u.id FROM users u JOIN org_members m ON m.user_id = u.id
  WHERE m.org_id = nfx_org() AND m.status = 'active' AND u.email_verified AND lower(u.email) = lower(p_email)
$$;

GRANT EXECUTE ON FUNCTION
  nfx_upsert_user(text, text, text, boolean), nfx_org_users(), nfx_org_user_by_email(text)
TO nfx_app;

RESET ROLE;
