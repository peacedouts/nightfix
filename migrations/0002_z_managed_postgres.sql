-- Run on managed Postgres (RDS, Aurora): no BYPASSRLS for the owner.
--
-- Managed Postgres has no superuser, and Postgres 16 lets only a role that
-- itself has BYPASSRLS create one, so nfx_owner can't have it there. The
-- SECURITY DEFINER functions nfx_owner owns (routing, claims, audit) still
-- need to see every org, so the policies admit it explicitly instead.
-- Nothing logs in as nfx_owner; nfx_app still sees only the current org, and
-- still gets an error, not an empty result, when no org is set.
--
-- The odd name is deliberate. Migrations apply in name order, and this must
-- run after 0002 but before 0003: 0003 adds foreign keys whose validation
-- runs as nfx_owner under RLS, which fails on a fresh RDS database unless
-- the owner is admitted first. Databases already migrated from main pick it
-- up as an unapplied file, which is harmless (every statement is idempotent).
-- 0013 repeats the policy change for tables created after this point.

SET ROLE nfx_owner;

-- The app role errors without an org (a code path that forgot to scope
-- itself fails loudly); the owner gets NULL, so its policies fall through
-- to the explicit owner clause.
CREATE OR REPLACE FUNCTION nfx_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN current_user = 'nfx_owner' THEN nullif(current_setting('app.org_id', true), '')::uuid
              ELSE current_setting('app.org_id')::uuid END
$$;

DO $$
DECLARE r record; col text;
BEGIN
  FOR r IN SELECT tablename FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation' LOOP
    col := CASE WHEN r.tablename = 'orgs' THEN 'id' ELSE 'org_id' END;
    EXECUTE format('ALTER POLICY tenant_isolation ON %I USING (%I = nfx_org() OR current_user = %L) WITH CHECK (%I = nfx_org() OR current_user = %L)',
                   r.tablename, col, 'nfx_owner', col, 'nfx_owner');
  END LOOP;
  -- Reached only through nfx_create_enroll_challenge / nfx_consume_enroll_challenge.
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'enrollment_challenges' AND policyname = 'owner_only') THEN
    CREATE POLICY owner_only ON enrollment_challenges USING (current_user = 'nfx_owner') WITH CHECK (current_user = 'nfx_owner');
  END IF;
END $$;

RESET ROLE;
