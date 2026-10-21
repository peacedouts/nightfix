-- Hardening found in QA review.
--
-- 1. SECURITY DEFINER functions searched pg_temp first (Postgres puts it
--    ahead of the listed schemas unless it's named), so any app session
--    could create a temp table such as api_keys or audit_events and have a
--    privileged function read or write it instead of the real one. pg_temp
--    is now named last on every SECURITY DEFINER function. New functions
--    must use the same setting; internal/db tests check it.
--
-- 2. The audit hash covered `at::text`, which renders in the session's
--    TimeZone and DateStyle, so one connection with a different timezone
--    reported every org's chain as broken. New events (hash_version 2) hash
--    a fixed UTC rendering. Existing events keep version 1 and are verified
--    as before, so the chain stays intact across the change.

SET ROLE nfx_owner;

DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.prosecdef LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
  END LOOP;
END $$;

ALTER TABLE audit_events ADD COLUMN hash_version smallint NOT NULL DEFAULT 1;

-- A rendering of an instant that no session setting can change.
CREATE FUNCTION nfx_audit_ts(p_at timestamptz) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

CREATE OR REPLACE FUNCTION nfx_audit(p_actor_type text, p_actor_id text, p_action text,
                          p_resource_type text, p_resource_id text, p_data jsonb)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  v_org uuid := nfx_org();
  v_seq bigint;
  v_prev bytea;
  v_hash bytea;
  v_at timestamptz := clock_timestamp();
BEGIN
  INSERT INTO org_counters (org_id, name, value) VALUES (v_org, 'audit', 0)
  ON CONFLICT (org_id, name) DO NOTHING;
  UPDATE org_counters SET value = value + 1 WHERE org_id = v_org AND name = 'audit'
  RETURNING value INTO v_seq;
  SELECT hash INTO v_prev FROM audit_events WHERE org_id = v_org AND seq = v_seq - 1;
  v_hash := sha256(
    coalesce(v_prev, ''::bytea) ||
    convert_to(concat_ws('|', v_org::text, v_seq::text, nfx_audit_ts(v_at), p_actor_type, p_actor_id,
                         p_action, p_resource_type, p_resource_id, coalesce(p_data, '{}'::jsonb)::text), 'UTF8'));
  INSERT INTO audit_events (org_id, seq, at, actor_type, actor_id, action, resource_type, resource_id, data, prev_hash, hash, hash_version)
  VALUES (v_org, v_seq, v_at, p_actor_type, p_actor_id, p_action, p_resource_type, p_resource_id, coalesce(p_data, '{}'::jsonb), v_prev, v_hash, 2);
  RETURN v_seq;
END $$;

CREATE OR REPLACE FUNCTION nfx_verify_audit_chain()
RETURNS bigint LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  r record;
  v_prev bytea := NULL;
  v_expect bigint := 1;
BEGIN
  FOR r IN SELECT * FROM audit_events WHERE org_id = nfx_org() ORDER BY seq LOOP
    IF r.seq <> v_expect OR r.prev_hash IS DISTINCT FROM v_prev OR r.hash <> sha256(
         coalesce(v_prev, ''::bytea) ||
         convert_to(concat_ws('|', r.org_id::text, r.seq::text,
                              CASE WHEN r.hash_version >= 2 THEN nfx_audit_ts(r.at) ELSE r.at::text END,
                              r.actor_type, r.actor_id, r.action, r.resource_type, r.resource_id, r.data::text), 'UTF8')) THEN
      RETURN r.seq;
    END IF;
    v_prev := r.hash;
    v_expect := v_expect + 1;
  END LOOP;
  RETURN NULL;
END $$;

RESET ROLE;
