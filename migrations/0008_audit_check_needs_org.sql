-- 0006 redefined nfx_verify_audit_chain (timezone-stable hashing) from the
-- version before the managed-Postgres change, dropping its guard. Restore it:
-- without an org, the check refuses instead of reporting an empty chain as
-- intact. Same body as 0006 otherwise.

SET ROLE nfx_owner;

CREATE OR REPLACE FUNCTION nfx_verify_audit_chain()
RETURNS bigint LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  r record;
  v_prev bytea := NULL;
  v_expect bigint := 1;
BEGIN
  -- Runs as nfx_owner, where nfx_org() is NULL rather than an error when no
  -- org is set (managed Postgres has no BYPASSRLS; see 0001). An empty
  -- result must never read as "intact".
  IF nfx_org() IS NULL THEN
    RAISE EXCEPTION 'nfx_verify_audit_chain: no org set';
  END IF;
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
