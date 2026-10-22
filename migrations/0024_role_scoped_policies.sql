-- Tenant policies per role, so lookups can use the org indexes (final review).
--
-- Every tenant policy was "org_id = nfx_org() OR current_user = 'nfx_owner'"
-- (0002_z, 0013). Postgres can't use an index on org_id for a condition
-- with an OR, so each per-event lookup (an alert by fingerprint, an event by
-- id) scanned every org's rows, and alert processing slowed linearly as the
-- tables grew. Now there are two policies per table: tenant_isolation, for
-- nfx_app only, is "org_id = nfx_org()" (index-friendly), and tenant_owner
-- lets nfx_owner (the SECURITY DEFINER functions and migrations) see every
-- org, as the OR did. nfx_app still sees only its org.
--
-- New tenant tables need both policies (see nfx_ensure_partitions below for
-- the shape). internal/db tests check every RLS table.
--
-- Also: an index for the incident's runs (verified marking, reopen), and one
-- on alert_events.id, whose primary key starts with received_at.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

DO $$
DECLARE r record; col text;
BEGIN
  FOR r IN SELECT tablename FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation' LOOP
    col := CASE WHEN r.tablename = 'orgs' THEN 'id' ELSE 'org_id' END;
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I TO nfx_app USING (%I = public.nfx_org()) WITH CHECK (%I = public.nfx_org())',
                   r.tablename, col, col);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = r.tablename AND policyname = 'tenant_owner') THEN
      EXECUTE format('CREATE POLICY tenant_owner ON public.%I TO nfx_owner USING (true) WITH CHECK (true)', r.tablename);
    END IF;
  END LOOP;
END $$;

-- As in 0011, with the two policies.
CREATE OR REPLACE FUNCTION nfx_ensure_partitions(days_ahead int DEFAULT 3) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  t text;
  hi timestamptz;
  today date := (now() AT TIME ZONE 'UTC')::date;
  target timestamptz;
  lo timestamptz;
  pname text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('nfx_ensure_partitions', 0));
  FOREACH t IN ARRAY ARRAY['alert_events','step_output_chunks'] LOOP
    SELECT max(nfx_partition_upper(i.inhrelid)) INTO hi
    FROM pg_inherits i WHERE i.inhparent = format('public.%I', t)::regclass;
    FOR n IN -1..days_ahead LOOP
      target := ((today + n + 1)::timestamp AT TIME ZONE 'UTC');
      IF hi IS NOT NULL AND hi >= target THEN
        CONTINUE;
      END IF;
      lo := coalesce(hi, target - interval '1 day');
      pname := format('%s_%s', t, to_char(target AT TIME ZONE 'UTC' - interval '1 day', 'YYYYMMDD'));
      IF to_regclass(format('public.%I', pname)) IS NOT NULL THEN
        pname := pname || '_' || to_char(lo AT TIME ZONE 'UTC', 'HH24MI');
      END IF;
      EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)', pname, t, lo, target);
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', pname);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', pname);
      EXECUTE format('CREATE POLICY tenant_isolation ON public.%I TO nfx_app USING (org_id = public.nfx_org()) WITH CHECK (org_id = public.nfx_org())', pname);
      EXECUTE format('CREATE POLICY tenant_owner ON public.%I TO nfx_owner USING (true) WITH CHECK (true)', pname);
      EXECUTE format('GRANT SELECT, INSERT ON public.%I TO nfx_app', pname);
      IF t = 'alert_events' THEN
        EXECUTE format('GRANT UPDATE (processed_at, error) ON public.%I TO nfx_app', pname);
      END IF;
      hi := target;
    END LOOP;
  END LOOP;
END $$;
REVOKE EXECUTE ON FUNCTION nfx_ensure_partitions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nfx_ensure_partitions(int) TO nfx_app;

CREATE INDEX runbook_runs_incident ON runbook_runs (org_id, incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX alert_events_id ON alert_events (org_id, id);

RESET ROLE;
