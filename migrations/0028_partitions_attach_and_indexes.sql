-- Partition maintenance no longer blocks ingest; two lookups that scanned
-- history get indexes (limits review).
--
-- nfx_ensure_partitions created partitions with CREATE TABLE ... PARTITION
-- OF, which takes ACCESS EXCLUSIVE on the parent: queued behind any open
-- alert-processing transaction, it blocked every org's ingest until it timed
-- out, and partitions (made only 3 days ahead) could run out. It now creates
-- each partition on its own and attaches it, which takes SHARE UPDATE
-- EXCLUSIVE on the parent and doesn't conflict with inserts or reads. RLS,
-- policies and grants are set before the partition is attached. The worker
-- also creates partitions further ahead and retries failures soon (Go side).
--
-- Indexes: incident_alerts by alert (the reopen lookup on every re-fire
-- scanned the org's incident history), and enrollment_challenges by expiry
-- (each unauthenticated challenge request deleted expired ones with a scan).
--
-- nfx_ensure_partitions starts from 0024's definition.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

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
      -- Created on its own and attached afterwards: ATTACH takes only SHARE
      -- UPDATE EXCLUSIVE on the parent, so ingest and open processing
      -- transactions carry on (PARTITION OF takes ACCESS EXCLUSIVE).
      EXECUTE format('CREATE TABLE public.%I (LIKE public.%I INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', pname, t);
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', pname);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', pname);
      EXECUTE format('CREATE POLICY tenant_isolation ON public.%I TO nfx_app USING (org_id = public.nfx_org()) WITH CHECK (org_id = public.nfx_org())', pname);
      EXECUTE format('CREATE POLICY tenant_owner ON public.%I TO nfx_owner USING (true) WITH CHECK (true)', pname);
      EXECUTE format('GRANT SELECT, INSERT ON public.%I TO nfx_app', pname);
      IF t = 'alert_events' THEN
        EXECUTE format('GRANT UPDATE (processed_at, error) ON public.%I TO nfx_app', pname);
      END IF;
      EXECUTE format('ALTER TABLE public.%I ATTACH PARTITION public.%I FOR VALUES FROM (%L) TO (%L)', t, pname, lo, target);
      hi := target;
    END LOOP;
  END LOOP;
END $$;
REVOKE EXECUTE ON FUNCTION nfx_ensure_partitions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nfx_ensure_partitions(int) TO nfx_app;

CREATE INDEX incident_alerts_alert ON incident_alerts (org_id, alert_id, attached_at DESC);
CREATE INDEX enrollment_challenges_expiry ON enrollment_challenges (expires_at);

RESET ROLE;
