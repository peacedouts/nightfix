-- Fix partition maintenance (QA round 2).
--
-- 1. 0006 put pg_catalog first on every SECURITY DEFINER function's
--    search_path. nfx_ensure_partitions created tables with unqualified
--    names, which now resolved to pg_catalog and failed, so no partition was
--    created after the ones 0001 made at migrate time: alert ingest and step
--    output would have started failing four days after migrating. Every
--    object is now schema-qualified.
-- 2. Bounds were bare dates, read in the session's TimeZone, so a worker in
--    a different timezone from the migrator created overlapping partitions
--    (which aborted maintenance for good) or left hours-long gaps. Bounds
--    are now computed in UTC, and each new partition starts exactly where
--    the latest existing one ends, so partitions made earlier under another
--    timezone stay contiguous with new ones.
-- 3. Concurrent instances serialize on an advisory lock instead of racing.
-- 4. Expiry is decided by a partition's upper bound, not by parsing its name.
-- 5. New partitions get the owner-aware policy text PR #3 uses everywhere.

SET ROLE nfx_owner;

CREATE OR REPLACE FUNCTION nfx_partition_upper(p_rel oid) RETURNS timestamptz
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT (regexp_match(pg_get_expr(c.relpartbound, c.oid), 'TO \(''([^'']+)''\)'))[1]::timestamptz
  FROM pg_class c WHERE c.oid = p_rel
$$;

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
      -- Same policy text as PR #3's owner-aware policies (managed Postgres
      -- without BYPASSRLS). On a database where nfx_owner bypasses RLS the
      -- extra clause has no effect.
      EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING (org_id = public.nfx_org() OR current_user = ''nfx_owner'') WITH CHECK (org_id = public.nfx_org() OR current_user = ''nfx_owner'')', pname);
      EXECUTE format('GRANT SELECT, INSERT ON public.%I TO nfx_app', pname);
      IF t = 'alert_events' THEN
        EXECUTE format('GRANT UPDATE (processed_at, error) ON public.%I TO nfx_app', pname);
      END IF;
      hi := target;
    END LOOP;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION nfx_drop_expired_partitions(alert_event_days int DEFAULT 30, output_days int DEFAULT 90)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  r record;
  dropped int := 0;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('nfx_ensure_partitions', 0));
  FOR r IN
    SELECT c.relname, p.relname AS parent, nfx_partition_upper(c.oid) AS upper
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace ns ON ns.oid = p.relnamespace
    WHERE ns.nspname = 'public' AND p.relname IN ('alert_events','step_output_chunks')
  LOOP
    IF r.upper < now() - make_interval(days => CASE WHEN r.parent = 'alert_events' THEN alert_event_days ELSE output_days END) THEN
      EXECUTE format('DROP TABLE public.%I', r.relname);
      dropped := dropped + 1;
    END IF;
  END LOOP;
  RETURN dropped;
END $$;

RESET ROLE;
