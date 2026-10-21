-- Only nfx_app may call the SECURITY DEFINER functions.
--
-- Postgres grants EXECUTE on new functions to PUBLIC by default, and no
-- migration revoked it, so any role that could log in (including one with
-- no grants at all) could call them: nfx_drop_expired_partitions(-2, -2)
-- dropped current partitions for every org, and nfx_create_org created
-- orgs. nfx_app's explicit grants (0001, 0002, 0003, 0007, 0014, 0016, 0017) are
-- unchanged.
--
-- nfx_drop_expired_partitions also clamps its arguments, so even nfx_app
-- (say, through an injection) can't use it to drop recent data.

SET ROLE nfx_owner;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE nfx_owner IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- As in 0011, with retention floors.
CREATE OR REPLACE FUNCTION nfx_drop_expired_partitions(alert_event_days int DEFAULT 30, output_days int DEFAULT 90)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  r record;
  dropped int := 0;
BEGIN
  alert_event_days := greatest(alert_event_days, 30);
  output_days := greatest(output_days, 90);
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
