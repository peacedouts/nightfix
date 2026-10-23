-- Ingest no longer waits for alert processing, and processing keeps up
-- with a continuously ingested org (reliability review, PR #25 review).
--
-- 0023 made the claim take the org's nfx_ingest lock exclusively and hold it
-- (a transaction-level lock) until the claimed event's processing committed.
-- Ingest takes the same lock shared, so while one of an org's events was
-- being processed, nothing new from that org could be stored; a slow
-- processing transaction stalled the org's ingest, and a burst of its
-- deliveries, each holding a pool connection while it waited, stopped every
-- org's ingest, processing and paging on the instance. It also used a
-- try-lock, which almost never succeeded while the org was being ingested
-- continuously (an alert storm): processing of that org nearly stopped.
--
-- The lock only has to be held while the claim picks the event: at that
-- moment no ingest of the org is mid-commit, so no older event can still
-- appear, and anything stored afterwards gets a later received_at. Now:
--   * the claim waits (up to 2s) for the org's in-flight ingests to commit;
--     Postgres queues new ingests behind the waiting claim, so it can't be
--     starved, and they wait only for that instant;
--   * the lock is session-level and released before the function returns,
--     including on error, cancellation and statement timeout (OTHERS
--     doesn't cover QUERY_CANCELED, so it's trapped by name);
--   * lock_timeout is changed only inside the block, so it reverts on its
--     own if the block fails.
-- Per-org serialization doesn't depend on the lock: an event is eligible
-- only when no older event of its org is unprocessed, and the oldest is
-- taken only if no other claim holds it, so two instances never process one
-- org's events at the same time or out of order.
--
-- Started from 0023's definition (rule: redefine from the latest).

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

CREATE OR REPLACE FUNCTION nfx_claim_alert_event()
RETURNS TABLE (org_id uuid, id uuid, received_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
#variable_conflict use_column
DECLARE
  v_skip uuid[] := '{}';
  v_org uuid;
  v_id uuid;
  v_at timestamptz;
  v_key bigint;
  v_lt text;
BEGIN
  FOR i IN 1..20 LOOP
    SELECT e.org_id INTO v_org FROM alert_events e
    WHERE e.processed_at IS NULL
      AND e.org_id <> ALL (v_skip)
      AND NOT EXISTS (
        SELECT 1 FROM alert_events o
        WHERE o.org_id = e.org_id AND o.processed_at IS NULL
          AND (o.received_at, o.id) < (e.received_at, e.id))
    ORDER BY e.received_at
    LIMIT 1
    FOR UPDATE OF e SKIP LOCKED;
    IF NOT FOUND THEN
      RETURN;
    END IF;
    v_key := hashtextextended('nfx_ingest:' || v_org::text, 0);
    v_id := NULL;
    v_lt := current_setting('lock_timeout');
    BEGIN
      PERFORM set_config('lock_timeout', '2s', true);
      PERFORM pg_advisory_lock(v_key);
      PERFORM set_config('lock_timeout', v_lt, true);
      -- An older event of this org may have committed since the first
      -- look: take the oldest, and only if no other claim is processing it.
      SELECT e.id, e.received_at INTO v_id, v_at FROM alert_events e
      WHERE e.processed_at IS NULL AND e.org_id = v_org
      ORDER BY e.received_at, e.id
      LIMIT 1;
      IF v_id IS NOT NULL THEN
        PERFORM 1 FROM alert_events e
        WHERE e.org_id = v_org AND e.id = v_id AND e.received_at = v_at AND e.processed_at IS NULL
        FOR UPDATE OF e SKIP LOCKED;
        IF NOT FOUND THEN
          v_id := NULL;
        END IF;
      END IF;
      PERFORM pg_advisory_unlock(v_key);
    EXCEPTION
      WHEN lock_not_available THEN
        -- An ingest of this org held the lock for 2s: try other orgs.
        v_id := NULL;
      WHEN query_canceled THEN
        PERFORM pg_advisory_unlock(v_key);
        RAISE;
      WHEN OTHERS THEN
        PERFORM pg_advisory_unlock(v_key);
        RAISE;
    END;
    IF v_id IS NOT NULL THEN
      org_id := v_org;
      id := v_id;
      received_at := v_at;
      RETURN NEXT;
      RETURN;
    END IF;
    v_skip := v_skip || v_org;
  END LOOP;
END $$;

REVOKE EXECUTE ON FUNCTION nfx_claim_alert_event() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nfx_claim_alert_event() TO nfx_app;

RESET ROLE;
