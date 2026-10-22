-- Alert events apply in the order their source sent them (final review).
--
-- 1. Events are processed oldest first per org, but an event only becomes
--    visible when its ingest transaction commits. One that commits after a
--    later event has already been processed (a firing event whose request
--    was slow, after the source's resolve) was applied last and left the
--    alert firing. Ingest now holds a shared per-org lock while it stores an
--    event, and the claim takes that lock exclusively before choosing an
--    org's next event: it never picks one while an older event of the org
--    may still be committing, and moves on to other orgs meanwhile.
--
-- 2. A CloudWatch OK that arrives before its ALARM (SNS doesn't guarantee
--    order) found no open alert and recorded nothing, so the older ALARM was
--    then applied and the alarm stayed firing, with nothing left to clear
--    it. alert_states keeps the latest state time applied to each
--    fingerprint, alert or no alert, so a state older than it is ignored.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

CREATE TABLE alert_states (
  org_id       uuid NOT NULL REFERENCES orgs(id),
  fingerprint  text NOT NULL,
  state_at     timestamptz NOT NULL,
  PRIMARY KEY (org_id, fingerprint)
);
ALTER TABLE alert_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON alert_states USING (org_id = nfx_org() OR current_user = 'nfx_owner')
  WITH CHECK (org_id = nfx_org() OR current_user = 'nfx_owner');
GRANT SELECT, INSERT, UPDATE ON alert_states TO nfx_app;

-- As in 0009, plus the per-org ingest lock. Returns the same columns.
CREATE OR REPLACE FUNCTION nfx_claim_alert_event()
RETURNS TABLE (org_id uuid, id uuid, received_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
#variable_conflict use_column
DECLARE
  c record;
  v_skip uuid[] := '{}';
BEGIN
  FOR i IN 1..20 LOOP
    SELECT e.org_id AS org, e.id AS eid, e.received_at AS at INTO c FROM alert_events e
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
    -- Held until this claim's transaction (the event's processing) commits.
    IF pg_try_advisory_xact_lock(hashtextextended('nfx_ingest:' || c.org::text, 0)) THEN
      -- An older event of this org may have committed while we waited for
      -- nothing: look again under the lock, and take the oldest.
      SELECT e.org_id AS org, e.id AS eid, e.received_at AS at INTO c FROM alert_events e
      WHERE e.processed_at IS NULL AND e.org_id = c.org
      ORDER BY e.received_at, e.id
      LIMIT 1
      FOR UPDATE OF e SKIP LOCKED;
      IF FOUND THEN
        org_id := c.org;
        id := c.eid;
        received_at := c.at;
        RETURN NEXT;
        RETURN;
      END IF;
    END IF;
    v_skip := v_skip || c.org;
  END LOOP;
END $$;

REVOKE EXECUTE ON FUNCTION nfx_claim_alert_event() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nfx_claim_alert_event() TO nfx_app;

RESET ROLE;
