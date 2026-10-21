-- Process each org's alert events in the order they arrived.
--
-- Events were claimed oldest-first with SKIP LOCKED, so with more than one
-- worker (several control-plane instances), worker B could take a newer
-- event while worker A was still on an older one for the same alert. If the
-- older event was the alarm and the newer one its OK, the resolve ran first,
-- found nothing open, and the alarm then opened an alert that stayed firing
-- forever. An event is now claimable only when no older unprocessed event
-- exists for its org; different orgs still process in parallel.
--
-- Numbered 0009 to stay clear of PR #3's 0004 and 0008.

SET ROLE nfx_owner;

CREATE INDEX alert_events_unprocessed_by_org ON alert_events (org_id, received_at, id) WHERE processed_at IS NULL;

CREATE OR REPLACE FUNCTION nfx_claim_alert_event()
RETURNS TABLE (org_id uuid, id uuid, received_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT e.org_id, e.id, e.received_at FROM alert_events e
  WHERE e.processed_at IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM alert_events o
      WHERE o.org_id = e.org_id AND o.processed_at IS NULL
        AND (o.received_at, o.id) < (e.received_at, e.id))
  ORDER BY e.received_at
  LIMIT 1
  FOR UPDATE OF e SKIP LOCKED
$$;

RESET ROLE;
