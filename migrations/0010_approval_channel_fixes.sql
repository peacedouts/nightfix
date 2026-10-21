-- Approval channel fixes found in QA round 2.
--
-- 1. Replacing an approval channel's webhook URL deleted the row and
--    inserted a new one, which failed with a foreign-key error once any
--    notification had been sent to it, so a leaked or broken webhook URL
--    couldn't be rotated. The URL is now updated in place.
-- 2. In-order delivery (0005) matched on incident_id and target_id, which
--    are NULL for approval-channel notifications, so those were never held
--    behind older ones: an "approved by …" update could arrive before a
--    retried "approval needed" message with live buttons. Approval-channel
--    notifications are now ordered per channel.

SET ROLE nfx_owner;

GRANT UPDATE (credential, created_by, created_at) ON approval_channels TO nfx_app;

CREATE INDEX notifications_pending_by_channel
  ON notifications (org_id, channel_id, created_at) WHERE status = 'pending' AND channel_id IS NOT NULL;

CREATE OR REPLACE FUNCTION nfx_claim_notification()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT n.org_id, n.id FROM notifications n
  WHERE n.status = 'pending' AND n.next_attempt_at <= now()
    AND NOT EXISTS (
      SELECT 1 FROM notifications p
      WHERE p.org_id = n.org_id AND p.status = 'pending' AND (p.created_at, p.id) < (n.created_at, n.id)
        AND ((n.target_id IS NOT NULL AND p.target_id = n.target_id AND p.incident_id IS NOT DISTINCT FROM n.incident_id)
          OR (n.channel_id IS NOT NULL AND p.channel_id = n.channel_id)))
  ORDER BY n.next_attempt_at
  LIMIT 1
  FOR UPDATE OF n SKIP LOCKED
$$;

RESET ROLE;
