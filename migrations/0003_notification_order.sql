-- Deliver notifications for the same incident and target in order.
--
-- A page that failed and is backing off must not be overtaken by a later
-- resolve: the resolve would reach PagerDuty first, the retried page would
-- then open an upstream incident that nothing ever resolves.

SET ROLE nfx_owner;

CREATE INDEX notifications_pending_by_target
  ON notifications (org_id, incident_id, target_id, created_at) WHERE status = 'pending';

CREATE OR REPLACE FUNCTION nfx_claim_notification()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT n.org_id, n.id FROM notifications n
  WHERE n.status = 'pending' AND n.next_attempt_at <= now()
    AND NOT EXISTS (
      SELECT 1 FROM notifications p
      WHERE p.org_id = n.org_id AND p.incident_id = n.incident_id AND p.target_id = n.target_id
        AND p.status = 'pending' AND (p.created_at, p.id) < (n.created_at, n.id))
  ORDER BY n.next_attempt_at
  LIMIT 1
  FOR UPDATE OF n SKIP LOCKED
$$;

RESET ROLE;
