-- Notification outbox redesign.
--
-- 1. Claims take a short lease instead of holding a row lock while the
--    HTTP request runs. DeliverNotifications used to send inside the claim
--    transaction, one row at a time, so a few tenants with hanging webhook
--    URLs delayed every other org's pages. nfx_claim_notification now sets
--    lease_until/lease_id and commits; the worker sends outside any
--    transaction and records the result in a new one, fenced on lease_id.
--    A leased row is still 'pending', so its successors keep waiting; an
--    expired lease (a crashed worker) makes it claimable again. Delivery is
--    at least once (PagerDuty dedupes on dedup_key).
-- 2. The in-order check (0005, 0010) couldn't use an index: it matched
--    incident_id with IS NOT DISTINCT FROM and ORed both destination kinds
--    together, so each candidate scanned the org's whole pending backlog.
--    It is now two NOT EXISTS, one per destination kind, each matching an
--    index exactly. Notifications to escalation targets always have an
--    incident (enforced for new rows below), so plain equality is right.
-- 3. created_at defaulted to now(), the transaction start time: a resolve
--    written by a transaction that began before (and waited on) the one
--    that wrote the page could sort ahead of it. It is now the insert time.
-- 4. A row queued behind a destination's backed-off head starts out due at
--    the head's retry time instead of now, so claims don't re-check a
--    blocked backlog that can't move (same as the push-back on failure).
--
-- 5. One org can have at most p_org_limit notifications in flight (leased)
--    at once, so its slow destinations or a burst of its updates can't
--    occupy every worker; pages and resolves are claimed before updates.
-- 6. The zero-argument claim is dropped outright: no deployment runs the
--    old code yet, so there's no rolling-deploy window to bridge. (Once
--    there is, a change like this keeps a compatible shim for a release.)
--    lock_timeout makes the migration fail fast, to be retried, rather than
--    queue every notification insert behind its table lock.
--
-- Numbered 0020 to follow 0014-0019 (main and the QA-round-3 renumbering).

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

ALTER TABLE notifications
  ADD COLUMN lease_until timestamptz,
  ADD COLUMN lease_id uuid;

ALTER TABLE notifications ALTER COLUMN created_at SET DEFAULT clock_timestamp();

ALTER TABLE notifications ADD CONSTRAINT notifications_target_has_incident
  CHECK (target_id IS NULL OR incident_id IS NOT NULL) NOT VALID;

DROP INDEX notifications_pending_by_target;
CREATE INDEX notifications_pending_by_target
  ON notifications (org_id, incident_id, target_id, created_at, id) WHERE status = 'pending' AND target_id IS NOT NULL;
DROP INDEX notifications_pending_by_channel;
CREATE INDEX notifications_pending_by_channel
  ON notifications (org_id, channel_id, created_at, id) WHERE status = 'pending' AND channel_id IS NOT NULL;

-- Rows currently leased, for the per-org in-flight cap.
CREATE INDEX notifications_leased ON notifications (org_id, lease_until) WHERE lease_until IS NOT NULL;

-- The old zero-argument claim locked the row for the caller's transaction.
DROP FUNCTION nfx_claim_notification();

-- Claims are serialized per org (an advisory lock, then a fresh count), so
-- concurrent workers can't all claim the same org's rows at once. A row
-- whose org is at its limit is passed over for other orgs' rows.
CREATE FUNCTION nfx_claim_notification(p_lease interval, p_lease_id uuid, p_org_limit int)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
#variable_conflict use_column
DECLARE
  c record;
  v_skip uuid[] := '{}';
  v_inflight int;
BEGIN
  FOR i IN 1..10 LOOP
    SELECT n.org_id AS org, n.id AS nid INTO c FROM notifications n
    WHERE n.status = 'pending' AND n.next_attempt_at <= now()
      AND (n.lease_until IS NULL OR n.lease_until <= now())
      AND n.org_id <> ALL (v_skip)
      AND (SELECT count(*) FROM notifications l
           WHERE l.org_id = n.org_id AND l.lease_until > clock_timestamp()) < p_org_limit
      AND NOT EXISTS (
        SELECT 1 FROM notifications p
        WHERE p.org_id = n.org_id AND p.incident_id = n.incident_id AND p.target_id = n.target_id
          AND p.status = 'pending' AND (p.created_at, p.id) < (n.created_at, n.id))
      AND NOT EXISTS (
        SELECT 1 FROM notifications p
        WHERE p.org_id = n.org_id AND p.channel_id = n.channel_id
          AND p.status = 'pending' AND (p.created_at, p.id) < (n.created_at, n.id))
    ORDER BY n.kind IN ('page', 'resolve') DESC, n.next_attempt_at
    LIMIT 1
    FOR UPDATE OF n SKIP LOCKED;
    IF NOT FOUND THEN
      RETURN;
    END IF;
    -- Held until this claim commits; the count below is a new snapshot, so
    -- it sees every lease committed by a claim that held the lock before.
    PERFORM pg_advisory_xact_lock(hashtextextended('nfx_notify_org:' || c.org::text, 0));
    SELECT count(*) INTO v_inflight FROM notifications l
    WHERE l.org_id = c.org AND l.lease_until > clock_timestamp();
    IF v_inflight < p_org_limit THEN
      UPDATE notifications u SET lease_until = clock_timestamp() + p_lease, lease_id = p_lease_id
      WHERE u.org_id = c.org AND u.id = c.nid;
      org_id := c.org;
      id := c.nid;
      RETURN NEXT;
      RETURN;
    END IF;
    v_skip := v_skip || c.org;
  END LOOP;
END $$;

REVOKE EXECUTE ON FUNCTION nfx_claim_notification(interval, uuid, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nfx_claim_notification(interval, uuid, int) TO nfx_app;

-- Runs as the inserting role, so row-level security scopes the lookup to
-- the new row's org.
CREATE FUNCTION nfx_notification_follow_head() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  v_head timestamptz;
BEGIN
  IF NEW.status <> 'pending' THEN
    RETURN NEW;
  END IF;
  IF NEW.target_id IS NOT NULL THEN
    SELECT max(p.next_attempt_at) INTO v_head FROM notifications p
    WHERE p.org_id = NEW.org_id AND p.incident_id = NEW.incident_id AND p.target_id = NEW.target_id
      AND p.status = 'pending';
  ELSIF NEW.channel_id IS NOT NULL THEN
    SELECT max(p.next_attempt_at) INTO v_head FROM notifications p
    WHERE p.org_id = NEW.org_id AND p.channel_id = NEW.channel_id AND p.status = 'pending';
  END IF;
  IF v_head > NEW.next_attempt_at THEN
    NEW.next_attempt_at := v_head;
  END IF;
  RETURN NEW;
END $$;

REVOKE EXECUTE ON FUNCTION nfx_notification_follow_head() FROM PUBLIC;

CREATE TRIGGER notifications_follow_head BEFORE INSERT ON notifications
  FOR EACH ROW EXECUTE FUNCTION nfx_notification_follow_head();

RESET ROLE;
