-- Acknowledging an incident acknowledges its upstream PagerDuty page, so
-- PagerDuty's escalation policy stops paging the next person while someone
-- is already on it (alert-incident-model.md §7). It goes out as a
-- notification of its own kind, in order after the page and before the
-- resolve for the same incident and target.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('page','resolve','update','approval','acknowledge'));

RESET ROLE;
