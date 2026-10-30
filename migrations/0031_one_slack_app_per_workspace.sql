-- One active Slack app per workspace in an org (review, Oct 30).
--
-- Links are per app (0030), but the link table's key is still per workspace,
-- so with two active apps on one workspace, linking through one silently
-- unlinked the person from the other. Nothing needs two: archive the extras
-- (newest kept) and refuse a second registration.
--
-- Also drops links 0030 bound to an app of a different workspace (an org
-- whose one active app wasn't the workspace's): they could never match.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

UPDATE slack_apps a SET archived_at = now()
WHERE a.archived_at IS NULL AND a.team_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM slack_apps b
              WHERE b.org_id = a.org_id AND b.team_id = a.team_id AND b.archived_at IS NULL
                AND (b.created_at, b.id) > (a.created_at, a.id));

DELETE FROM slack_user_links l
USING slack_apps a
WHERE a.org_id = l.org_id AND a.id = l.slack_app_id
  AND a.team_id IS NOT NULL AND a.team_id <> l.slack_team_id;

CREATE UNIQUE INDEX slack_apps_one_active_per_team
  ON slack_apps (org_id, team_id) WHERE archived_at IS NULL AND team_id IS NOT NULL;

RESET ROLE;
