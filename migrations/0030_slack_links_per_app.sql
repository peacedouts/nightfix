-- Slack links belong to the Slack app they were made through (security review).
--
-- A link (Slack user → Nightfix user) was looked up by Slack workspace and
-- user only. An admin could register a second Slack app with a signing
-- secret of their own, sign an approval click as any linked user, and decide
-- gates as that person (an owner, the requester's colleagues, several of
-- them for a multi-person gate). Links now record their app, and a click
-- counts only through that app. Existing links get the org's app when it has
-- exactly one; the rest are removed and their people link again.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

ALTER TABLE slack_user_links ADD COLUMN slack_app_id uuid;

UPDATE slack_user_links l SET slack_app_id = a.id
FROM slack_apps a
WHERE a.org_id = l.org_id AND a.archived_at IS NULL
  AND (SELECT count(*) FROM slack_apps b WHERE b.org_id = l.org_id AND b.archived_at IS NULL) = 1;

DELETE FROM slack_user_links WHERE slack_app_id IS NULL;

ALTER TABLE slack_user_links
  ALTER COLUMN slack_app_id SET NOT NULL,
  ADD FOREIGN KEY (org_id, slack_app_id) REFERENCES slack_apps (org_id, id);

RESET ROLE;
