-- A revoked IAM-enrolled agent stays revoked (final review).
--
-- Revoking an agent cut its certificate off, but the agent then re-enrolled
-- at once with the same IAM role session and was back. Agents now record
-- the AWS identity they enrolled as (the assumed-role ARN, which includes
-- the session: on ECS, the task), and an identity whose agent was revoked
-- can't enroll again. A new task (a new session) can, under the rule; to
-- keep a role out entirely, revoke its enrollment rule.

SET LOCAL lock_timeout = '5s';
SET ROLE nfx_owner;

ALTER TABLE agents ADD COLUMN iam_arn text;
CREATE INDEX agents_revoked_iam_arn ON agents (org_id, iam_arn) WHERE revoked_at IS NOT NULL AND iam_arn IS NOT NULL;

RESET ROLE;
