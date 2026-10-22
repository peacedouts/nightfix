-- Step retries back off exponentially (runbook-schema.md §3.7, `retries`).
--
-- A failed or timed-out attempt was re-queued and handed out again on the
-- very next poll, so a step with `retries: 3` burned through every retry in
-- well under a second, before whatever it was waiting on (a deployment, a
-- failover, a throttled API) had any chance to change. A retry is now queued
-- with the earliest time it may be dispatched, and polls skip it until then.

SET ROLE nfx_owner;

ALTER TABLE step_attempts ADD COLUMN not_before timestamptz;

RESET ROLE;
