-- Background workers no longer stall on one bad row.
--
-- The claim functions for due incidents, expired leases, overdue runs and
-- expired approval gates took LIMIT 1 with no ORDER BY, and a handler error
-- rolled back and ended the loop. A row whose handler always failed (say,
-- a runbook version that no longer decodes) was claimed first again on the
-- next tick, so nothing behind it was ever processed, for any org: run
-- timeouts, lease expiry, gate expiry and hold/verify paging all stopped.
--
-- Each table gets a failure counter, a retry time and the last error. The
-- worker records a failure and moves on (internal/controlplane/worker.go),
-- and claims skip rows until their retry time and take the most overdue
-- first.
--
-- Numbered 0014 to stay clear of open PRs using 0010-0013.

SET ROLE nfx_owner;

ALTER TABLE incidents      ADD COLUMN worker_failures int NOT NULL DEFAULT 0, ADD COLUMN worker_retry_at timestamptz, ADD COLUMN worker_error text;
ALTER TABLE runbook_runs   ADD COLUMN worker_failures int NOT NULL DEFAULT 0, ADD COLUMN worker_retry_at timestamptz, ADD COLUMN worker_error text;
ALTER TABLE step_attempts  ADD COLUMN worker_failures int NOT NULL DEFAULT 0, ADD COLUMN worker_retry_at timestamptz, ADD COLUMN worker_error text;
ALTER TABLE approval_gates ADD COLUMN worker_failures int NOT NULL DEFAULT 0, ADD COLUMN worker_retry_at timestamptz, ADD COLUMN worker_error text;

CREATE OR REPLACE FUNCTION nfx_claim_due_incident()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT i.org_id, i.id FROM incidents i
  WHERE i.status = 'remediating'
    AND (i.hold_until <= now() OR i.verify_until <= now())
    AND (i.worker_retry_at IS NULL OR i.worker_retry_at <= now())
  ORDER BY least(i.hold_until, i.verify_until)
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

CREATE OR REPLACE FUNCTION nfx_claim_expired_lease()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT a.org_id, a.id FROM step_attempts a
  WHERE a.state IN ('dispatched','running') AND a.lease_expires_at <= now()
    AND (a.worker_retry_at IS NULL OR a.worker_retry_at <= now())
  ORDER BY a.lease_expires_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- As in 0003 (runs waiting for approval still have a deadline).
CREATE OR REPLACE FUNCTION nfx_claim_overdue_run()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT r.org_id, r.id FROM runbook_runs r
  WHERE r.status IN ('running','awaiting_approval') AND r.deadline_at <= now()
    AND (r.worker_retry_at IS NULL OR r.worker_retry_at <= now())
  ORDER BY r.deadline_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Locks the run (not the gate) like 0003, so gate decisions and expiry
-- take locks in the same order.
CREATE OR REPLACE FUNCTION nfx_claim_expired_gate()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT g.org_id, g.id FROM approval_gates g JOIN runbook_runs r ON r.org_id = g.org_id AND r.id = g.run_id
  WHERE g.status = 'pending' AND g.expires_at <= now()
    AND (g.worker_retry_at IS NULL OR g.worker_retry_at <= now())
  ORDER BY g.expires_at
  LIMIT 1
  FOR UPDATE OF r SKIP LOCKED
$$;

RESET ROLE;
