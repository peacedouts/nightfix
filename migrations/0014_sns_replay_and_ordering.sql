-- SNS replay and out-of-order state changes (QA follow-up).
--
-- 1. SNS retries a delivery, with the same MessageId, until it gets a 2xx,
--    and anyone holding a captured, validly signed message could post it
--    again. Ingest now refuses notifications whose signed Timestamp is older
--    than a bounded window, and records each MessageId per integration: a
--    repeat is acknowledged with a 2xx and stored nowhere. A row only has to
--    outlive the window (after that the timestamp check refuses the message),
--    so each carries an expiry and a worker deletes expired rows.
--
-- 2. alerts.state_at is the source's time for the latest state applied to
--    an alert (CloudWatch StateChangeTime). A state update that isn't newer,
--    such as a retried ALARM arriving after the OK, is ignored instead of
--    reopening or resolving the alert. NULL for sources without a trustworthy
--    timestamp (generic webhooks), which keep processing order as before.

SET ROLE nfx_owner;

ALTER TABLE alerts ADD COLUMN state_at timestamptz;
CREATE INDEX alerts_fingerprint_state ON alerts (org_id, fingerprint, state_at DESC) WHERE state_at IS NOT NULL;

CREATE TABLE ingest_message_ids (
  org_id          uuid NOT NULL REFERENCES orgs(id),
  integration_id  uuid NOT NULL,
  message_id      text NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  PRIMARY KEY (org_id, integration_id, message_id),
  FOREIGN KEY (org_id, integration_id) REFERENCES integrations(org_id, id)
);
CREATE INDEX ingest_message_ids_expiry ON ingest_message_ids (expires_at);

ALTER TABLE ingest_message_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_message_ids FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_message_ids USING (org_id = nfx_org() OR current_user = 'nfx_owner') WITH CHECK (org_id = nfx_org() OR current_user = 'nfx_owner');

-- Ingest only ever inserts; ON CONFLICT DO NOTHING tells it about a repeat,
-- which needs SELECT on the key columns it checks.
GRANT INSERT ON ingest_message_ids TO nfx_app;
GRANT SELECT (org_id, integration_id, message_id) ON ingest_message_ids TO nfx_app;

-- Delete MessageIds whose replay window has passed, across every org.
CREATE FUNCTION nfx_expire_ingest_message_ids()
RETURNS int LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  WITH d AS (DELETE FROM ingest_message_ids WHERE expires_at < now() RETURNING 1)
  SELECT count(*)::int FROM d
$$;
GRANT EXECUTE ON FUNCTION nfx_expire_ingest_message_ids() TO nfx_app;

RESET ROLE;
