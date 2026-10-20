-- Nightfix — initial schema for the walking-skeleton slice.
--
-- Roles:
--   nfx_owner  NOLOGIN, owns every table and the SECURITY DEFINER lookup/claim
--              functions. BYPASSRLS so those functions can find the org for an
--              incoming request or a due background job.
--   nfx_app    LOGIN, what the application connects as. Not an owner, so RLS
--              always applies. Append-only tables get INSERT/SELECT only.
--
-- Every tenant table carries org_id, has RLS forced on, and references other
-- tenant rows through composite (org_id, id) foreign keys.

SET ROLE nfx_owner;

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Current org for RLS. Errors (fails closed) if the app forgot to set it.
CREATE FUNCTION nfx_org() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT current_setting('app.org_id')::uuid $$;

-- ---------------------------------------------------------------------------
-- Tenancy and identity
-- ---------------------------------------------------------------------------

CREATE TABLE orgs (
  id          uuid PRIMARY KEY,
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  frozen_at   timestamptz,
  frozen_by   text,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_counters (
  org_id  uuid NOT NULL REFERENCES orgs(id),
  name    text NOT NULL,
  value   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (org_id, name)
);

CREATE TABLE api_keys (
  id          uuid NOT NULL,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  name        text NOT NULL,
  prefix      text NOT NULL,
  hash        bytea NOT NULL UNIQUE,
  role        text NOT NULL CHECK (role IN ('owner','admin','responder','viewer')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at  timestamptz,
  PRIMARY KEY (org_id, id)
);

-- ---------------------------------------------------------------------------
-- Trust and agents
-- ---------------------------------------------------------------------------

CREATE TABLE signing_keys (
  key_id       text NOT NULL,
  org_id       uuid NOT NULL REFERENCES orgs(id),
  owner        text NOT NULL CHECK (owner IN ('control_plane','customer')),
  public_key   bytea NOT NULL,
  private_key  bytea,              -- sealed; NULL for customer keys. KMS in production.
  state        text NOT NULL DEFAULT 'active' CHECK (state IN ('active','retiring','retired')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, key_id)
);

CREATE TABLE org_trust_config (
  org_id            uuid PRIMARY KEY REFERENCES orgs(id),
  required_signers  text[] NOT NULL,
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_rules (
  id          uuid NOT NULL,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  method      text NOT NULL CHECK (method IN ('token','iam')),
  token_hash  bytea UNIQUE,
  aws_account_id text,
  role_arn    text,
  labels      jsonb NOT NULL,
  max_agents  int NOT NULL DEFAULT 10,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);

CREATE TABLE agents (
  id                 uuid NOT NULL,
  org_id             uuid NOT NULL REFERENCES orgs(id),
  enrollment_rule_id uuid NOT NULL,
  labels             jsonb NOT NULL,
  status             text NOT NULL DEFAULT 'offline' CHECK (status IN ('online','offline','revoked')),
  version            text,
  capabilities       text[] NOT NULL DEFAULT '{}',
  slots              int NOT NULL DEFAULT 4,
  allowlist_mode     text,
  frozen_local       boolean NOT NULL DEFAULT false,
  cert_serial        text NOT NULL UNIQUE,
  cert_expires_at    timestamptz NOT NULL,
  last_seen_at       timestamptz,
  revoked_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, enrollment_rule_id) REFERENCES enrollment_rules(org_id, id)
);

-- ---------------------------------------------------------------------------
-- Services, integrations, routing
-- ---------------------------------------------------------------------------

CREATE TABLE services (
  id                  uuid NOT NULL,
  org_id              uuid NOT NULL REFERENCES orgs(id),
  name                text NOT NULL,
  team                text,
  is_catch_all        boolean NOT NULL DEFAULT false,
  grouping_labels     text[] NOT NULL DEFAULT '{}',
  grouping_window     interval NOT NULL DEFAULT '2 hours',
  max_hold            interval NOT NULL DEFAULT '10 minutes' CHECK (max_hold <= '30 minutes'),
  verification_window interval NOT NULL DEFAULT '5 minutes',
  reopen_window       interval NOT NULL DEFAULT '15 minutes',
  auto_resolve        boolean NOT NULL DEFAULT true,
  archived_at         timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, name)
);

CREATE TABLE escalation_targets (
  id          uuid NOT NULL,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  service_id  uuid NOT NULL,
  type        text NOT NULL CHECK (type IN ('slack','pagerduty')),
  config      jsonb NOT NULL DEFAULT '{}',   -- non-secret settings (e.g. endpoint override)
  credential  bytea NOT NULL,                -- sealed: Slack webhook URL / PagerDuty routing key
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, service_id) REFERENCES services(org_id, id)
);

CREATE TABLE integrations (
  id                 uuid NOT NULL,
  org_id             uuid NOT NULL REFERENCES orgs(id),
  type               text NOT NULL CHECK (type IN ('cloudwatch','webhook')),
  name               text NOT NULL,
  default_service_id uuid NOT NULL,
  severity_map       jsonb NOT NULL DEFAULT '{}',
  dedupe_keys        text[] NOT NULL DEFAULT '{alertname,service,instance}',
  config             jsonb NOT NULL DEFAULT '{}',
  credential         bytea,                  -- sealed HMAC secret for webhook integrations
  archived_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, default_service_id) REFERENCES services(org_id, id)
);

CREATE TABLE routing_rules (
  id          uuid NOT NULL,
  org_id      uuid NOT NULL REFERENCES orgs(id),
  priority    int NOT NULL,
  match       text NOT NULL,
  action      text NOT NULL DEFAULT 'route' CHECK (action IN ('route','suppress')),
  service_id  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, service_id) REFERENCES services(org_id, id)
);

-- ---------------------------------------------------------------------------
-- Alerts and incidents
-- ---------------------------------------------------------------------------

-- Raw deliveries, append-only, partitioned by day (30-day retention by dropping partitions).
CREATE TABLE alert_events (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL,
  integration_id  uuid NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  raw             text NOT NULL,
  processed_at    timestamptz,
  error           text,
  PRIMARY KEY (received_at, id)
) PARTITION BY RANGE (received_at);
CREATE INDEX alert_events_unprocessed ON alert_events (received_at) WHERE processed_at IS NULL;

CREATE TABLE alerts (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL REFERENCES orgs(id),
  fingerprint     text NOT NULL,
  integration_id  uuid NOT NULL,
  service_id      uuid NOT NULL,
  status          text NOT NULL CHECK (status IN ('firing','resolved')),
  severity        text NOT NULL CHECK (severity IN ('critical','high','warning','info')),
  summary         text NOT NULL,
  source          text NOT NULL,
  labels          jsonb NOT NULL DEFAULT '{}',
  annotations     jsonb NOT NULL DEFAULT '{}',
  suppressed      boolean NOT NULL DEFAULT false,
  first_seen_at   timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL,
  resolved_at     timestamptz,
  event_count     int NOT NULL DEFAULT 1,
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, integration_id) REFERENCES integrations(org_id, id),
  FOREIGN KEY (org_id, service_id) REFERENCES services(org_id, id)
);
-- One open alert per fingerprint: makes concurrent dedupe safe.
CREATE UNIQUE INDEX alerts_open_fingerprint ON alerts (org_id, fingerprint) WHERE status <> 'resolved';
CREATE INDEX alerts_fingerprint_recent ON alerts (org_id, fingerprint, resolved_at DESC);

CREATE TABLE incidents (
  id                  uuid NOT NULL,
  org_id              uuid NOT NULL REFERENCES orgs(id),
  number              bigint NOT NULL,
  service_id          uuid NOT NULL,
  group_key           text NOT NULL,
  status              text NOT NULL CHECK (status IN ('remediating','triggered','acknowledged','resolved')),
  severity            text NOT NULL,
  title               text NOT NULL,
  opened_at           timestamptz NOT NULL DEFAULT now(),
  ack_at              timestamptz,
  resolved_at         timestamptz,
  resolution          text CHECK (resolution IN ('human','auto_remediated','alerts_resolved')),
  hold_until          timestamptz,
  verify_until        timestamptz,
  paged_at            timestamptz,
  remediation_run_id  uuid,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, number),
  FOREIGN KEY (org_id, service_id) REFERENCES services(org_id, id)
);
-- One open incident per service + group key.
CREATE UNIQUE INDEX incidents_open_group ON incidents (org_id, service_id, group_key) WHERE status <> 'resolved';
CREATE INDEX incidents_deadlines ON incidents (hold_until, verify_until) WHERE status = 'remediating';

CREATE TABLE incident_alerts (
  org_id       uuid NOT NULL,
  incident_id  uuid NOT NULL,
  alert_id     uuid NOT NULL,
  attached_at  timestamptz NOT NULL DEFAULT now(),
  detached_at  timestamptz,
  PRIMARY KEY (org_id, incident_id, alert_id),
  FOREIGN KEY (org_id, incident_id) REFERENCES incidents(org_id, id),
  FOREIGN KEY (org_id, alert_id) REFERENCES alerts(org_id, id)
);

CREATE TABLE incident_timeline (
  id           bigserial,
  org_id       uuid NOT NULL,
  incident_id  uuid NOT NULL,
  at           timestamptz NOT NULL DEFAULT clock_timestamp(),
  type         text NOT NULL,
  actor_type   text NOT NULL,
  actor_id     text,
  message      text NOT NULL,
  data         jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, incident_id) REFERENCES incidents(org_id, id)
);
CREATE INDEX incident_timeline_incident ON incident_timeline (org_id, incident_id, id);

-- Outbox for pages and Slack messages; delivered by a worker after commit.
CREATE TABLE notifications (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL,
  incident_id     uuid NOT NULL,
  target_id       uuid NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('page','resolve','update')),
  payload         jsonb NOT NULL,
  status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, incident_id) REFERENCES incidents(org_id, id),
  FOREIGN KEY (org_id, target_id) REFERENCES escalation_targets(org_id, id)
);
CREATE INDEX notifications_pending ON notifications (next_attempt_at) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- Runbooks and runs
-- ---------------------------------------------------------------------------

CREATE TABLE runbooks (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL REFERENCES orgs(id),
  name            text NOT NULL,
  title           text NOT NULL,
  team            text,
  tags            text[] NOT NULL DEFAULT '{}',
  latest_version  int NOT NULL DEFAULT 0,
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, name)
);

-- Immutable published versions.
CREATE TABLE runbook_versions (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL,
  runbook_id      uuid NOT NULL,
  version         int NOT NULL,
  digest          text NOT NULL,
  canonical_json  text NOT NULL,
  source_yaml     text NOT NULL,
  source          text NOT NULL DEFAULT 'api',
  published_by    text NOT NULL,
  published_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, runbook_id, version),
  FOREIGN KEY (org_id, runbook_id) REFERENCES runbooks(org_id, id)
);

CREATE TABLE runbook_signatures (
  org_id      uuid NOT NULL,
  version_id  uuid NOT NULL,
  key_id      text NOT NULL,
  signature   bytea NOT NULL,
  signed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, version_id, key_id),
  FOREIGN KEY (org_id, version_id) REFERENCES runbook_versions(org_id, id)
);

-- Denormalized from the latest version for fast matching.
CREATE TABLE runbook_triggers (
  org_id            uuid NOT NULL,
  runbook_id        uuid NOT NULL,
  version           int NOT NULL,
  idx               int NOT NULL,
  type              text NOT NULL,
  mode              text,
  match             text,
  services          text[] NOT NULL DEFAULT '{}',
  before_paging     boolean NOT NULL DEFAULT false,
  cooldown          interval,
  max_runs_per_hour int,
  PRIMARY KEY (org_id, runbook_id, idx),
  FOREIGN KEY (org_id, runbook_id) REFERENCES runbooks(org_id, id)
);
CREATE INDEX runbook_triggers_services ON runbook_triggers USING gin (services);

CREATE TABLE runbook_runs (
  id                  uuid NOT NULL,
  org_id              uuid NOT NULL,
  runbook_version_id  uuid NOT NULL,
  runbook_name        text NOT NULL,
  digest              text NOT NULL,
  incident_id         uuid,
  fingerprint         text,
  trigger_type        text NOT NULL,
  mode                text NOT NULL,
  requested_by_type   text NOT NULL CHECK (requested_by_type IN ('user','api_key','trigger')),
  requested_by_id     text NOT NULL,
  params              jsonb NOT NULL,
  context             jsonb NOT NULL,       -- alert, incident, run, step outputs (never secrets)
  target_selector     jsonb NOT NULL,
  status              text NOT NULL CHECK (status IN ('running','succeeded','failed','timed_out','cancelled','needs_human')),
  current_step        int NOT NULL DEFAULT 0,
  before_paging       boolean NOT NULL DEFAULT false,
  verified            boolean,
  deadline_at         timestamptz NOT NULL,
  started_at          timestamptz NOT NULL DEFAULT now(),
  finished_at         timestamptz,
  error               text,
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, runbook_version_id) REFERENCES runbook_versions(org_id, id),
  FOREIGN KEY (org_id, incident_id) REFERENCES incidents(org_id, id)
);
CREATE INDEX runbook_runs_recent ON runbook_runs (org_id, runbook_name, started_at DESC);
CREATE INDEX runbook_runs_fingerprint ON runbook_runs (org_id, fingerprint, started_at DESC);
CREATE INDEX runbook_runs_deadline ON runbook_runs (deadline_at) WHERE status = 'running';

ALTER TABLE incidents ADD FOREIGN KEY (org_id, remediation_run_id) REFERENCES runbook_runs(org_id, id);

-- The agent work queue.
CREATE TABLE step_attempts (
  id                uuid NOT NULL,
  org_id            uuid NOT NULL,
  run_id            uuid NOT NULL,
  step_index        int NOT NULL,
  step_id           text NOT NULL,
  attempt_number    int NOT NULL,
  state             text NOT NULL CHECK (state IN ('queued','dispatched','running','succeeded','failed','timed_out','cancelled','rejected','lost')),
  agent_id          uuid,
  lease_expires_at  timestamptz,
  exit_code         int,
  outputs           jsonb,
  error             text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  dispatched_at     timestamptz,
  started_at        timestamptz,
  finished_at       timestamptz,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, run_id, step_index, attempt_number),
  FOREIGN KEY (org_id, run_id) REFERENCES runbook_runs(org_id, id)
);
CREATE INDEX step_attempts_queue ON step_attempts (org_id, state, created_at) WHERE state = 'queued';
CREATE INDEX step_attempts_leases ON step_attempts (lease_expires_at) WHERE state IN ('dispatched','running');

-- Streamed output, partitioned by day (90-day default retention).
CREATE TABLE step_output_chunks (
  org_id      uuid NOT NULL,
  attempt_id  uuid NOT NULL,
  seq         int NOT NULL,
  stream      text NOT NULL CHECK (stream IN ('stdout','stderr','log')),
  data        text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (received_at, org_id, attempt_id, seq)
) PARTITION BY RANGE (received_at);
CREATE INDEX step_output_chunks_attempt ON step_output_chunks (org_id, attempt_id, seq);

-- ---------------------------------------------------------------------------
-- Audit: append-only, hash-chained per org.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_events (
  org_id        uuid NOT NULL,
  seq           bigint NOT NULL,
  at            timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_type    text NOT NULL,
  actor_id      text NOT NULL,
  action        text NOT NULL,
  resource_type text NOT NULL,
  resource_id   text NOT NULL,
  data          jsonb NOT NULL DEFAULT '{}',
  prev_hash     bytea,
  hash          bytea NOT NULL,
  PRIMARY KEY (org_id, seq)
);

-- ---------------------------------------------------------------------------
-- Partitions: daily partitions for the time-partitioned tables.
-- ---------------------------------------------------------------------------

CREATE FUNCTION nfx_ensure_partitions(days_ahead int DEFAULT 3) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  t text;
  d date;
  pname text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alert_events','step_output_chunks'] LOOP
    FOR i IN -1..days_ahead LOOP
      d := current_date + i;
      pname := format('%s_%s', t, to_char(d, 'YYYYMMDD'));
      IF to_regclass(pname) IS NULL THEN
        EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                       pname, t, d, d + 1);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', pname);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', pname);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nfx_org()) WITH CHECK (org_id = nfx_org())', pname);
        IF t = 'alert_events' THEN
          EXECUTE format('GRANT SELECT, INSERT ON %I TO nfx_app', pname);
          EXECUTE format('GRANT UPDATE (processed_at, error) ON %I TO nfx_app', pname);
        ELSE
          EXECUTE format('GRANT SELECT, INSERT ON %I TO nfx_app', pname);
        END IF;
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- Drop partitions older than the retention period.
CREATE FUNCTION nfx_drop_expired_partitions(alert_event_days int DEFAULT 30, output_days int DEFAULT 90)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r record;
  dropped int := 0;
  cutoff date;
BEGIN
  FOR r IN
    SELECT c.relname, p.relname AS parent
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname IN ('alert_events','step_output_chunks')
  LOOP
    cutoff := current_date - CASE WHEN r.parent = 'alert_events' THEN alert_event_days ELSE output_days END;
    IF to_date(right(r.relname, 8), 'YYYYMMDD') < cutoff THEN
      EXECUTE format('DROP TABLE %I', r.relname);
      dropped := dropped + 1;
    END IF;
  END LOOP;
  RETURN dropped;
END $$;

SELECT nfx_ensure_partitions();

-- ---------------------------------------------------------------------------
-- Row-level security on every tenant table.
-- ---------------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'org_counters','api_keys','signing_keys','org_trust_config','enrollment_rules','agents',
    'services','escalation_targets','integrations','routing_rules',
    'alert_events','alerts','incidents','incident_alerts','incident_timeline','notifications',
    'runbooks','runbook_versions','runbook_signatures','runbook_triggers','runbook_runs',
    'step_attempts','step_output_chunks','audit_events'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nfx_org()) WITH CHECK (org_id = nfx_org())', t);
  END LOOP;
END $$;

ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orgs USING (id = nfx_org()) WITH CHECK (id = nfx_org());

-- ---------------------------------------------------------------------------
-- Grants. nfx_app never owns anything.
-- ---------------------------------------------------------------------------

GRANT SELECT, UPDATE ON orgs TO nfx_app;
GRANT SELECT, INSERT, UPDATE ON
  org_counters, api_keys, enrollment_rules, agents, services, escalation_targets, integrations,
  routing_rules, alerts, incidents, incident_alerts, notifications, runbooks, runbook_triggers,
  runbook_runs, step_attempts, org_trust_config
TO nfx_app;
GRANT DELETE ON runbook_triggers, routing_rules TO nfx_app;
GRANT SELECT, INSERT ON signing_keys TO nfx_app;
-- Append-only.
GRANT SELECT, INSERT ON runbook_versions, runbook_signatures, incident_timeline, step_output_chunks, audit_events TO nfx_app;
GRANT SELECT, INSERT ON alert_events TO nfx_app;
GRANT UPDATE (processed_at, error) ON alert_events TO nfx_app;
GRANT USAGE ON SEQUENCE incident_timeline_id_seq TO nfx_app;
GRANT EXECUTE ON FUNCTION nfx_org() TO nfx_app;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER functions: the only way to cross the tenant boundary.
-- Each returns the org (and row id) for something presented before an org is
-- known — an API key, an integration URL, an agent certificate — or claims a
-- due background job. The caller then sets app.org_id and continues under RLS.
-- ---------------------------------------------------------------------------

CREATE FUNCTION nfx_route_api_key(p_hash bytea)
RETURNS TABLE (org_id uuid, key_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT k.org_id, k.id, k.role FROM api_keys k WHERE k.hash = p_hash AND k.revoked_at IS NULL
$$;

CREATE FUNCTION nfx_route_integration(p_id uuid)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT i.org_id FROM integrations i WHERE i.id = p_id AND i.archived_at IS NULL
$$;

CREATE FUNCTION nfx_route_enrollment_token(p_hash bytea)
RETURNS TABLE (org_id uuid, rule_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT r.org_id, r.id FROM enrollment_rules r
  WHERE r.token_hash = p_hash AND r.revoked_at IS NULL AND (r.expires_at IS NULL OR r.expires_at > now())
$$;

CREATE FUNCTION nfx_route_agent(p_serial text)
RETURNS TABLE (org_id uuid, agent_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT a.org_id, a.id FROM agents a WHERE a.cert_serial = p_serial AND a.revoked_at IS NULL
$$;

-- Claim one unprocessed alert event (row lock held until the caller's tx ends).
CREATE FUNCTION nfx_claim_alert_event()
RETURNS TABLE (org_id uuid, id uuid, received_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT e.org_id, e.id, e.received_at FROM alert_events e
  WHERE e.processed_at IS NULL
  ORDER BY e.received_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Claim one due notification.
CREATE FUNCTION nfx_claim_notification()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT n.org_id, n.id FROM notifications n
  WHERE n.status = 'pending' AND n.next_attempt_at <= now()
  ORDER BY n.next_attempt_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Claim one remediating incident whose hold or verification deadline passed.
CREATE FUNCTION nfx_claim_due_incident()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT i.org_id, i.id FROM incidents i
  WHERE i.status = 'remediating'
    AND (i.hold_until <= now() OR i.verify_until <= now())
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Claim one step attempt whose lease expired.
CREATE FUNCTION nfx_claim_expired_lease()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT a.org_id, a.id FROM step_attempts a
  WHERE a.state IN ('dispatched','running') AND a.lease_expires_at <= now()
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Claim one run past its overall deadline.
CREATE FUNCTION nfx_claim_overdue_run()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT r.org_id, r.id FROM runbook_runs r
  WHERE r.status = 'running' AND r.deadline_at <= now()
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Mark agents offline that have gone quiet.
CREATE FUNCTION nfx_mark_stale_agents(p_after interval DEFAULT '45 seconds')
RETURNS int LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH u AS (
    UPDATE agents SET status = 'offline'
    WHERE status = 'online' AND last_seen_at < now() - p_after
    RETURNING 1
  ) SELECT count(*)::int FROM u
$$;

-- Append a hash-chained audit event for the current org. The counter row lock
-- serializes appends per org so the chain has no forks.
CREATE FUNCTION nfx_audit(p_actor_type text, p_actor_id text, p_action text,
                          p_resource_type text, p_resource_id text, p_data jsonb)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_org uuid := nfx_org();
  v_seq bigint;
  v_prev bytea;
  v_hash bytea;
  v_at timestamptz := clock_timestamp();
BEGIN
  INSERT INTO org_counters (org_id, name, value) VALUES (v_org, 'audit', 0)
  ON CONFLICT (org_id, name) DO NOTHING;
  UPDATE org_counters SET value = value + 1 WHERE org_id = v_org AND name = 'audit'
  RETURNING value INTO v_seq;
  SELECT hash INTO v_prev FROM audit_events WHERE org_id = v_org AND seq = v_seq - 1;
  v_hash := sha256(
    coalesce(v_prev, ''::bytea) ||
    convert_to(concat_ws('|', v_org::text, v_seq::text, v_at::text, p_actor_type, p_actor_id,
                         p_action, p_resource_type, p_resource_id, coalesce(p_data, '{}'::jsonb)::text), 'UTF8'));
  INSERT INTO audit_events (org_id, seq, at, actor_type, actor_id, action, resource_type, resource_id, data, prev_hash, hash)
  VALUES (v_org, v_seq, v_at, p_actor_type, p_actor_id, p_action, p_resource_type, p_resource_id, coalesce(p_data, '{}'::jsonb), v_prev, v_hash);
  RETURN v_seq;
END $$;

-- Re-verify an org's audit chain. Returns the first broken seq, or NULL if intact.
CREATE FUNCTION nfx_verify_audit_chain()
RETURNS bigint LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r record;
  v_prev bytea := NULL;
  v_expect bigint := 1;
BEGIN
  FOR r IN SELECT * FROM audit_events WHERE org_id = nfx_org() ORDER BY seq LOOP
    IF r.seq <> v_expect OR r.prev_hash IS DISTINCT FROM v_prev OR r.hash <> sha256(
         coalesce(v_prev, ''::bytea) ||
         convert_to(concat_ws('|', r.org_id::text, r.seq::text, r.at::text, r.actor_type, r.actor_id,
                              r.action, r.resource_type, r.resource_id, r.data::text), 'UTF8')) THEN
      RETURN r.seq;
    END IF;
    v_prev := r.hash;
    v_expect := v_expect + 1;
  END LOOP;
  RETURN NULL;
END $$;

-- Create an org. Called by the bootstrap CLI before any org exists.
CREATE FUNCTION nfx_create_org(p_id uuid, p_name text, p_slug text)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  INSERT INTO orgs (id, name, slug) VALUES (p_id, p_name, p_slug)
$$;

GRANT EXECUTE ON FUNCTION
  nfx_route_api_key(bytea), nfx_route_integration(uuid), nfx_route_enrollment_token(bytea),
  nfx_route_agent(text), nfx_claim_alert_event(), nfx_claim_notification(), nfx_claim_due_incident(),
  nfx_claim_expired_lease(), nfx_claim_overdue_run(), nfx_mark_stale_agents(interval),
  nfx_audit(text, text, text, text, text, jsonb), nfx_verify_audit_chain(), nfx_create_org(uuid, text, text),
  nfx_ensure_partitions(int), nfx_drop_expired_partitions(int, int)
TO nfx_app;

RESET ROLE;
