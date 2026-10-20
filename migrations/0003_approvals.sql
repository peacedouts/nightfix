-- Approval steps: a run pauses at an `approval` step until enough eligible
-- people approve it, anyone eligible rejects it, or it expires. Decisions
-- come from the API or from Slack buttons, so Slack users are linked to
-- Nightfix users through a verified one-time code.

SET ROLE nfx_owner;

ALTER TABLE runbook_runs DROP CONSTRAINT runbook_runs_status_check;
ALTER TABLE runbook_runs ADD CONSTRAINT runbook_runs_status_check
  CHECK (status IN ('running','awaiting_approval','succeeded','failed','timed_out','cancelled','needs_human'));
DROP INDEX runbook_runs_deadline;
CREATE INDEX runbook_runs_deadline ON runbook_runs (deadline_at) WHERE status IN ('running','awaiting_approval');

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('page','resolve','update','approval'));

-- One gate per approval step a run reaches.
CREATE TABLE approval_gates (
  id                 uuid NOT NULL,
  org_id             uuid NOT NULL,
  run_id             uuid NOT NULL,
  step_index         int NOT NULL,
  step_id            text NOT NULL,
  required_count     int NOT NULL CHECK (required_count BETWEEN 1 AND 10),
  from_roles         text[] NOT NULL CHECK (from_roles <@ ARRAY['responder','admin','owner'] AND cardinality(from_roles) > 0),
  exclude_requester  boolean NOT NULL,
  status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired','cancelled')),
  requested_at       timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  decided_at         timestamptz,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, run_id, step_index),
  FOREIGN KEY (org_id, run_id) REFERENCES runbook_runs(org_id, id)
);
CREATE INDEX approval_gates_pending ON approval_gates (expires_at) WHERE status = 'pending';

-- Individual decisions. Append-only: the app role can't change or delete one.
CREATE TABLE approvals (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL,
  gate_id         uuid NOT NULL,
  approver_id     text NOT NULL,          -- usr_… (people only, never API keys)
  approver_email  text NOT NULL,
  decision        text NOT NULL CHECK (decision IN ('approved','rejected')),
  comment         text NOT NULL DEFAULT '',
  via             text NOT NULL CHECK (via IN ('api','slack')),
  decided_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, gate_id, approver_id),  -- one vote per person
  FOREIGN KEY (org_id, gate_id) REFERENCES approval_gates(org_id, id)
);

-- Defense in depth for the rules the application checks: votes only on an
-- open, unexpired gate, and never from the requester when the step says so.
CREATE FUNCTION nfx_check_approval() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
DECLARE g approval_gates%ROWTYPE; r runbook_runs%ROWTYPE;
BEGIN
  SELECT * INTO g FROM approval_gates WHERE org_id = NEW.org_id AND id = NEW.gate_id;
  IF g.status <> 'pending' OR g.expires_at <= now() THEN
    RAISE EXCEPTION 'approval gate is no longer open' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO r FROM runbook_runs WHERE org_id = NEW.org_id AND id = g.run_id;
  IF g.exclude_requester AND r.requested_by_type = 'user' AND r.requested_by_id = NEW.approver_id THEN
    RAISE EXCEPTION 'the requester cannot approve this step' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approvals_check BEFORE INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION nfx_check_approval();

-- A Slack app the org installed for interactive buttons. The signing secret
-- authenticates every request Slack sends us.
CREATE TABLE slack_apps (
  id              uuid NOT NULL,
  org_id          uuid NOT NULL REFERENCES orgs(id),
  team_id         text,                   -- if set, requests from other workspaces are refused
  signing_secret  bytea NOT NULL,         -- sealed
  created_at      timestamptz NOT NULL DEFAULT now(),
  archived_at     timestamptz,
  PRIMARY KEY (org_id, id)
);

-- Slack user → Nightfix user, created only by a signed-in user redeeming a
-- code that Slack's signed request issued to that Slack user.
CREATE TABLE slack_user_links (
  org_id         uuid NOT NULL,
  slack_team_id  text NOT NULL,
  slack_user_id  text NOT NULL,
  user_id        uuid NOT NULL,
  linked_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, slack_team_id, slack_user_id),
  UNIQUE (org_id, slack_team_id, user_id),
  FOREIGN KEY (org_id, user_id) REFERENCES org_members(org_id, user_id)
);

CREATE TABLE slack_link_codes (
  code_hash      bytea NOT NULL,
  org_id         uuid NOT NULL REFERENCES orgs(id),
  slack_team_id  text NOT NULL,
  slack_user_id  text NOT NULL,
  slack_username text NOT NULL DEFAULT '',  -- shown to the redeemer, so they can see whose Slack account they're linking
  expires_at     timestamptz NOT NULL,
  PRIMARY KEY (org_id, code_hash)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['approval_gates','approvals','slack_apps','slack_user_links','slack_link_codes'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nfx_org()) WITH CHECK (org_id = nfx_org())', t);
  END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE ON approval_gates, slack_apps TO nfx_app;
GRANT SELECT, INSERT ON approvals TO nfx_app;
GRANT SELECT, INSERT, DELETE ON slack_user_links, slack_link_codes TO nfx_app;

-- ---------------------------------------------------------------------------
-- Functions
-- ---------------------------------------------------------------------------

-- Map a Slack app (from the interactivity URL) to its org.
CREATE FUNCTION nfx_route_slack_app(p_id uuid)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT a.org_id FROM slack_apps a WHERE a.id = p_id AND a.archived_at IS NULL
$$;

-- Claim one pending approval gate past its expiry.
CREATE FUNCTION nfx_claim_expired_gate()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT g.org_id, g.id FROM approval_gates g
  WHERE g.status = 'pending' AND g.expires_at <= now()
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

-- Runs waiting for approval still have a deadline.
CREATE OR REPLACE FUNCTION nfx_claim_overdue_run()
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT r.org_id, r.id FROM runbook_runs r
  WHERE r.status IN ('running','awaiting_approval') AND r.deadline_at <= now()
  LIMIT 1
  FOR UPDATE SKIP LOCKED
$$;

GRANT EXECUTE ON FUNCTION nfx_route_slack_app(uuid), nfx_claim_expired_gate() TO nfx_app;

RESET ROLE;
