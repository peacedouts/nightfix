# Nightfix — Core Data Model & API Surface (Draft v1alpha1)

Status: draft for discussion. Unifies the tables sketched in `runbook-schema.md`, `agent-protocol.md` and `alert-incident-model.md` into one Postgres model, defines how tenancy, RBAC and audit work, and outlines the v1 REST API.

---

## 1. Design principles

1. **Tenant isolation is enforced by the database, not just the app.** Every tenant table carries `org_id`, Postgres row-level security (RLS) is forced on, and foreign keys include `org_id`, so a bug in one query can't read or link another org's data.
2. **RLS is for tenancy; RBAC is in the app.** RLS answers "which org's rows can this connection see?" The app's authorization module answers "can this user do this action on this resource?" Mixing the two makes both hard to reason about.
3. **Append-only where it matters.** Audit events, incident timelines, alert events and runbook versions are never updated or deleted by the application.
4. **Retention by partition drop.** High-volume, time-bounded tables are partitioned by time so retention is a cheap `DROP PARTITION`, not a slow `DELETE`.
5. **One Postgres, no extra stores in v1.** Queue, output streaming, and audit all live in Postgres. S3 is used only for long-term audit export.

---

## 2. Conventions

| Topic | Convention |
|---|---|
| Primary keys | UUIDv7 (time-ordered, index-friendly) |
| API IDs | Prefixed and opaque: `org_…`, `svc_…`, `inc_…`, `rb_…`, `run_…`, `agt_…`, `key_…` |
| Human numbers | Incidents get a per-org sequence (`#412`) from an `org_counters` table |
| Timestamps | `timestamptz`, UTC |
| Labels, tags, config | `jsonb` with size caps enforced in the app |
| Foreign keys | Composite `(org_id, id)` for every tenant-to-tenant reference |
| Config deletion | `archived_at` instead of hard delete for config objects (services, runbooks, integrations), so history and audit still resolve |
| Credentials we must hold | Encrypted with envelope encryption: a per-org data key wrapped by AWS KMS |

### 2.1 A clarification to the core principle

The core principle says the control plane never holds customer secrets. That stays true for **infrastructure secrets and credentials used during execution**, which live only in the customer's account.

The control plane does have to hold a small set of **notification and integration credentials**: a PagerDuty routing key, a Slack bot token, our own HMAC secrets for webhook ingest. These are narrowly scoped (a PagerDuty routing key can only create events), encrypted per org with KMS envelope encryption, never returned by the API after creation, and listed explicitly in security documentation. The core principle in plop.md was reworded on Oct 20, 2026 to say exactly this.

---

## 3. Entity overview

```
org ─┬─ org_members ─ users (global, Auth0 identity)
     ├─ teams ─ team_members
     ├─ role_bindings (user|team|api_key → role → scope)
     ├─ api_keys
     │
     ├─ signing_keys, org_trust_config
     ├─ enrollment_rules ─ agents
     ├─ enrollment_challenges
     │
     ├─ runbooks ─ runbook_versions ─ runbook_signatures
     │      └─ runbook_triggers (denormalized for matching)
     ├─ runbook_runs ─ step_attempts ─ step_output_chunks
     │      └─ approval_gates ─ approvals
     ├─ critical_hold_grants
     │
     ├─ integrations ─ alert_events
     ├─ services ─ routing_rules, maintenance_windows, escalation_targets
     ├─ alerts ─ incident_alerts ─ incidents ─ incident_timeline
     │                                  └─ notifications (outbox)
     │
     ├─ slack_apps, slack_user_links, slack_link_codes
     ├─ approval_channels
     └─ audit_events
```

---

## 4. Tables

Columns are the important ones, not exhaustive. Every tenant table also has `org_id`, `created_at`, `updated_at`.

### 4.1 Tenancy and identity

| Table | Key columns | Notes |
|---|---|---|
| `orgs` | `id`, `name`, `slug`, `auth0_org_id`, `plan`, `frozen_at`, `frozen_by` | `frozen_at` is the org kill switch |
| `users` | `id`, `auth0_sub` (unique), `email`, `name` | **Global**, not tenant-scoped; a user can belong to several orgs. No RLS; only readable via joins through `org_members` |
| `org_members` | `org_id`, `user_id`, `status`, `joined_at` | Membership only; permissions come from role bindings |
| `teams` | `id`, `name`, `slug`, `auth0_group` | `auth0_group` maps an IdP group claim to this team |
| `team_members` | `team_id`, `user_id`, `source` (`manual` \| `idp`) | `idp` rows are synced from Auth0 claims on login; SCIM later |
| `role_bindings` | `id`, `subject_type` (`user` \| `team` \| `api_key`), `subject_id`, `role`, `scope` (jsonb) | See section 5 |
| `api_keys` | `id`, `name`, `prefix`, `hash`, `created_by`, `expires_at`, `last_used_at`, `revoked_at` | Secret shown once; stored as SHA-256 hash. Permissions come from a role binding with `subject_type = api_key` |
| `org_counters` | `org_id`, `name`, `value` | Per-org sequences, e.g. incident numbers |

### 4.2 Trust and agents

| Table | Key columns | Notes |
|---|---|---|
| `signing_keys` | `key_id`, `owner` (`control_plane` \| `customer`), `kms_key_arn`, `public_key`, `state` (`active` \| `retiring` \| `retired`), `rotated_from` | Customer keys store only the public key |
| `org_trust_config` | `org_id`, `required_signers` (key_id[]), `version`, `signature` | Signed by the current control-plane key; agents may pin their own list locally |
| `enrollment_rules` | `id`, `method` (`iam` \| `token`), `aws_account_id`, `role_arn`, `token_hash`, `labels`, `max_agents`, `expires_at` | Labels always come from the rule |
| `enrollment_challenges` | `nonce_hash`, `org_id`, `expires_at` | Single-use nonces for IAM enrollment; bound into the signed STS request so it can't be replayed (built) |
| `agents` | `id`, `enrollment_rule_id`, `labels`, `status` (`online` \| `offline` \| `revoked`), `version`, `capabilities`, `slots`, `allowlist_mode`, `cert_serial`, `cert_expires_at`, `last_seen_at`, `frozen_local` | `frozen_local` is reported by the agent, not set by us |

### 4.3 Runbooks and runs

| Table | Key columns | Notes |
|---|---|---|
| `runbooks` | `id`, `name` (unique per org), `title`, `team_id`, `tags`, `latest_version`, `archived_at` | Mutable header used for listing and RBAC attributes |
| `runbook_versions` | `id`, `runbook_id`, `version`, `digest`, `canonical_json`, `source_yaml`, `source` (`api` \| `ui` \| `terraform` \| `git`), `source_ref`, `published_by` | **Immutable.** `source_ref` is a Git commit SHA or Terraform workspace, when known |
| `runbook_signatures` | `version_id`, `key_id`, `signature`, `signed_at` | Control-plane signature at publish; customer co-signatures added later |
| `runbook_triggers` | `runbook_id`, `version`, `type`, `mode`, `match`, `services`, `before_paging`, `cooldown`, `max_runs_per_hour` | **Denormalized** from the latest version so trigger matching is one indexed query |
| `critical_hold_grants` | `id`, `runbook_id`, `service_id`, `granted_by`, `granted_at`, `track_record_snapshot`, `last_verified_run_at`, `revoked_at`, `revoked_reason` | One active grant per (runbook, service) |
| `runbook_runs` | `id`, `runbook_version_id`, `digest`, `incident_id`, `trigger_type`, `mode`, `requested_by_type` (`user` \| `api_key` \| `trigger`), `requested_by_id`, `params`, `status`, `before_paging`, `held_critical`, `verified`, `started_at`, `finished_at` | `params` never contains secret values |
| `step_attempts` | `id`, `run_id`, `step_id`, `attempt_number`, `state`, `agent_id`, `lease_expires_at`, `exit_code`, `outputs`, `error`, `started_at`, `finished_at` | The agent work queue (`SKIP LOCKED`) |
| `approval_gates` | `id`, `run_id`, `step_index`, `step_id`, `required_count` (1–10), `from_roles`, `exclude_requester`, `status` (`pending` \| `approved` \| `rejected` \| `expired` \| `cancelled`), `requested_at`, `expires_at`, `decided_at` | One per approval step per run (built; semantics in `runbook-schema.md` §9) |
| `approvals` | `id`, `run_id`, `step_id`, `approver_id`, `decision` (`approved` \| `rejected`), `comment`, `decided_at`, `expires_at` | One decision per person per gate. DB trigger: approver ≠ requester when the gate sets `exclude_requester` |
| `step_output_chunks` | `attempt_id`, `seq`, `stream`, `data`, `received_at` | **Partitioned by day**, 90-day default retention; 1 MiB cap per attempt |

**Trigger-to-service links (decided Oct 20, 2026):** runbook triggers carry an optional `services:` list, required for `auto` triggers. `runbook_triggers.services` is indexed (GIN) so the control plane can find a service's triggers in one query when an incident opens.

### 4.4 Alerts and incidents

| Table | Key columns | Notes |
|---|---|---|
| `integrations` | `id`, `type`, `name`, `default_service_id`, `severity_map`, `dedupe_keys`, `credential` (encrypted), `archived_at` | |
| `alert_events` | `id`, `integration_id`, `received_at`, `raw`, `processed_at`, `error` | **Partitioned by day**, 30-day retention; append-only |
| `services` | `id`, `name`, `team_id`, `grouping_labels`, `grouping_window`, `max_hold`, `auto_resolve`, `reopen_window`, `verification_window`, `slack_channel_id`, `archived_at` | Catch-all service created with every org |
| `routing_rules` | `id`, `priority`, `match`, `service_id`, `action` (`route` \| `suppress`), `version` | Each change creates a new version; old versions kept |
| `maintenance_windows` | `id`, `service_id`, `starts_at`, `ends_at`, `recurrence`, `created_by` | |
| `escalation_targets` | `id`, `service_id`, `type` (`pagerduty` \| `incidentio` \| `slack` \| later `native`), `config`, `credential` (encrypted) | |
| `alerts` | `id`, `fingerprint`, `integration_id`, `service_id`, `status`, `severity`, `summary`, `labels`, `annotations`, `first_seen_at`, `last_seen_at`, `resolved_at`, `event_count` | |
| `incidents` | `id`, `number`, `service_id`, `group_key`, `status`, `severity`, `title`, `opened_at`, `ack_at`, `ack_by`, `resolved_at`, `resolution`, `hold_until`, `upstream_refs` | `upstream_refs` stores PagerDuty / incident.io IDs for auto-resolve |
| `incident_alerts` | `incident_id`, `alert_id`, `attached_at`, `detached_at` | Join table so an alert's history across incidents is kept |
| `incident_timeline` | `id`, `incident_id`, `at`, `type`, `actor_type`, `actor_id`, `data` | Append-only |
| `notifications` | `id`, `incident_id`, `target_id`, `channel_id`, `kind` (`page` \| `resolve` \| `update` \| `approval`), `payload`, `status` (`pending` \| `sent` \| `failed`), `attempts`, `next_attempt_at`, `lease_until`, `lease_id`, `last_error`, `sent_at` | Outbox for upstream pages and Slack posts (built). Workers claim a row on a short lease and send outside any transaction; the result is recorded only under the same `lease_id`. Rows for one incident+target, or one approval channel, go out in order. Pages and resolves retry for up to 24h |
| `slack_apps` | `id`, `team_id` (Slack workspace; requests from others are refused), `signing_secret` (sealed), `archived_at` | The org's Slack app, used to verify button clicks and slash commands (built) |
| `slack_user_links` | `slack_team_id`, `slack_user_id`, `user_id`, `linked_at` | Links a Slack user to a Nightfix member; created only by a one-time code (built) |
| `slack_link_codes` | `code_hash`, `user_id`, `expires_at` | One-time codes Nightfix issues to a signed-in user for `/nightfix link <code>` (built) |
| `approval_channels` | `id`, `team_id` (null = org default), `type` (`slack`), `credential` (sealed webhook URL), `created_by` | Where approval requests go for runs outside an incident (built) |

**Concurrency-critical indexes:**

```sql
-- one open alert per fingerprint
CREATE UNIQUE INDEX alerts_open_fingerprint
  ON alerts (org_id, fingerprint) WHERE status <> 'resolved';

-- one open incident per service + group key
CREATE UNIQUE INDEX incidents_open_group
  ON incidents (org_id, service_id, group_key) WHERE status <> 'resolved';

-- agent work queue
CREATE INDEX step_attempts_queue
  ON step_attempts (org_id, state, lease_expires_at) WHERE state IN ('queued', 'dispatched');
```

Ingest uses `INSERT … ON CONFLICT` against these indexes, so two events for the same alarm arriving at once can't create two alerts or two incidents.

### 4.5 Audit

| Table | Key columns | Notes |
|---|---|---|
| `audit_events` | `id`, `at`, `actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`, `data`, `request_id`, `source_ip`, `prev_hash`, `hash` | **Partitioned by month**, ≥ 1-year retention |

Immutability is enforced three ways:

1. **Grants:** the application's database role has `INSERT` and `SELECT` on audit tables, and no `UPDATE` or `DELETE`.
2. **Hash chain:** each event stores the SHA-256 of the previous event in the same org plus its own content, so tampering or deletion is detectable.
3. **Export:** partitions are exported nightly to an S3 bucket with Object Lock (compliance mode) before they're eligible to drop.

Audited actions include every permission change, API key event, runbook publish, run, approval, grant, freeze, enrollment, routing rule change and maintenance window.

---

## 5. RBAC

### 5.1 Roles (fixed set in v1)

| Role | Can do |
|---|---|
| **Owner** | Everything, including billing, deleting the org, and managing Owners |
| **Admin** | Manage members, teams, roles, API keys, integrations, services, agents, enrollment, signing config, critical-hold grants, freeze |
| **Responder** | Acknowledge/resolve incidents, run runbooks, approve steps, publish runbooks — all within scope |
| **Viewer** | Read incidents, runbooks, runs and timelines within scope. **Free seats** |

### 5.2 Scopes

A role binding's `scope` narrows where the role applies. Omitted fields mean "any."

```json
{ "teams": ["payments"], "tags": ["payments"], "env": ["staging", "dev"] }
```

- `teams` matches the resource's owning team (runbook, service, incident's service).
- `tags` matches runbook tags.
- `env` matches the target agent's `env` label for runs and approvals.

A user's effective permissions are the **union** of all bindings that reach them: their own and their teams'.

**Example:** "Team Payments can run runbooks tagged `payments`, but only Admins can run against `env=prod`":

| Subject | Role | Scope |
|---|---|---|
| team `payments` | Responder | `{ "tags": ["payments"], "env": ["staging", "dev"] }` |
| team `platform-admins` | Admin | `{}` |

### 5.3 Enforcement

- Every API handler calls `authz.Check(principal, action, resource)` before touching data. The resource carries its attributes (team, tags, target env).
- **List endpoints filter in SQL** using the caller's bindings, so pagination stays correct and nothing out of scope is ever returned.
- Run-time checks happen twice: when a run is requested (can this principal start it against this target?) and again when each approval is given.
- Auto-triggered runs execute as the **trigger principal**, which is authorized by whoever published the runbook version and its triggers. A runbook version whose publisher has since lost permission stays runnable until re-published or archived; this is shown in the UI.

---

## 6. Row-level security mechanics

```sql
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON incidents
  USING (org_id = current_setting('app.org_id')::uuid)
  WITH CHECK (org_id = current_setting('app.org_id')::uuid);
```

- The app connects as a role that **does not own** the tables, so RLS can't be bypassed by ownership.
- Every request runs in a transaction that starts with `SET LOCAL app.org_id = '<org>'`, taken from the authenticated principal, never from request input.
- Background workers (ingest processor, dispatcher, timers) claim a job, then `SET LOCAL app.org_id` to the job's org before doing anything else.
- If `app.org_id` isn't set, `current_setting` errors and the query fails closed.
- A separate `ops_admin` role with `BYPASSRLS` exists for our own support tooling only. Every session with it is audit-logged.
- Composite foreign keys `(org_id, id)` mean that even an RLS bypass couldn't link one org's incident to another org's service.

The ingest endpoint resolves the org from the integration ID before setting `app.org_id`. That lookup reads a small `integration_routes` table outside RLS that holds only `integration_id → org_id`.

---

## 7. Retention summary

| Data | Retention | Mechanism |
|---|---|---|
| Raw alert events | 30 days | Daily partitions, dropped |
| Step output chunks | 90 days (configurable per org) | Daily partitions, dropped |
| Audit events | ≥ 1 year (configurable upward) | Monthly partitions, exported to S3 Object Lock, then dropped |
| Incident timeline | ≥ 1 year | Kept with incidents |
| Alerts, incidents, runs, attempts, approvals | ≥ 1 year | Kept; archival policy later |
| Runbook versions and signatures | Forever while the runbook exists | Never dropped |

---

## 8. API surface (v1)

### 8.1 Conventions

| Topic | Convention |
|---|---|
| Base | `https://api.nightfix.dev/v1` |
| Auth | Auth0 access token (users) or `Authorization: Bearer nfx_<key>` (API keys) |
| Org | Inferred from the token; API keys belong to one org. Users in several orgs pass `Nightfix-Org: org_…` |
| Pagination | Cursor-based: `?limit=50&cursor=…` |
| Idempotency | `Idempotency-Key` header on every `POST`, stored 24h |
| Concurrency | `ETag` on reads; `If-Match` required on `PATCH`/`PUT` of config objects |
| Errors | RFC 9457 `application/problem+json` |
| Rate limits | Per API key and per user; `429` with `Retry-After` |
| Spec | OpenAPI 3.1 is the source of truth; the CLI and Terraform provider are generated from it |

### 8.2 Resources

**Identity and access**

| Method | Path | Purpose |
|---|---|---|
| GET | `/me` | Current principal, orgs, effective permissions |
| GET, POST | `/members` | List / invite members |
| PATCH, DELETE | `/members/{id}` | Update / remove |
| GET, POST | `/teams` | List / create teams |
| GET, PATCH, DELETE | `/teams/{id}` | Read / update / archive |
| PUT, DELETE | `/teams/{id}/members/{user_id}` | Manage manual membership |
| PUT | `/org/auth0` | Connect the org's Auth0 Organization (built) |
| POST | `/me/slack-link-code` | Issue a one-time code to link the caller's Slack user (built) |
| GET, POST | `/role-bindings` | List / create bindings |
| DELETE | `/role-bindings/{id}` | Remove |
| GET, POST | `/api-keys` | List / create (secret returned once) |
| DELETE | `/api-keys/{id}` | Revoke |

**Agents and trust**

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `/enrollment-rules` | List / create IAM or token rules |
| DELETE | `/enrollment-rules/{id}` | Revoke |
| GET | `/agents` | List with health, labels, version |
| GET | `/agents/{id}` | Detail |
| POST | `/agents/{id}/revoke` | Revoke an agent |
| GET, PUT | `/trust-config` | Required signers |
| GET, POST | `/signing-keys` | List / register a customer public key |
| POST | `/org/freeze`, `/org/unfreeze` | Org kill switch (Admin) |

**Runbooks and runs**

| Method | Path | Purpose |
|---|---|---|
| GET | `/runbooks` | List (scope-filtered) |
| POST | `/runbooks/validate` | Lint and validate YAML without publishing (used by the editor) |
| POST | `/runbooks/dry-run` | Resolve params against a sample alert; executes nothing |
| PUT | `/runbooks/{name}` | Publish a new version (idempotent on identical digest) |
| GET | `/runbooks/{name}` | Header + latest version |
| GET | `/runbooks/{name}/versions` | Version history |
| GET | `/runbooks/{name}/versions/{v}` | One version, with digest and signatures |
| POST | `/runbooks/{name}/versions/{v}/signatures` | Add a customer co-signature |
| POST | `/runbooks/{name}/archive` | Archive |
| GET, POST | `/runbooks/{name}/critical-hold-grants` | Track record + grant (Admin) |
| DELETE | `/critical-hold-grants/{id}` | Revoke |
| POST | `/runs` | Start a run: runbook, version (optional), params, incident (optional) |
| GET | `/runs` | List (filter by runbook, incident, status) |
| GET | `/runs/{id}` | Run detail with steps |
| GET | `/runs/{id}/steps/{step_id}/output` | Output; supports `Accept: text/event-stream` for live streaming |
| POST | `/runs/{id}/cancel` | Cancel |
| POST | `/runs/{id}/steps/{step_id}/approve`, `/reject` | Approval decisions |
| GET | `/approvals` | Pending approvals the caller can decide (built) |
| GET, PUT | `/approval-channels` | Org-default and per-team approval channels (built) |
| POST | `/runs/{id}/steps/{step_id}/confirm` | Complete a `manual` checklist step |

**Alerts and incidents**

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `/integrations` | List / create (returns ingest URL and credential once) |
| GET, PATCH, DELETE | `/integrations/{id}` | Read / update / archive |
| GET, POST | `/services` | List / create |
| GET, PATCH, DELETE | `/services/{id}` | Read / update / archive |
| GET, PUT | `/routing-rules` | Read / replace the ordered rule set (creates a new version) |
| GET, POST | `/services/{id}/maintenance-windows` | List / create |
| DELETE | `/maintenance-windows/{id}` | Remove |
| GET, POST | `/services/{id}/escalation-targets` | List / configure upstream pager or Slack |
| POST | `/slack-apps` | Register the org's Slack app (signing secret); returns the interactivity and command URLs (built) |
| POST | `/slack/interactions/{id}`, `/slack/commands/{id}` | Called by Slack; authenticated by Slack's request signature, not a token (built) |
| GET | `/alerts` | List (filters: status, service, severity) |
| GET | `/alerts/{id}` | Detail with recent events |
| GET | `/incidents` | List |
| GET | `/incidents/{id}` | Detail |
| GET | `/incidents/{id}/timeline` | Timeline |
| POST | `/incidents/{id}/acknowledge`, `/resolve`, `/reopen` | Lifecycle actions |
| POST | `/incidents/{id}/merge` | Merge another incident into this one |
| POST | `/incidents/{id}/notes` | Add a timeline note |

**Ingest** (separate host, separate service)

| Method | Path | Purpose |
|---|---|---|
| POST | `https://ingest.nightfix.dev/v1/i/{integration_id}` | Receive alerts; returns `202` |

**Audit**

| Method | Path | Purpose |
|---|---|---|
| GET | `/audit-events` | Search audit log (Admin) |
| POST | `/audit-events/export` | Export a time range as JSON Lines |

### 8.3 Terraform provider mapping

| Terraform resource | API |
|---|---|
| `nightfix_team`, `nightfix_team_membership` | `/teams` |
| `nightfix_role_binding` | `/role-bindings` |
| `nightfix_api_key` | `/api-keys` |
| `nightfix_enrollment_rule` | `/enrollment-rules` |
| `nightfix_runbook` | `PUT /runbooks/{name}` (YAML or HCL-encoded spec) |
| `nightfix_service` | `/services` |
| `nightfix_routing_rules` | `PUT /routing-rules` (one resource for the ordered set) |
| `nightfix_integration` | `/integrations` |
| `nightfix_escalation_target` | `/services/{id}/escalation-targets` |
| `nightfix_maintenance_window` | `/services/{id}/maintenance-windows` |

Data sources: `nightfix_agents`, `nightfix_runbook_version`, `nightfix_service`.

Not exposed to Terraform on purpose: critical-hold grants (they depend on live track record) and freeze (an emergency action, not configuration).

---

## 9. Open questions

1. **Routing rules: one ordered set per org, or per integration?** Per org is simpler to reason about; per integration avoids one team's rule shadowing another's.
2. **Custom roles.** Fixed roles plus scopes should cover v1. When will a customer need a custom role, and is it a premium feature?
3. **Multi-org users.** How common will consultants or agencies belonging to several orgs be? It affects the `Nightfix-Org` header and the UI org switcher.
4. **Region.** Is v1 US-only (`us-east-1` primary, `us-west-2` for the notification path), with EU data residency later?
5. **Long-term archival** of alerts, incidents and runs beyond one year: keep forever on paid plans, or archive to S3 after a period?
