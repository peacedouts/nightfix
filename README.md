# Nightfix

Incident response for startups on AWS: alerts, paging, and runbooks that actually run. The control plane is hosted; a lightweight agent runs in the customer's VPC under the customer's own IAM role, makes outbound connections only, and redacts the infrastructure secrets it resolves from everything it sends (see Agent below for what redaction covers).

This repository is the **walking skeleton**: one thin path through the whole system, end to end.

> A CloudWatch alarm fires → an incident opens → `ecs-service-restart` runs through the agent → the alarm clears → the incident auto-resolves → Slack gets a summary. **Nobody is paged.** If the fix doesn't work, on-call is paged with the run's result and error, and the page resolves itself when the alarm clears.

Design docs: [`docs/design/`](docs/design) (runbook schema, agent protocol, alert-to-incident model, data model).

## Run the demo

Needs Go 1.24+, PostgreSQL 15+ server binaries (`pg_ctl`/`initdb`) and `psql`, `curl` and `python3`.

```bash
make demo        # alarm auto-fixes itself; nobody is paged
make demo-fail   # the fix doesn't work; on-call is paged, then the page auto-resolves
```

Everything runs locally: a throwaway Postgres, the control plane, a real agent connected over mutual TLS, and `devstub`, which simulates ECS (speaking the real AWS JSON protocol; requests must carry a SigV4 Authorization header, and the STS stub verifies signatures), SNS (signed notifications), Slack and PagerDuty. The demo prints the incident timeline and exactly what Slack and PagerDuty received.

## What the slice exercises

| Area | What's real in this build |
|---|---|
| Ingest | CloudWatch via SNS with signature verification (v1/v2) and topic pinning; generic webhook with HMAC + 5-minute replay window, and each signed delivery accepted once (a repeat inside the window is acknowledged and not stored, so a replayed "resolved" can't silence a firing alert). The same body signed in the same second is one delivery; senders that can emit identical payloads that fast should make each body unique (an event id field, say; webhook alerts are timed on receipt). Raw event persisted before processing; `202` returned. |
| Dedupe & routing | Fingerprints (integration + `AlarmArn`, `dedup_key`, label hash), so one integration's messages can't touch another's alerts; events apply in the order they were received (CloudWatch: the order of their state changes), even when a later one commits first, and a CloudWatch state older than one already applied (an ALARM delivered after its OK) is ignored; re-fire within the reopen window reopens; ordered CEL routing rules; catch-all service so nothing is unrouted. Concurrency-safe via partial unique indexes. |
| Incidents | Grouping by service + labels within a window; severity = highest alert; lifecycle `remediating → triggered → acknowledged → resolved`; reopen pages without retrying auto-remediation; append-only timeline. |
| Remediate before paging | Held page bounded by `min(run timeout + verification, max_hold)`; resolves only if the run succeeds **and** alerts clear; pages on failure, timeout, lost agent, expired hold, or still-firing alert. Guardrails: org freeze, no healthy agent, cooldown, `maxRunsPerHour`, more than one auto runbook holding the page (`beforePaging`), no matching agent able to run the runbook's step types, flap guard (3 auto-fixes of one alert in 24h, counting fixes that later reopened). Critical incidents page in parallel, and their auto-fixes count as verified too. A fix whose alert re-fires within the reopen window is un-verified. |
| Notifications | Outbox delivered by concurrent workers on short leases: requests are sent outside any database transaction, so a hanging endpoint delays only its own row. Per-incident ordering (a resolve never overtakes its page) is index-backed. One org has at most a quarter of the workers in flight, and pages and resolves are claimed first. A claimed notification is seen through and recorded even during shutdown, and a worker that stalls past its lease can't send. Pages and resolves retry with backoff capped at 5 min (±20% jitter) for up to 24h, and after 3 failed attempts say so (an Error log line, which alarms, and an entry on the incident's timeline); updates and approval messages 8 times; `Retry-After` is honoured. PagerDuty Events v2 with the incident as `dedup_key`, so acknowledging an incident acknowledges the upstream page and resolving it resolves the page. Slack incoming webhooks. Tenant URLs are limited to `hooks.slack.com` and PagerDuty's event hosts, re-checked at send time, with no redirects and a dialer that refuses private, loopback and metadata addresses (`NIGHTFIX_DEV_ALLOW_PRIVATE_TARGETS=1` lifts this for local stubs). Stored errors are generic and never contain URLs. Credentials sealed per org and per purpose (a sealed value copied into another column, row or org doesn't decrypt); never logged or returned. |
| Runbooks | Strict YAML parsing, the full publish linter (no templating in `run:`, pattern or enum on alert-derived string params (int and bool are type-checked), auto triggers must list services, secrets only in env/files, read-only wait checks…), CEL bounded by a size-aware cost limit and a 250 ms deadline, at most 100 steps / 500 expressions / 10 retries, YAML anchors and aliases refused, `allowedRoles` enforced when a run starts, RFC 8785 canonical digests, Ed25519 signatures, immutable versions. |
| Runs & dispatch | Step-by-step dispatch from a Postgres queue (`SKIP LOCKED`), 30s leases, signed per-step envelopes bound to one agent with a 2-minute expiry. Lost non-idempotent steps go to `needs_human` and page; idempotent ones retry. Run timeouts. |
| Identity | Auth0 login: RS256 access tokens verified against the tenant's JWKS (no `none`/HS256, issuer + audience + expiry checked, key rotation handled). Auth0 Organizations map to orgs; users are provisioned on first login; IdP groups sync to teams. Scoped role bindings (org → teams → roles → scopes) enforced on runs, runbook publishing (including takeover protection) and incident actions; members without a binding are free viewers; only owners can grant admin or owner. API keys for automation: admins create, list and revoke them (`POST /v1/api-keys`, `GET /v1/api-keys`, `POST /v1/api-keys/{id}/revoke`); keys are shown once and stored hashed (a retry with the same `Idempotency-Key` within 24h returns the same response, kept sealed); only owners can create or revoke admin and owner keys; the org's last owner credential can't be revoked (create a new owner key first, then revoke the old one). If an owner key leaks and nobody can rotate it, an operator runs `nightfix org new-owner-key --org org_… --revoke-others` (on AWS: `deploy/scripts/new-owner-key.sh`). |
| Approvals | `approval` steps pause a run (`awaiting_approval`) until `count` people holding one of `fromRoles` (or higher) **within scope of the runbook and its target env** approve; re-checked at decision time; people only, never API keys; `excludeRequester` enforced in the API and by a database trigger; one vote per person; one rejection cancels; expiry times the run out. A held auto-remediation pages as soon as it needs an approval. Approve/reject from the API or Slack buttons: Slack's v0 request signature and 5-minute timestamp window are verified, `response_url` is pinned to Slack's host, and Slack users are linked only by a one-time code issued by Nightfix to the signed-in user and typed into Slack (`/nightfix link`), never by profile email; the code never travels Slack-to-Nightfix, so the device-code phishing pattern doesn't apply. Slack approvals need a sign-in to this org within 7 days so IdP-synced teams stay fresh. Runbooks with `excludeRequester` can't be started by API keys. Freeze cancels waiting runs and blocks decisions; locks are always taken org → run → gate. Requests go to the incident's service Slack targets; runs outside an incident (or services with no Slack target) use the runbook team's approval channel, else the org default (`PUT /v1/approval-channels`); with none of those, the catch-all service's Slack targets, so a request is never sent nowhere. |
| Agent enrollment | **IAM by default**: the agent signs an `sts:GetCallerIdentity` request (never sent by itself) that covers the org and a single-use challenge nonce; the control plane builds the STS URL itself (no SSRF), has STS verify the signature, and matches account + role to an enrollment rule. Nothing long-lived to leak, no persistent disk needed. Denials are audited once the caller has proved an AWS identity (no matching rule, a revoked identity, a rule at `max_agents`) or holds a valid token; refusals before that (an invalid proof or token) aren't, so unauthenticated callers can't fill an org's audit log. Token enrollment remains as a fallback: a token lives at most 7 days and enrolls at most `max_agents` agents over its life. Agents and enrollment rules can be revoked (`POST /v1/agents/{id}/revoke`, `POST /v1/enrollment-rules/{id}/revoke`, optionally with its agents); a revoked rule's agents can't renew their certificates. |
| Agent | Key generated locally (CSR only), 24h mTLS certs with renewal, re-verification of everything before running (envelope signature, target agent, expiry, replay, bundle digest, **every required signer — locally pinned list wins**, allowlist — pinned by digest, since version numbers aren't signed — params, target labels). `aws` (SigV4 JSON-protocol calls), `wait`, and `shell` steps (minimal env, process-group kill on timeout). Secrets from Secrets Manager / SSM resolved on the agent and redacted from output and outputs, including values returned by `GetSecretValue`, SSM `SecureString` reads and KMS `Decrypt`, in plain, hex, base64 (at any offset for values of 7 bytes or more, wrapped at any width or not), URL- and JSON-escaped forms, across chunk boundaries; for a JSON secret, its secret fields rather than connection details. Redaction covers how tools print a secret, not a script that deliberately disguises one (reversing it, say): runbooks are signed and reviewed for that. Outputs over 1 MiB fail the step. Local freeze flag. |
| Tenancy & audit | Forced row-level security on every tenant table, app role that owns nothing, composite `(org_id, id)` foreign keys, `SECURITY DEFINER` functions as the only cross-tenant path. Hash-chained, append-only audit log (the app role can't update or delete it), verified on request (`GET /v1/audit-events?verify=true`, one at a time per org). |

## Deliberate differences from the design docs

These are scoped out of the skeleton, not changes of direction:

- **Agent transport** is mutual-TLS HTTPS with long-polling, not a gRPC stream. Messages, signatures, leases and failure semantics follow `agent-protocol.md`; swapping the transport doesn't change them.
- **Keys**: with `NIGHTFIX_KMS_KEY_ID` set (as in the AWS deployment), the credential-sealing key is a KMS-wrapped data key and the agent CA lives in Postgres with its key sealed; locally, files in the state dir stand in. The agent CA is ours rather than AWS Private CA, and per-org runbook signing keys are sealed in Postgres rather than held in KMS. Signing-key rotation chaining isn't built; the agent accepts trust-config updates from the authenticated control plane, so pin `--required-signers` for the full guarantee.
- **RBAC on reads**: scopes restrict writes (runs, publishing, incident actions); list endpoints aren't filtered by scope yet, so any member can view every incident and runbook. SCIM and custom roles come later.
- **Login is cached nowhere**: each request with a user token re-syncs the user and their IdP teams. Fine for now; it'll want a short-lived session cache at scale.
- **Critical-hold grants** (decision #29) aren't built, so critical incidents always page in parallel, which is the documented default.
- **Step types**: `note`, `approval`, `shell`, `aws`, `wait`. `manual`, `python`, `http`, `container` and SSM execution are valid schema but rejected at publish until implemented. AWS calls support JSON-protocol services (ECS, Secrets Manager, SSM, DynamoDB, Logs, KMS); RDS and other Query/XML services aren't supported yet.
- **Approvals are enforced by the control plane.** The agent runs the step after an approval because the control plane dispatched it; it doesn't yet verify signed approval evidence itself. Requiring your own runbook signature still bounds what can run.
- `when:` is evaluated on the control plane, so it can't reference `target` yet (the linter rejects it).
- **API keys** have no expiry or scopes of their own yet: a key has one role, org-wide, until it's revoked (a role binding can add scoped roles to a key).
- **Notifications**: a page for a resolved incident stops after 8 failed attempts or 10 minutes; no 4xx is treated as permanent, so a page with a bad routing key retries for up to 24h. The notification client ignores `HTTPS_PROXY` (the address check must see the real destination).
- **Migration 0020** drops the old notification claim outright, which is safe only because nothing is deployed yet; later changes like it should keep a compatible shim for a release.
- No UI, no native paging (SMS/voice), no Terraform provider, no Git sync — all later phases.

## Layout

```
cmd/nightfix          control plane: migrate | org create | serve
cmd/nightfix-agent    customer-side agent
cmd/devstub            simulated ECS, SNS, Slack, PagerDuty (local only)
internal/controlplane  ingest, incidents, runs, dispatch, notifications, API, agent gateway
internal/agent         agent loop, verification, executors, redaction; awscall/ signs AWS calls
internal/runbook       model, parser, linter, params, canonical form
internal/signing       bundles, envelopes, trust config, credential sealer
internal/auth0         Auth0 access-token verification (JWKS, RS256); auth0test/ is a fake tenant
internal/expr          CEL and ${{ }} templates
internal/db            pool, per-org transactions, claims, migrator
migrations/            schema, RLS policies, grants, SECURITY DEFINER functions (never edit a shipped one; add a new file)
deploy/                Terraform (control plane, agent module) and the deployment guide
teaser/                the pre-launch site on nightfix.dev (deployed by the root wrangler.jsonc)
examples/runbooks/     ecs-service-restart.yaml
internal/e2e           end-to-end tests of the whole loop
```

## Deploying

`deploy/` has the Terraform for the hosted control plane (VPC, RDS, KMS, ECS Fargate, ALB + NLB, Cloudflare DNS), the customer agent module, and the GitHub workflows that build, sign and roll out images. Start with [deploy/README.md](deploy/README.md).

The database schema runs on managed Postgres without a superuser: CI runs every test as an RDS-like admin (`CREATEROLE CREATEDB` plus `pg_signal_backend`, like the RDS master user).

## Operating it

- `GET /healthz` is liveness only and never touches the database (a database outage mustn't make the orchestrator restart every instance). `GET /readyz` checks the database.
- Every listener sets header, read, write and idle timeouts; the agent gateway's write timeout outlasts a long poll.
- `GET /v1/integrations` lists ingest URLs and, for CloudWatch, the pinned topic. It flags an integration with no topic (it accepts nothing) and shows the last correctly signed delivery it refused for its topic; fix either with `PUT /v1/integrations/{id}/topic`.
- `GET /v1/runs/{id}` returns a 64 KiB tail of each attempt's output (1 MiB across the run, with `output_bytes` and `output_truncated`); the whole output of one attempt is at `GET /v1/runs/{id}/steps/{step}/attempts/{n}/output`. Incident timelines are paged with `?after=<id>&limit=`; a page also stops at about 1 MiB of messages, so read until a page comes back empty.
- Background workers record a row that keeps failing (`worker_failures`, `worker_error`, `worker_retry_at`) and back off from it, rather than retrying it forever or stopping the loop.

## Running against real AWS by hand

1. Postgres: `NIGHTFIX_ADMIN_DATABASE_URL=… NIGHTFIX_APP_DB_PASSWORD=… nightfix migrate`, then run `nightfix serve` with `NIGHTFIX_DATABASE_URL` pointing at `nfx_app`. See `cmd/nightfix/main.go` for every setting. Expose `NIGHTFIX_INGEST_ADDR` for SNS (HTTPS in front of it) and `NIGHTFIX_AGENT_ADDR` for agents. Set `NIGHTFIX_PUBLIC_INGEST_URL` to the public ingest URL (integrations return it), `NIGHTFIX_AGENT_TLS_HOSTS` to the gateway's hostname (its certificate defaults to localhost), and `NIGHTFIX_KMS_KEY_ID` to keep the sealing key in KMS rather than the state dir; run `org create` with the same settings.
2. `nightfix org create --name Acme --slug acme` prints an owner API key.
3. Create a service, escalation targets and a `cloudwatch` integration via the API (the demo script shows each call). CloudWatch integrations require `topic_arn` (`arn:aws:sns:<region>:<account>:<topic>`); only that topic's notifications are accepted. Subscribe the integration's ingest URL to your SNS topic; the subscription is confirmed automatically after its signature is verified. Set the topic's signature version to 2 (SHA-256; `signature_version = 2` in Terraform); version 1 (SHA-1, AWS's default) is accepted too.
4. Create an IAM enrollment rule for the agent's role, then run the agent in your VPC under that role. The role needs whatever your runbooks call — for the example, `ecs:DescribeServices` and `ecs:UpdateService` on the target service. `sts:GetCallerIdentity` needs no permission.
   ```bash
   curl -X POST $API/v1/enrollment-rules -H "Authorization: Bearer $KEY" \
     -d '{"method":"iam","role_arn":"arn:aws:iam::<account>:role/nightfix-agent","labels":{"env":"prod"},"max_agents":4}'

   nightfix-agent --endpoint https://<gateway>:8443 --ca-file ca.crt --org org_… \
     --required-signers <key_id>=<base64 public key>
   ```
   `ca.crt` is the gateway's CA certificate, from `GET /v1/agent-ca.pem`.
   Pin each signer as `key_id=base64-public-key` (`nightfix org create` prints it, and `GET /v1/signing-keys` returns it as `agent_pin`): with the key itself pinned, the control plane can't swap in a different key under the same id. A bare `key_id` only requires that some key with that id signed. Rules match on account + role name (STS's assumed-role ARN doesn't carry the role's path). For hosts without an IAM role, use `"method":"token"` and `--enroll-method token --enroll-token …`.
5. Publish `examples/runbooks/ecs-service-restart.yaml` with `PUT /v1/runbooks/ecs-service-restart`, editing `services:` and the CloudWatch alarm name in `match:` to fit. Name the alarm's dimensions `ClusterName` and `ServiceName` (aliased to `alert.labels.cluster` / `.service`).

## User login with Auth0

1. In Auth0, create an **API** whose identifier is your audience (e.g. `https://api.nightfix.dev`), and enable **Organizations**. Create an Auth0 Organization per customer.
2. Add a post-login **Action** that puts the user's email and groups into the access token:
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.accessToken.setCustomClaim("https://nightfix.dev/email", event.user.email);
     api.accessToken.setCustomClaim("https://nightfix.dev/email_verified", event.user.email_verified);
     api.accessToken.setCustomClaim("https://nightfix.dev/groups", event.user.app_metadata.groups || []);
   };
   ```
   (Source groups from wherever your IdP provides them; `app_metadata.groups` is just an example.)
3. Run the control plane with `NIGHTFIX_AUTH0_DOMAIN=<tenant>.us.auth0.com` and `NIGHTFIX_AUTH0_AUDIENCE=https://api.nightfix.dev`.
4. Link the Auth0 Organization to the Nightfix org. This is an operator step, done once the customer has shown they control it (an Auth0 org id isn't secret, so the API won't let an org's owner claim one): `nightfix org link-auth0 --org org_… --auth0-org org_…` (on AWS: `deploy/scripts/link-auth0.sh org_… org_…`, which runs it as a one-off admin task). Then, with the owner API key, create teams mapped to groups (`POST /v1/teams {"slug":"payments","auth0_group":"payments-eng"}`), and grant roles:
   ```json
   POST /v1/role-bindings
   {"subject_type":"team","subject":"payments","role":"responder",
    "scope":{"tags":["payments"],"env":["staging","dev"]}}
   ```
   That's the data model's example: Team Payments can run runbooks tagged `payments` outside prod; only admins run against `env=prod`.

## Tests

```bash
make test        # starts a throwaway Postgres on :54329 unless NIGHTFIX_TEST_ADMIN_DSN is set
make test-race   # what CI runs: race detector, shuffled order, coverage summary (fails under 80%)
```

CI also runs `govulncheck`, and both demos with `DEMO_CHECK=1`, which fails if the demo's story (auto-fixed with nobody paged; or paged, then resolved upstream) didn't happen. Run the tests as CI does, as a non-superuser admin (`CREATEROLE CREATEDB`): a superuser bypasses row-level security, so some failures only show up that way.

The end-to-end tests cover: IAM enrollment (and its rejection of an unmatched role, a replayed nonce, an org/nonce that isn't inside the signature, a different STS action, and a forged signature), token enrollment as a fallback, scoped RBAC through Auth0 tokens (including republish takeover, privilege escalation, unlinked orgs, wrong audience, and group removal), auto-remediation with no page, a failed fix that pages and then auto-resolves upstream, an injection attempt in alert labels (refused by the parameter pattern; no ECS call is made), and forged or wrong-topic SNS messages (rejected before anything is stored). The database tests cover RLS isolation, cross-org write rejection, fail-closed queries without an org, composite foreign keys, and the audit chain.
