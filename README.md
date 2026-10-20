# Nightfix

Incident response for startups on AWS: alerts, paging, and runbooks that actually run. The control plane is hosted; a lightweight agent runs in the customer's VPC under the customer's own IAM role, makes outbound connections only, and never sends infrastructure secrets anywhere.

This repository is the **walking skeleton**: one thin path through the whole system, end to end.

> A CloudWatch alarm fires → an incident opens → `ecs-service-restart` runs through the agent → the alarm clears → the incident auto-resolves → Slack gets a summary. **Nobody is paged.** If the fix doesn't work, on-call is paged with the run output, and the page resolves itself when the alarm clears.

Design docs: [`docs/design/`](docs/design) (runbook schema, agent protocol, alert-to-incident model, data model).

## Run the demo

Needs Go 1.24+, PostgreSQL 15+ server binaries (`pg_ctl`/`initdb` on the machine), `curl` and `python3`.

```bash
make demo        # alarm auto-fixes itself; nobody is paged
make demo-fail   # the fix doesn't work; on-call is paged, then the page auto-resolves
```

Everything runs locally: a throwaway Postgres, the control plane, a real agent connected over mutual TLS, and `devstub`, which simulates ECS (speaking the real AWS JSON protocol, SigV4-signed requests required), SNS (signed notifications), Slack and PagerDuty. The demo prints the incident timeline and exactly what Slack and PagerDuty received.

## What the slice exercises

| Area | What's real in this build |
|---|---|
| Ingest | CloudWatch via SNS with signature verification (v1/v2) and topic pinning; generic webhook with HMAC + 5-minute replay window. Raw event persisted before processing; `202` returned. |
| Dedupe & routing | Fingerprints (`AlarmArn`, `dedup_key`, label hash); re-fire within the reopen window reopens; ordered CEL routing rules; catch-all service so nothing is unrouted. Concurrency-safe via partial unique indexes. |
| Incidents | Grouping by service + labels within a window; severity = highest alert; lifecycle `remediating → triggered → acknowledged → resolved`; reopen pages without retrying auto-remediation; append-only timeline. |
| Remediate before paging | Held page bounded by `min(run timeout + verification, max_hold)`; resolves only if the run succeeds **and** alerts clear; pages on failure, timeout, lost agent, expired hold, or still-firing alert. Guardrails: org freeze, no healthy agent, cooldown, `maxRunsPerHour`, more than one auto runbook, flap guard (3 verified fixes in 24h). Critical incidents page in parallel. |
| Notifications | Outbox delivered by a worker with backoff. PagerDuty Events v2 with the incident as `dedup_key`, so upstream pages auto-resolve. Slack incoming webhooks. Credentials sealed per org; never logged or returned. |
| Runbooks | Strict YAML parsing, the full publish linter (no templating in `run:`, pattern/enum on alert-derived params, auto triggers must list services, secrets only in env/files, read-only wait checks…), CEL, RFC 8785 canonical digests, Ed25519 signatures, immutable versions. |
| Runs & dispatch | Step-by-step dispatch from a Postgres queue (`SKIP LOCKED`), 30s leases, signed per-step envelopes bound to one agent with a 2-minute expiry. Lost non-idempotent steps go to `needs_human` and page; idempotent ones retry. Run timeouts. |
| Identity | Auth0 login: RS256 access tokens verified against the tenant's JWKS (no `none`/HS256, issuer + audience + expiry checked, key rotation handled). Auth0 Organizations map to orgs; users are provisioned on first login; IdP groups sync to teams. Scoped role bindings (org → teams → roles → scopes) enforced on runs, runbook publishing (including takeover protection) and incident actions; members without a binding are free viewers; only owners can grant admin or owner. API keys remain for automation. |
| Agent enrollment | **IAM by default**: the agent signs an `sts:GetCallerIdentity` request (never sent by itself) that covers the org and a single-use challenge nonce; the control plane builds the STS URL itself (no SSRF), has STS verify the signature, and matches account + role to an enrollment rule. Nothing long-lived to leak, no persistent disk needed. Denials are audited. Token enrollment remains as a fallback. |
| Agent | Key generated locally (CSR only), 24h mTLS certs with renewal, re-verification of everything before running (envelope signature, target agent, expiry, replay, bundle digest, **every required signer — locally pinned list wins**, allowlist, params, target labels). `aws` (SigV4 JSON-protocol calls), `wait`, and `shell` steps (minimal env, process-group kill on timeout). Secrets from Secrets Manager / SSM resolved on the agent and redacted (plain, base64 and URL-encoded) from output and outputs. Local freeze flag. |
| Tenancy & audit | Forced row-level security on every tenant table, app role that owns nothing, composite `(org_id, id)` foreign keys, `SECURITY DEFINER` functions as the only cross-tenant path. Hash-chained, append-only audit log (the app role can't update or delete it), verified on read. |

## Deliberate differences from the design docs

These are scoped out of the skeleton, not changes of direction:

- **Agent transport** is mutual-TLS HTTPS with long-polling, not a gRPC stream. Messages, signatures, leases and failure semantics follow `agent-protocol.md`; swapping the transport doesn't change them.
- **Keys**: a local CA and a local AES-256-GCM sealer stand in for AWS Private CA and KMS envelope encryption. Signing-key rotation chaining isn't built; the agent accepts trust-config updates from the authenticated control plane, so pin `--required-signers` for the full guarantee.
- **RBAC on reads**: scopes restrict writes (runs, publishing, incident actions); list endpoints aren't filtered by scope yet, so any member can view every incident and runbook. SCIM, custom roles and approval-step authorization come later.
- **Login is cached nowhere**: each request with a user token re-syncs the user and their IdP teams. Fine for now; it'll want a short-lived session cache at scale.
- **Critical-hold grants** (decision #29) aren't built, so critical incidents always page in parallel, which is the documented default.
- **Step types**: `note`, `shell`, `aws`, `wait`. `manual`, `approval`, `python`, `http`, `container` and SSM execution are valid schema but rejected at publish until implemented. AWS calls support JSON-protocol services (ECS, Secrets Manager, SSM, DynamoDB, Logs, KMS); RDS and other Query/XML services aren't supported yet.
- `when:` is evaluated on the control plane, so it can't reference `target` yet.
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
migrations/            schema, RLS policies, grants, SECURITY DEFINER functions
examples/runbooks/     ecs-service-restart.yaml
internal/e2e           end-to-end tests of the whole loop
```

## Running against real AWS

1. Postgres: `NIGHTFIX_ADMIN_DATABASE_URL=… NIGHTFIX_APP_DB_PASSWORD=… nightfix migrate`, then run `nightfix serve` with `NIGHTFIX_DATABASE_URL` pointing at `nfx_app`. See `cmd/nightfix/main.go` for every setting. Expose `NIGHTFIX_INGEST_ADDR` for SNS (HTTPS in front of it) and `NIGHTFIX_AGENT_ADDR` for agents.
2. `nightfix org create --name Acme --slug acme` prints an owner API key.
3. Create a service, escalation targets and a `cloudwatch` integration via the API (the demo script shows each call). Subscribe the integration's ingest URL to your SNS topic; the subscription is confirmed automatically after its signature is verified.
4. Create an IAM enrollment rule for the agent's role, then run the agent in your VPC under that role. The role needs whatever your runbooks call — for the example, `ecs:DescribeServices` and `ecs:UpdateService` on the target service. `sts:GetCallerIdentity` needs no permission.
   ```bash
   curl -X POST $API/v1/enrollment-rules -H "Authorization: Bearer $KEY" \
     -d '{"method":"iam","role_arn":"arn:aws:iam::<account>:role/nightfix-agent","labels":{"env":"prod"},"max_agents":2}'

   nightfix-agent --endpoint https://<gateway>:8443 --ca-file ca.crt --org org_… \
     --required-signers <your org signing key id>
   ```
   Rules match on account + role name (STS's assumed-role ARN doesn't carry the role's path). For hosts without an IAM role, use `"method":"token"` and `--enroll-method token --enroll-token …`.
5. Publish `examples/runbooks/ecs-service-restart.yaml` with `PUT /v1/runbooks/ecs-service-restart`, editing `services:` and the CloudWatch alarm name in `match:` to fit. Name the alarm's dimensions `ClusterName` and `ServiceName` (aliased to `alert.labels.cluster` / `.service`).

## User login with Auth0

1. In Auth0, create an **API** whose identifier is your audience (e.g. `https://api.nightfix.dev`), and enable **Organizations**. Create an Auth0 Organization per customer.
2. Add a post-login **Action** that puts the user's email and groups into the access token:
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     api.accessToken.setCustomClaim("https://nightfix.dev/email", event.user.email);
     api.accessToken.setCustomClaim("https://nightfix.dev/groups", event.user.app_metadata.groups || []);
   };
   ```
   (Source groups from wherever your IdP provides them; `app_metadata.groups` is just an example.)
3. Run the control plane with `NIGHTFIX_AUTH0_DOMAIN=<tenant>.us.auth0.com` and `NIGHTFIX_AUTH0_AUDIENCE=https://api.nightfix.dev`.
4. With the owner API key: link the org (`PUT /v1/org/auth0 {"auth0_org_id":"org_…"}`), create teams mapped to groups (`POST /v1/teams {"slug":"payments","auth0_group":"payments-eng"}`), and grant roles:
   ```json
   POST /v1/role-bindings
   {"subject_type":"team","subject":"payments","role":"responder",
    "scope":{"tags":["payments"],"env":["staging","dev"]}}
   ```
   That's the data model's example: Team Payments can run runbooks tagged `payments` outside prod; only admins run against `env=prod`.

## Tests

```bash
make test   # starts a throwaway Postgres on :54329 unless NIGHTFIX_TEST_ADMIN_DSN is set
```

The end-to-end tests cover: IAM enrollment (and its rejection of an unmatched role, a replayed nonce, an org/nonce that isn't inside the signature, a different STS action, and a forged signature), token enrollment as a fallback, scoped RBAC through Auth0 tokens (including republish takeover, privilege escalation, unlinked orgs, wrong audience, and group removal), auto-remediation with no page, a failed fix that pages and then auto-resolves upstream, an injection attempt in alert labels (refused by the parameter pattern; no ECS call is made), and forged or wrong-topic SNS messages (rejected before anything is stored). The database tests cover RLS isolation, cross-org write rejection, fail-closed queries without an org, composite foreign keys, and the audit chain.
