# Nightfix — Runbook Schema (Draft v1alpha1)

Status: draft for discussion. Defines the format customers write runbooks in, what the control plane validates and signs, and what the agent executes.

---

## 1. Design principles

1. **Declarative YAML, Kubernetes-style envelope** (`apiVersion` / `kind` / `metadata` / `spec`). Familiar to the target buyer, easy to keep in Git, validatable with JSON Schema, and maps cleanly to a Terraform resource.
2. **One expression language: CEL** (Common Expression Language). It's used for trigger matching, `when` conditions, wait conditions, output extraction, and template values. CEL is sandboxed, non-Turing-complete, fast, and already used by Kubernetes and Envoy, so it's safe to evaluate on both the control plane and the agent.
3. **Untrusted input never reaches a shell string.** Alert payloads can be influenced by attackers. A `run:` block is literal text. Parameters, alert fields, and secrets enter scripts only through `env:` or `files:`. The publish-time linter rejects `${{ }}` inside `run:`.
4. **Secrets are declared up front.** The agent knows exactly what to fetch, the approval UI can show "this runbook reads X", and customers can scope IAM to match. Values exist only in the agent's memory, env vars, or temp files. They're redacted from logs and can never be step outputs.
5. **Strict typing.** Every parameter has a type. Any parameter derived from an alert must have a `pattern` or `enum`, and the linter enforces this.
6. **Immutable, signed versions.** Each publish creates a new immutable version with a content digest, signed by the control plane. Each execution pins `name@version` plus the digest. The agent verifies the signature, then checks its local allowlist.
7. **Sequential steps in v1.** There are no DAGs, parallel branches, or loops. Runbooks stay lightweight, readable during an incident, and easy to audit. Revisit only when customers ask.

---

## 2. Top-level structure

```yaml
apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata: {...}     # identity, ownership, discovery
spec:
  parameters: {...} # typed inputs
  secrets: {...}    # declared secret references
  target: {...}     # which agent(s) may run it
  triggers: [...]   # how it starts
  policy: {...}     # who may run it, limits
  steps: [...]      # what it does, in order
  onFailure: {...}  # what happens if it fails
```

---

## 3. Field reference

### 3.1 `metadata`

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Slug, unique per org. `^[a-z0-9][a-z0-9-]{1,62}$` |
| `title` | string | yes | Human-readable name shown in UI and Slack |
| `description` | string | no | Markdown allowed |
| `team` | string | no | Owning group; used by RBAC scopes |
| `tags` | string[] | no | Used by RBAC scopes and search, e.g. `payments` |
| `labels` | map | no | Free-form key/values |

`version` and `digest` are **assigned by the control plane on publish**, never written by authors.

### 3.2 `spec.parameters`

A map of parameter name to definition.

| Field | Type | Notes |
|---|---|---|
| `type` | `string` \| `int` \| `bool` \| `enum` \| `duration` | Required |
| `description` | string | Shown in the run form |
| `required` | bool | Default `false` |
| `default` | any | Must match `type` |
| `from` | CEL | Resolve from trigger context, e.g. `alert.labels.service` |
| `pattern` | regex | For `string`. **Required if `from` is set** |
| `values` | list | For `enum` |
| `min` / `max` | number / duration | For `int` / `duration` |

Resolution order: the value supplied by the user or API, then `from`, then `default`. A run fails validation before execution if a required parameter is missing or invalid.

### 3.3 `spec.secrets`

A map of local secret name to reference. They're resolved by the agent at execution time.

```yaml
secrets:
  db_admin:
    ref: secret://aws-sm/prod/rds/admin   # AWS Secrets Manager
    key: password                          # optional: JSON key within the secret
  slack_hook:
    ref: secret://aws-ssm/prod/slack/hook  # SSM Parameter Store (SecureString)
```

| Scheme | Provider | v1 |
|---|---|---|
| `secret://aws-sm/<name>` | AWS Secrets Manager | yes |
| `secret://aws-ssm/<path>` | SSM Parameter Store | yes |
| `secret://vault/<path>` | HashiCorp Vault | later |

Rules:
- Secrets can be referenced only in `env:` or `files:` values, or in `http.headers`. The syntax is `${{ secrets.db_admin }}`.
- They can't appear in `run:`, `aws.input`, `outputs`, or `note` / `manual` text.
- The agent redacts every resolved value, including its base64 and URL-encoded forms, from stdout and stderr before streaming.

### 3.4 `spec.target`

Selects which agent(s) may execute the runbook.

```yaml
target:
  agentSelector:
    env: prod
    region: us-east-1
```

The run is routed to a healthy agent whose labels match. If no agent matches, the run fails immediately with `no_matching_agent`, and that failure escalates.

### 3.5 `spec.triggers`

A list. A runbook can have several triggers.

| Field | Type | Notes |
|---|---|---|
| `type` | `manual` \| `alert` \| `api` | `manual` = UI/Slack/CLI; `api` = API key |
| `services` | string[] | `alert` only. Service names this trigger may act on. If set, the trigger is considered only for incidents on these services, and `match` must still be true. If omitted, the trigger is org-wide. **Required when `mode: auto`** |
| `match` | CEL | `alert` only; evaluated against the incoming alert |
| `mode` | `suggest` \| `one-click` \| `auto` | `alert` only. `suggest` = attach to incident; `one-click` = button in Slack/UI; `auto` = run immediately |
| `beforePaging` | bool | `auto` only. Run first; page only if it fails or doesn't resolve the alert. Default `false` |
| `cooldown` | duration | Minimum time between auto runs for the same parameter set |
| `maxRunsPerHour` | int | Hard cap per runbook, per org |

Auto-mode lint rules:
- `services` must be set and non-empty, and every listed service must exist in the org. An over-broad `match` expression then can't let automation act on another team's services. `suggest` and `one-click` triggers may omit `services` because a human is in the loop.
- Every required parameter must resolve via `from` or `default`.
- No `manual` steps.
- `approval` steps are allowed. They pause the run and page the approver group.
- `cooldown` and `maxRunsPerHour` are required.

`beforePaging` holds pages for non-critical incidents only. Holding a **critical** page is not a runbook field: it's a per-runbook, per-service grant that the control plane issues after a verified track record and Admin opt-in (see `alert-incident-model.md` §8.6). A runbook author can't give their own runbook that right.

### 3.6 `spec.policy`

| Field | Type | Notes |
|---|---|---|
| `allowedRoles` | string[] | Roles that may start a run. Scoped further by team, tags and env via org RBAC |
| `timeout` | duration | Whole-run timeout. Default `30m`, max `4h` |
| `concurrency` | int | Max simultaneous runs per parameter set. Default `1` |

### 3.7 `spec.steps`

Steps run in order. Every step has these common fields:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Unique within the runbook; referenced as `steps.<id>` |
| `name` | string | Display name |
| `type` | see below | Required |
| `when` | CEL | Skip the step if false |
| `timeout` | duration | Default `5m` |
| `retries` | int | Default `0`; exponential backoff |
| `onFailure` | `stop` \| `continue` \| `escalate` | Default `stop` (then runbook-level `onFailure`) |
| `outputs` | map name → CEL | Evaluated against `result`; available to later steps as `steps.<id>.outputs.<name>` |

#### Step types (v1)

| Type | Runs where | Purpose | Key fields |
|---|---|---|---|
| `note` | Control plane | Narrative context for the responder | `markdown` |
| `manual` | Control plane | Human checklist; run pauses until confirmed | `markdown`, `checklist[]` |
| `approval` | Control plane | Gate; pauses until approved | `count`, `fromRoles[]`, `excludeRequester`, `expiresAfter` |
| `shell` | Agent, or EC2 via SSM | Bash script | `run`, `env`, `files`, `runOn` |
| `python` | Agent, or EC2 via SSM | Python 3 script | `run`, `env`, `files`, `runOn` |
| `aws` | Agent (AWS SDK, customer IAM) | Single AWS API call | `service`, `action`, `input`, `assumeRole` |
| `container` | Agent launches ECS RunTask / K8s Job | Run a pinned image | `image` (digest-pinned), `command`, `env` |
| `http` | Agent | HTTP request (health checks, internal APIs) | `method`, `url`, `headers`, `body`, `expectStatus` |
| `wait` | Agent | Poll until a condition is true | `check` (an `aws` or `http` call), `until` (CEL), `interval` |

`runOn` for `shell` and `python`:
- `agent` is the default. The script runs in the agent's own sandboxed subprocess.
- `ssm` runs on EC2 instances via SSM Run Command, selected with `instances: { tags: {...} }` and `maxTargets`.

The `result` object each step type exposes to `outputs` and `until`:
- `shell` / `python`: `result.exitCode`, `result.stdout`, `result.stderr` (redacted)
- `aws`: `result` = the parsed API response
- `http`: `result.status`, `result.headers`, `result.body` (parsed if JSON)
- `container`: `result.exitCode`, `result.logs`

### 3.8 `spec.onFailure`

```yaml
onFailure:
  action: escalate        # escalate | notify | none
  message: "Auto-restart failed for ${{ params.service }}; paging on-call."
```

`escalate` pages through the incident's escalation policy. With `beforePaging: true`, this is how an unresolved auto-remediation still wakes someone up.

---

## 4. Templating and context

The syntax is `${{ <CEL expression> }}`. It's allowed in parameter `from`, `when`, `outputs`, `until`, `aws.input`, `http` fields, `env` / `files` values, and `onFailure.message`. It's **not** allowed in `run:`.

Context available to expressions:

| Name | Contents |
|---|---|
| `params` | Resolved, validated parameters |
| `secrets` | Secret values (only in `env` / `files` / `http.headers`) |
| `alert` | `source`, `severity`, `summary`, `labels`, `annotations`, `raw` (when triggered by an alert) |
| `incident` | `id`, `title`, `severity`, `url` |
| `run` | `id`, `requestedBy`, `startedAt`, `mode` |
| `target` | Matched agent's labels, e.g. `target.env` |
| `steps` | `steps.<id>.outputs.*`, `steps.<id>.status` |

---

## 5. Example: auto-remediate an unhealthy ECS service before paging

```yaml
apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: ecs-service-restart
  title: Restart unhealthy ECS service
  description: Forces a new deployment when tasks repeatedly fail health checks.
  team: platform
  tags: [ecs, restart]
spec:
  parameters:
    cluster:
      type: string
      required: true
      from: alert.labels.cluster
      pattern: "^[A-Za-z0-9_-]{1,255}$"
    service:
      type: string
      required: true
      from: alert.labels.service
      pattern: "^[A-Za-z0-9_-]{1,255}$"
  target:
    agentSelector:
      env: prod
  triggers:
    - type: alert
      services: [checkout-api, search-api]
      match: 'alert.source == "cloudwatch" && alert.labels.alarm_name.startsWith("ecs-unhealthy-")'
      mode: auto
      beforePaging: true
      cooldown: 15m
      maxRunsPerHour: 2
    - type: manual
  policy:
    allowedRoles: [Responder, Admin]
    timeout: 15m
    concurrency: 1
  steps:
    - id: context
      name: What this does
      type: note
      markdown: |
        Forces a new ECS deployment for the service, which replaces all tasks.
        If tasks keep failing after this, the problem is likely the image or a dependency.
    - id: before
      name: Capture current state
      type: aws
      service: ecs
      action: DescribeServices
      input:
        cluster: ${{ params.cluster }}
        services: ["${{ params.service }}"]
      outputs:
        running: result.services[0].runningCount
        desired: result.services[0].desiredCount
    - id: restart
      name: Force new deployment
      type: aws
      service: ecs
      action: UpdateService
      input:
        cluster: ${{ params.cluster }}
        service: ${{ params.service }}
        forceNewDeployment: true
    - id: wait-stable
      name: Wait for service to stabilize
      type: wait
      interval: 30s
      timeout: 10m
      check:
        aws:
          service: ecs
          action: DescribeServices
          input:
            cluster: ${{ params.cluster }}
            services: ["${{ params.service }}"]
      until: >
        result.services[0].deployments.size() == 1 &&
        result.services[0].runningCount == result.services[0].desiredCount
  onFailure:
    action: escalate
    message: "Auto-restart of ${{ params.service }} did not stabilize; paging on-call."
```

---

## 6. Example: Aurora failover with checklist, approval and secrets

```yaml
apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: aurora-failover
  title: Fail over Aurora cluster
  team: data
  tags: [rds, aurora, failover]
spec:
  parameters:
    db_cluster:
      type: string
      required: true
      pattern: "^[a-z][a-z0-9-]{0,62}$"
    db_endpoint:
      type: string
      required: true
      pattern: "^[a-z0-9.-]+\\.rds\\.amazonaws\\.com$"
  secrets:
    db_admin:
      ref: secret://aws-sm/prod/rds/admin
      key: password
  target:
    agentSelector:
      env: prod
  triggers:
    - type: manual
    - type: alert
      services: [databases]   # optional for one-click; scopes the button to this service
      match: 'alert.labels.alarm_name == "aurora-writer-unhealthy"'
      mode: one-click
  policy:
    allowedRoles: [Responder, Admin]
    timeout: 30m
  steps:
    - id: confirm
      name: Pre-failover checklist
      type: manual
      markdown: Confirm before failing over the writer.
      checklist:
        - Writer health confirmed in the RDS console
        - Incident announced in #incidents
        - App team aware of a brief write outage
    - id: replica-lag
      name: Check replica lag
      type: shell
      timeout: 2m
      env:
        PGHOST: ${{ params.db_endpoint }}
        PGUSER: admin
        PGPASSWORD: ${{ secrets.db_admin }}
      run: |
        psql -At -c "select coalesce(max(replica_lag_in_msec),0) from aurora_replica_status();"
      outputs:
        lag_ms: int(result.stdout.trim())
    - id: approve
      name: Admin approval for prod failover
      type: approval
      when: target.env == "prod"
      count: 1
      fromRoles: [Admin]
      excludeRequester: true
      expiresAfter: 15m
    - id: failover
      name: Trigger failover
      type: aws
      service: rds
      action: FailoverDBCluster
      input:
        DBClusterIdentifier: ${{ params.db_cluster }}
    - id: wait-available
      name: Wait for cluster available
      type: wait
      interval: 20s
      timeout: 10m
      check:
        aws:
          service: rds
          action: DescribeDBClusters
          input:
            DBClusterIdentifier: ${{ params.db_cluster }}
      until: result.DBClusters[0].Status == "available"
  onFailure:
    action: escalate
    message: "Aurora failover for ${{ params.db_cluster }} failed or timed out."
```

---

## 7. Lifecycle: publish, sign, execute

**Publish (control plane)**
1. Parse the YAML and validate it against the JSON Schema.
2. Lint: no `${{ }}` in `run:`; every `from` parameter has a `pattern` or `enum`; auto-mode rules, including a non-empty `services` list of existing services; secrets used only in allowed fields; `container.image` is digest-pinned.
3. Canonicalize to JSON (RFC 8785), compute a SHA-256 digest, and assign the next immutable `version`.
4. Sign the digest with an org-scoped Ed25519 key held in AWS KMS.

**Execute**
1. A trigger fires, and the control plane checks RBAC, `policy`, `cooldown` and `concurrency`.
2. Parameters are resolved and validated, and the run is queued as `name@version` with its digest and signature.
3. The agent pulls the job. It verifies the signature and checks the digest against its local allowlist, if allowlisting is enabled. It then resolves secrets and executes steps, streaming redacted output.
4. Control-plane steps (`note`, `manual`, `approval`) pause the run. The agent resumes when they're satisfied.

**Run states:** `pending` → `awaiting_approval` / `awaiting_input` → `running` → `succeeded` | `failed` | `timed_out` | `cancelled` | `rejected` (signature, allowlist or validation failure).

---

## 8. Authoring, runtime and retention (decided Oct 20, 2026)

**Authoring.** The publish API is the single write path. The Terraform provider (`nightfix_runbook` resource), Git sync and the UI all call it, so every route gets the same validation, linting and signing. The v1 UI includes a YAML editor with schema-aware autocomplete and live lint results from the publish linter, plus a "dry run" that resolves parameters against a sample alert without executing anything. There is no visual editor.

**Script runtime.** `shell` and `python` steps run with the tools in the agent image:
- **Default image:** `aws` CLI v2, `psql`, `mysql`, `redis-cli`, `jq`, `curl`, Python 3 with `boto3`.
- **Slim base image:** documented for customers who want to add their own tools or reduce attack surface.
- Both are rebuilt weekly and on critical CVEs, scanned in CI, signed, and published with an SBOM.
- Fargate agents can't run Docker, so `container` steps always go through ECS RunTask or a K8s Job.

**Retention.**

| Data | Default | Configurable | Mutable |
|---|---|---|---|
| Execution output (stdout/stderr, redacted) | 90 days | Yes, per org | No |
| Audit metadata: requester, runbook `name@version` + digest, parameters, approvals, agent, timings, status, outputs | ≥ 1 year | Upward only | Never (append-only) |

Secrets never appear in either. Output is capped at 1 MiB per step attempt.

**Rollback.** There is no `rollback:` step list in v1. Failures use `onFailure`, which normally escalates to a human.

## 9. Open questions

1. **Reusable steps.** Shared step libraries such as `uses: nightfix/ecs-restart@v1`. Deferred; needs its own signing and versioning story.
2. **Large output.** Spill output beyond 1 MiB to S3? Deferred until a customer needs it.
