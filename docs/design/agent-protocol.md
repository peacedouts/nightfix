# Nightfix — Agent Job Protocol (Draft v1alpha1)

Status: draft for discussion. Defines how a customer-deployed agent enrolls, connects to the control plane, receives work, executes runbook steps, and reports results. Companion to `runbook-schema.md`.

---

## 1. Design principles

1. **Outbound only.** The agent opens a single TLS connection to `agent.nightfix.dev:443`. Customers open no inbound ports, and the agent works through an HTTPS proxy.
2. **Mutual TLS identity.** Every agent has its own short-lived client certificate. The control plane always knows exactly which agent it's talking to, and the agent always verifies it's talking to us.
3. **The control plane is not trusted blindly.** Signed runbooks aren't enough on their own: the agent also verifies a signed *dispatch envelope* that binds the run, step, parameters, target agent and expiry. A replayed, redirected or tampered job is rejected.
4. **The agent is nearly stateless.** The control plane owns run state, pauses (`manual`, `approval`) and orchestration. The agent executes one step at a time and reports back. Restarting or replacing an agent is safe.
5. **Never double-execute a dangerous step.** If an agent disappears mid-step, the control plane does not blindly retry. Only steps known to be safe to repeat are retried automatically. Everything else escalates to a human.
6. **Fail closed.** If the agent can't verify a signature, can't reach its signing keys, or is told to freeze, it refuses work.

---

## 2. Transport

- **gRPC over HTTP/2**, with one long-lived bidirectional stream per agent (`AgentService.Connect`).
- Both directions use the same stream. The agent sends hello, heartbeats, acknowledgments, output and results. The control plane sends dispatches, cancellations, config and key updates.
- **Reconnect:** exponential backoff with jitter, from 1s up to 60s. On reconnect, the agent re-sends `Hello` with any in-flight attempts so the control plane can reconcile.
- Two small **unary RPCs** (`GetEnrollChallenge` and `Enroll`) are used before the agent has a certificate.

---

## 3. Enrollment and identity

### 3.1 Enrollment flow: IAM-based (default)

Decision confirmed Oct 20, 2026. The agent proves its AWS identity instead of presenting a long-lived secret. This is the same pattern as Vault's AWS IAM auth method.

1. An org Admin registers an **enrollment rule** in the UI, CLI or Terraform. The rule maps an AWS account and IAM role ARN to the agent's labels, e.g. `arn:aws:iam::123456789012:role/nightfix-agent` → `env=prod, region=us-east-1`. The rule also sets a max agent count.
2. The customer deploys the agent with that IAM role (an ECS task role, IRSA on EKS, or an EC2 instance profile). There is no token to store.
3. On start, the agent generates an **Ed25519 key pair locally**. The private key never leaves the agent.
4. The agent builds an **SigV4-signed `sts:GetCallerIdentity` request** but does not send it to AWS. The signed headers include `X-Nightfix-Org: <org_id>` and a server-issued nonce from a `GetEnrollChallenge` call, so the request can't be replayed against another org or reused later.
5. The agent calls `Enroll` with the signed request and a CSR.
6. The control plane forwards the signed request to STS. STS returns the caller's account and role ARN. The control plane checks them against the org's enrollment rules and issues:
   - A **client certificate** with identity `spiffe://nightfix.dev/org/<org_id>/agent/<agent_id>`, valid for 24h.
   - The org's **trust config**: signing public keys and the required signer list (see 3.3).
   - The agent's ID and the labels from the matched rule. Labels always come from the rule, never from the agent.
7. Nothing needs persistent disk. A Fargate agent simply re-enrolls on restart with its role.

Why IAM by default: there's no secret to leak or rotate, it fits AWS-only scope, it works with Fargate's ephemeral storage, and the customer controls who can enroll by controlling who can assume the role.

### 3.1a Enrollment flow: tokens (fallback)

For environments without a usable IAM identity:

1. An org Admin creates an **enrollment token**. It's limited-use (`max_agents` counts every agent it has ever enrolled, not just live ones), expires (default 1h, at most 7 days), and carries the agent's labels.
2. The customer deploys the agent with the token, typically from Secrets Manager.
3. The agent calls `Enroll` with the token and a CSR, and receives the same certificate, trust config and labels as above.
4. An agent without persistent storage should use IAM enrollment: every token enrollment counts against `max_agents`, so re-enrolling on each restart uses the token up.

### 3.2 Certificate rotation and revocation

- The agent requests a renewal over the stream once 2/3 of the certificate's lifetime has passed (`RenewCert`).
- **Revoking** an agent (`POST /v1/agents/{id}/revoke`) takes effect on its next request, and the AWS identity it enrolled as (the role session: on ECS, the task) can't enroll again; a new task can, under the rule: the certificate lookup on every connection excludes revoked agents, so it can't poll, report or renew. Work leased to it is recovered when the lease expires.
- **Revoking an enrollment rule** (`POST /v1/enrollment-rules/{id}/revoke`) stops enrollment and certificate renewal under it, so its agents lapse within the 24h certificate TTL; with `{"revoke_agents": true}` they are revoked at once (the response to a leaked token).

### 3.3 Required signers (multi-signature verification)

Decision confirmed Oct 20, 2026. Built into the agent from day one.

- The agent's trust config has a **`required_signers` list of `key_id`s**. A runbook bundle is accepted only if it carries a valid signature from **every** required signer.
- **v1 default:** one required signer, the org's control-plane key in KMS.
- **Customer co-signing:** the customer adds a key they hold, e.g. one their CI pipeline uses to sign a runbook's digest when it merges to main. Co-signatures are uploaded through the API and attached to the published version.
- The required signer list **can be pinned in the agent's local config**, and the local list wins. That's what makes co-signing meaningful: if the control plane alone could remove the customer's key from the list, a compromised control plane could strip the requirement. With the list pinned locally, a compromised control plane can't get new code executed.
- **What a compromised control plane can still do, with signers pinned.** It decides *when and where* steps run, so it can dispatch any step of a signed runbook directly, skipping `when:` conditions and approval gates (the agent never sees approval state), with parameter values that pass the runbook's declared patterns. It can also forge `steps.<id>.outputs` and the agent's labels, which reach the agent through it. It can't change what a step does, use a parameter value its pattern refuses, or feed alert data into step inputs (the agent doesn't render `alert` or `incident` there). Runbook authors should give every parameter that names something to act on a tight pattern or an enum.
- Dispatch envelopes (section 6.2) are signed by the control-plane key only. They bind *when and where* to run a step, while the runbook bundle signatures decide *what* may run.

### 3.4 Signing key rotation

- The control plane rotates org signing keys by sending a `TrustBundleUpdate` that is **signed by the current key**.
- The agent accepts a new key only if the update verifies against a key it already trusts. Old keys stay valid for a grace period (default 7 days) so in-flight runs aren't broken.
- If the chain ever breaks, the agent fails closed and must be re-enrolled. This is deliberately painful.

---

## 4. Connection lifecycle

```
Agent                                         Control plane
  |  ---- TLS + mTLS handshake ---------------->  |
  |  ---- Hello(version, labels, capabilities,  |
  |          slots, in_flight_attempts) ------->  |  validate cert, reconcile in-flight
  |  <--- Welcome(config, trust_bundle_digest) --  |
  |  ---- Heartbeat (every 15s) ---------------->  |  agent "offline" after 45s silence
  |  <--- Dispatch(step attempt) ---------------  |
  |  ---- Ack(attempt_id, accepted|rejected) --->  |
  |  ---- Output chunks (seq 1..n) ------------->  |
  |  ---- Result(attempt_id, status, outputs) -->  |
  |  <--- ResultAck(attempt_id) ----------------  |
```

### 4.1 `Hello`

| Field | Purpose |
|---|---|
| `protocol_version` | e.g. `1`. The control plane rejects unsupported versions with an upgrade message |
| `agent_version` | Binary version, shown in the UI |
| `labels` | Must match enrolled labels. Agents can't grant themselves new labels |
| `capabilities` | Step types and executors supported: `shell`, `python`, `aws`, `http`, `wait`, `container:ecs`, `container:k8s`, `ssm` |
| `slots` | Max concurrent step attempts (default 4) |
| `allowlist_mode` | `off` / `warn` / `enforce`, reported so the UI can show it |
| `in_flight` | Attempt IDs still running or with unsent results after a reconnect |

The control plane dispatches only step types the agent advertises in `capabilities`.

### 4.2 Heartbeat

The heartbeat carries free slots, the current step attempt IDs, and basic health such as IAM credentials valid and clock offset. The control plane uses it for agent selection and the agent health page.

---

## 5. Work model: step-by-step dispatch

The control plane dispatches **one step attempt at a time** rather than a whole run.

**Why:**
- `manual`, `approval` and `note` steps run in the control plane. Pausing between steps is natural, and the agent holds no long-lived run state.
- Each step is independently signed, audited and leased.
- A run can resume on a different agent with the same labels if the first one dies between steps.

**Cost:** one round trip per step, which is negligible against incident timescales.

### 5.1 Control-plane queue (Postgres)

A `step_attempts` table holds `attempt_id`, `run_id`, `step_id`, `org_id`, `state`, `agent_id`, `lease_expires_at` and `attempt_number`.

The dispatcher claims queued attempts for connected agents with free slots, using `SELECT … FOR UPDATE SKIP LOCKED`. It then pushes a `Dispatch` down that agent's stream. The agent didn't open an inbound port; it's receiving on the stream it opened.

Attempt states:
`queued` → `dispatched` → `running` → `succeeded` | `failed` | `timed_out` | `cancelled` | `rejected` | `lost`

### 5.2 Leases

- Dispatch sets `lease_expires_at = now + 30s`.
- The agent must send `Ack` within the lease, then renew implicitly via heartbeats that list the attempt as running.
- If the lease expires without an `Ack`, the attempt returns to `queued` and is never considered started.
- If the lease expires after an `Ack` (the agent vanished mid-step), the attempt becomes `lost`. See section 8.

---

## 6. The dispatch envelope

Every `Dispatch` carries two signed artifacts.

### 6.1 The runbook bundle

The exact published runbook version: canonical JSON, its SHA-256 digest, and one or more signatures over the digest (the control plane's, plus any customer co-signatures). The agent caches bundles by digest, so later steps in the same run send only the digest.

### 6.2 The dispatch envelope

Signed with the same org key. It binds the specific piece of work:

| Field | Purpose |
|---|---|
| `attempt_id` | Unique; used for idempotency and dedupe |
| `run_id`, `step_id`, `attempt_number` | What to execute |
| `runbook_digest` | Must match the bundle |
| `agent_id` | **This agent only.** Blocks redirecting the job to another agent |
| `params` | Resolved, validated parameters, so they can't be altered in transit or by a forged message |
| `context` | Alert, incident, run and prior step outputs needed by this step's templates |
| `issued_at`, `expires_at` | Short validity (default 2m). Blocks replay |
| `requested_by` | User or trigger, for local logs |

### 6.3 Agent verification, in order

1. The envelope signature verifies against the trust bundle.
2. `agent_id` matches this agent, and `expires_at` hasn't passed (with a 30s skew allowance).
3. `attempt_id` hasn't been seen before (local dedupe cache).
4. The bundle digest is correct, and it carries a valid signature from every key in `required_signers`.
5. **Local allowlist:** `runbook_digest` is approved (or the name is allowed with `version: "*"`), if mode is `enforce`. Signatures cover the digest, not the version number, so the agent refuses to load an allowlist that pins a numeric version.
6. The step type is supported, and the parameters pass the runbook's declared types and patterns again. This is defense in depth against a buggy control plane.

Any failure produces `Ack(rejected, reason)`. The attempt becomes `rejected`, and the control plane escalates per the runbook's `onFailure`.

---

## 7. Execution on the agent

1. **Resolve secrets.** Fetch only the secrets that this step references, using the agent's IAM role. They live in memory and are zeroed after the step. There's no cache across steps in v1 (decided Oct 20, 2026).
2. **Render templates** for `env`, `files`, `aws.input` and `http` fields. `run:` is never templated.
3. **Execute** according to step type:
   - `shell` / `python`: a subprocess in a fresh temp directory, with a minimal environment and a process-group kill on timeout. `runOn: ssm` sends the script through SSM Run Command, and the agent polls for completion.
   - `aws`: an AWS SDK call with the agent's role, or `assumeRole` if specified.
   - `container`: ECS RunTask or a Kubernetes Job. The agent waits for it to finish and collects logs.
   - `http` / `wait`: run in-process.
4. **Redact and stream output.** Every resolved secret value, plus its base64 and URL-encoded forms, is scrubbed from stdout and stderr before anything leaves the agent.
5. **Evaluate `outputs`** (CEL) against `result`, then send `Result`.

### 7.1 Output streaming

- Messages are `OutputChunk { attempt_id, seq, stream: stdout|stderr, data }`, with chunks of at most 32 KiB.
- **Cap: 1 MiB per attempt.** After that, output is truncated with a marker, and the full exit status is still reported. Rows are capped too (50,000 per attempt, the last a "too many chunks" marker): the agent coalesces consecutive writes to one stream, and the control plane ignores empty chunks. Output is accepted while the attempt is dispatched or running and for an hour after it finishes (a cancelled step's last lines, or what an agent that was cut off captured before its attempt was declared lost), then refused with 409.
- Ordering and dedupe use `seq`. On reconnect, the agent resends unacknowledged chunks from a bounded local buffer.

### 7.2 Result

```
Result {
  attempt_id
  status: succeeded | failed | timed_out | cancelled
  exit_code            // shell / python / container
  outputs: map<string, Value>   // already redacted; secrets can never appear
  started_at, finished_at
  error: { code, message }
}
```

The agent holds a result until it receives `ResultAck`, and resends it after reconnects. The control plane treats duplicate results with the same `attempt_id` as no-ops.

---

## 8. Failure semantics

### 8.1 Safe-to-retry vs. unsafe steps

Proposed addition to the runbook schema: a step-level `idempotent` field.

- It defaults to `true` for `wait`, `http` with `GET`/`HEAD`, and `aws` actions whose names start with `Describe`, `List` or `Get`.
- It defaults to `false` for everything else, such as `UpdateService`, `FailoverDBCluster` and any shell script.

### 8.2 Failure matrix

| Situation | What happens |
|---|---|
| No `Ack` within the lease | Attempt re-queued; never started |
| Agent rejects the dispatch | `rejected`; runbook `onFailure` (usually escalate) |
| Agent disconnects mid-step, reconnects in time | Step keeps running locally. The agent reports it in `Hello.in_flight` and sends the buffered output and result |
| Agent never comes back (lease expires after `Ack`) | `lost`. If `idempotent: true` and `retries` remain, re-dispatch to another matching agent. Otherwise **pause the run and page a human**: "Step `failover` may or may not have completed" |
| Step exceeds its timeout | Agent kills the process group or stops the task → `timed_out` |
| Agent restarts mid-step | The subprocess dies with it. On reconnect, the agent reports the attempt as `lost` from its side, handled as above |
| No matching agent online | Run fails with `no_matching_agent` → escalate |
| Control plane unreachable | Running steps continue to completion. No new steps start. Output and results are buffered and sent on reconnect |

Continuing a running step during a disconnect is deliberate. Killing a failover halfway is worse than finishing it unobserved.

---

## 9. Cancellation and the kill switch

- **Cancel a run:** the control plane sends `Cancel { attempt_id, reason }`. The agent sends SIGTERM, waits 10s, then SIGKILL (or stops the ECS task or K8s Job), and reports `cancelled`. Remaining steps are never dispatched.
- **Org kill switch:** the control plane sends `Freeze { scope: org }` to every agent in the org. Agents cancel in-flight attempts and reject all new dispatches until they receive an `Unfreeze` signed by the org key. Freezing also stops all dispatching at the control plane.
- **Local kill switch:** the customer can set `NIGHTFIX_AGENT_FREEZE=true` (or a config flag) on the agent. It then connects for visibility only and refuses all work, regardless of what the control plane says. This is the customer's override if they ever distrust us.

---

## 10. Agent configuration

Configured via environment variables or a YAML file:

```yaml
endpoint: agent.nightfix.dev:443
org_id: org_7Hq2...
enrollment:
  method: iam        # iam (default) | token
  # token_secret: secret://aws-sm/nightfix/agent-token   # only for method: token
signing:
  required_signers:  # pinned locally; overrides the control plane's list
    - nightfix-org-kms-1
    # - acme-ci-signer-1   # add to require customer co-signing
slots: 4
proxy: http://proxy.internal:3128      # optional
allowlist:
  mode: enforce      # off | warn | enforce
  source: file       # file | s3
  path: /etc/nightfix/allowlist.yaml
freeze: false
```

Allowlist file:

```yaml
runbooks:
  - name: ecs-service-restart
    digest: sha256:4f1c...   # pin an exact version
  - name: aurora-failover
    version: "*"             # trust any signed version (weaker)
# A numeric version ("3") is refused: the version number isn't signed, so a
# control plane could relabel other signed content as v3. Pin the digest.
```

---

## 11. Message sketch (protobuf)

```proto
syntax = "proto3";
package nightfix.agent.v1;

service AgentService {
  rpc GetEnrollChallenge(EnrollChallengeRequest) returns (EnrollChallenge); // nonce for IAM enrollment
  rpc Enroll(EnrollRequest) returns (EnrollResponse);  // IAM-signed STS request or token, plus CSR
  rpc Connect(stream AgentMessage) returns (stream ControlMessage);
}

message AgentMessage {
  oneof msg {
    Hello hello = 1;
    Heartbeat heartbeat = 2;
    Ack ack = 3;
    OutputChunk output = 4;
    Result result = 5;
    RenewCertRequest renew_cert = 6;
  }
}

message ControlMessage {
  oneof msg {
    Welcome welcome = 1;
    Dispatch dispatch = 2;
    Cancel cancel = 3;
    ResultAck result_ack = 4;
    TrustBundleUpdate trust_bundle = 5;
    Freeze freeze = 6;
    Unfreeze unfreeze = 7;
    RenewCertResponse renew_cert = 8;
    ConfigUpdate config = 9;
  }
}

message RunbookBundle {
  string digest = 1;             // sha256 of canonical JSON
  bytes canonical_json = 2;
  repeated Signature signatures = 3;   // must cover every required signer
}

message Signature {
  string key_id = 1;
  bytes signature = 2;           // Ed25519 over digest
}

message Dispatch {
  RunbookBundle bundle = 1;      // omitted when the agent already has this digest
  SignedEnvelope envelope = 2;
}

message SignedEnvelope {
  bytes payload = 1;             // canonical-encoded DispatchEnvelope
  bytes signature = 2;           // Ed25519 over payload
  string key_id = 3;
}

message DispatchEnvelope {
  string attempt_id = 1;
  string run_id = 2;
  string step_id = 3;
  uint32 attempt_number = 4;
  string runbook_digest = 5;
  string agent_id = 6;
  map<string, Value> params = 7;
  Value context = 8;
  int64 issued_at_unix_ms = 9;
  int64 expires_at_unix_ms = 10;
  string requested_by = 11;
}
```

`Value` is a JSON-like union, i.e. `google.protobuf.Value` or an equivalent.

---

## 12. Open questions

**Resolved (Oct 20, 2026)**
- **Fargate enrollment:** IAM-based enrollment is the default; tokens are the fallback (section 3.1).
- **Who signs:** multi-signature verification ships in the agent from day one, with one required signer in v1 and optional customer co-signing (section 3.3).
- **Secret caching:** none in v1. Fetch per step, zero afterwards.
- **Agent HA:** two agents per production label set is the documented recommendation. The UI warns when a label set matching `env=prod` has fewer than two healthy agents.

**Deferred**
1. **Proxy compatibility.** A WebSocket fallback transport waits until a customer's proxy breaks long-lived HTTP/2 streams.
2. **Co-signing UX.** Key generation and registration, plus a GitHub Action that signs on merge. Build when a security-sensitive customer asks.
