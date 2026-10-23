# Deploying Nightfix to AWS

Two pieces, matching the hybrid model:

| Directory | Who runs it | What it creates |
|---|---|---|
| `terraform/control-plane` | Nightfix (us), once per environment | The hosted control plane: VPC, Postgres, KMS, ECS Fargate, load balancers, DNS |
| `terraform/modules/nightfix-agent` | Each customer, in their own AWS account | The agent: an IAM role, two Fargate tasks, an outbound-only security group |

## How the control plane is laid out

```
                    Cloudflare DNS (DNS only, not proxied)
   api.nightfix.dev ─┐                         agent.nightfix.dev
ingest.nightfix.dev ─┤                                 │
                     ▼                                 ▼
          ALB  (HTTPS, ACM cert)              NLB  (TCP 443, passed through)
            │ :8080 api   :8081 ingest            │ :8443 mutual TLS, terminated by the app
            └──────────────┬──────────────────────┘
                           ▼
        ECS Fargate service "controlplane" (2+ tasks, arm64, private subnets)
           │  API, ingest, agent gateway and all background workers in one binary;
           │  workers coordinate through Postgres (SKIP LOCKED), so any count works
           ▼
        RDS Postgres 16 (private, TLS required, verify-full)   KMS (sealing key)
```

**Why an NLB for agents:** agents authenticate with client certificates. An ALB would terminate TLS and hide them, so the NLB passes the TCP stream through and the app does the handshake.

**Where the secrets are:**
- **RDS master password:** created and rotated by RDS in Secrets Manager. Only the migrate task reads it.
- **`nfx_app` password:** generated ephemerally and written write-only, so it never appears in Terraform state or plans.
- **Credential-sealing key:** created by the control plane on first start with `kms:GenerateDataKey`. Only the KMS ciphertext is stored, in Postgres, so the database alone can't unseal anything.
- **Agent CA:** created on first start and stored in Postgres, with its private key sealed.
- **Customer credentials** (Slack webhooks, PagerDuty keys, Slack signing secrets), org signing keys and stored idempotent responses: sealed per org and per purpose, so a ciphertext copied into another column, row or org doesn't decrypt there.
- **Audit log:** the app role can read audit events and append them only through `nfx_audit`, which computes the hash chain; it can't insert, update or delete rows directly.

Nothing on the tasks' disks matters, and nothing secret is in Terraform state.

**Rough cost** (us-east-1, single-AZ database, light traffic): about $130 a month. That's two arm64 Fargate tasks (~$30), `db.t4g.small` (~$26), the NAT gateway (~$33), the ALB and NLB (~$16 each), plus KMS, Secrets Manager and logs. Multi-AZ RDS adds about $26. These are estimates; check the AWS pricing calculator.

## First-time setup

You need:
- An AWS account (a dedicated one is best).
- Terraform 1.11 or newer.
- The AWS CLI and `jq`.
- A Cloudflare API token with **Zone → DNS → Edit** and **Zone → Zone → Read** on `nightfix.dev` only.

### 1. State bucket

```bash
aws s3api create-bucket --bucket nightfix-tfstate-<account-id> --region us-east-1
aws s3api put-bucket-versioning --bucket nightfix-tfstate-<account-id> --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket nightfix-tfstate-<account-id> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

`deploy/terraform/control-plane/backend.hcl` (not committed):

```hcl
bucket       = "nightfix-tfstate-<account-id>"
key          = "control-plane/prod.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true
```

### 2. Apply

`terraform.tfvars` (not committed):

```hcl
environment  = "prod"
auth0_domain = "nightfix.us.auth0.com"   # leave out to start with API keys only
alarm_email  = "you@example.com"
db_multi_az  = false                     # turn on before customers depend on it
```

```bash
cd deploy/terraform/control-plane
export CLOUDFLARE_API_TOKEN=…
terraform init -backend-config=backend.hcl
terraform apply
```

The service is created before any image exists, so its tasks fail to start until step 4. That's expected.

### 3. Connect GitHub

From `terraform output github_variables`, add each value as a repository **variable** (Settings → Secrets and variables → Actions → Variables). None of them are secret: GitHub gets AWS access through OIDC, with no keys.

There are two AWS roles:
- **Push role:** jobs on `main` can push images, and do nothing else. Tags never build or push images, because anyone with write access can create one.
- **Deploy role:** only jobs in the `production` environment can roll out.

The deploy role can run any code as the control plane, because that's what deploying is, so set the environment up carefully. Create a GitHub **environment** named `production` (Settings → Environments) and:
- Under **Deployment branches and tags**, choose **Selected branches and tags** and add only `main`. **This is required.** Without it, anyone who can push a branch can run an edited deploy workflow in the environment.
- Add yourself as a **required reviewer**, so each rollout waits for your approval. On a private repo this needs a paid GitHub plan (Pro, Team or Enterprise); the free plan has no "Deployment protection rules" section. The branch restriction is the essential part. Add a reviewer at the latest when anyone else gets write access.
- **Protect `main`.** Everything above trusts `main`. The push role, the signature deploys check (`images.yml` on `main`) and the environment all key on it. So `main` must require a pull request with an approving review and block force-pushes (Settings → Rules, or branch protection). On a private repo that needs a paid plan too. Until it's in place, everyone with write access can, in effect, deploy to production.

### 4. Build and roll out

- Push to `main`, or run the **images** workflow on `main` (Actions → images → Run workflow). It pushes the control-plane image to ECR, signed and with an SBOM, unless that commit's image is already there.
- Run the **deploy** workflow. It checks that the image's signature names `images.yml` on `main` *and that commit*, runs migrations as the RDS master user, then rolls the service. If new tasks don't become healthy, ECS rolls back by itself and the workflow fails.
- After any later `terraform apply` that changes a task definition (new environment variables, Auth0 settings), run **deploy** again. Terraform registers its revisions with `image_tag` (default `latest`, which is never pushed), so until the next deploy the admin scripts and new tasks can't pull their image. Alternatively, apply with `-var image_tag=<the deployed commit>`.

```bash
curl https://api.nightfix.dev/healthz        # ok
curl https://api.nightfix.dev/v1/agent-ca.pem
```

### 5. Create the first org

```bash
deploy/scripts/create-org.sh "Acme Inc" acme
```

This runs a one-off admin task. The task writes the org's owner API key straight into Secrets Manager (as `nightfix-prod/org-api-keys/acme`), never printing or logging it. The script then shows the key to you once and offers to delete the secret after you've saved it in your password manager. The admin task has its own role. The service can't create secrets, and the migrate task has no AWS access at all. Only the migrate task's execution role can read the RDS master password. The org id and its `agent pin` are in the task's log (stream prefix `controlplane/admin`). With the key, `GET /v1/me` and `GET /v1/signing-keys` return them too.

To link a customer's Auth0 Organization once they've shown they control it, run `deploy/scripts/link-auth0.sh org_… <auth0 org id>`. This is an operator-only step, run as the same kind of admin task.

If an org loses its owner key, or one leaks and nobody can rotate it through the API (`POST /v1/api-keys`, then revoke the old key), run `deploy/scripts/new-owner-key.sh org_… --revoke-others`. It revokes every key the org has and issues a new owner key, delivered through Secrets Manager the same way.

### 6. Make the agent image public

Under GitHub → **Packages** → `nightfix-agent` → **Package settings**, set visibility to **Public** so customers can pull it. The repository itself stays private.

Every push to `main` publishes `:sha-<commit>` and nothing else: no `:latest` and no `:main`. The agent runs under the customer's IAM role and decides what to execute, so anything that can change would let a new build reach every customer on their next restart. GHCR tags, `sha-` tags included, can be re-pushed by anyone with write access to the package, so the agent module accepts only a digest. Use the tag to find the digest, then check its signature:

```bash
cosign verify ghcr.io/peacedouts/nightfix-agent@sha256:… \
  --certificate-identity https://github.com/peacedouts/nightfix/.github/workflows/images.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Installing an agent (customer side)

In the customer's AWS account:

```hcl
module "nightfix_agent" {
  source = "github.com/peacedouts/nightfix//deploy/terraform/modules/nightfix-agent?ref=<commit>"   # or a copy

  org_id     = "org_…"
  image      = "ghcr.io/peacedouts/nightfix-agent@sha256:…"   # pinned; verify it with cosign
  vpc_id     = "vpc-…"
  subnet_ids = ["subnet-…", "subnet-…"]   # private, with NAT

  # The agent's entire reach. Keep it to what your runbooks call.
  runbook_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:DescribeServices", "ecs:UpdateService"]
      Resource = "arn:aws:ecs:us-east-1:123456789012:service/prod-east/*"
    }]
  })
}
```

`deploy/terraform/examples/agent` is a complete example. The repository is private until launch, so customers can't fetch the module from it yet: hand them a copy, or publish the module (a public repo or registry) first. Always pin `?ref=` to a commit, so a later change to the module can't change their IAM.

**What `ecs:UpdateService` allows.** UpdateService can do more than force a new deployment. It can also point a service at another task definition, with another task role, or turn on ECS Exec. Anyone who can publish a runbook the agent runs (a Responder within scope, or a compromised control plane when the agent doesn't pin signers) could use that. To keep it narrow:
- give the agent only the clusters whose services it may restart;
- pin the org's signing key (`required_signers`) and, for production, the runbooks' digests in the agent's allowlist;
- don't keep task definitions with powerful task roles in those clusters.

Then let that role in:

```bash
curl -X POST https://api.nightfix.dev/v1/enrollment-rules -H "Authorization: Bearer $NIGHTFIX_API_KEY" \
  -d '{"method": "iam", "role_arn": "<module output role_arn>", "labels": {"env": "prod"}, "max_agents": 4}'
curl https://api.nightfix.dev/v1/agents -H "Authorization: Bearer $NIGHTFIX_API_KEY"   # two agents, online
```

Set `max_agents` to twice the module's `desired_count`: a rolling restart briefly runs old and new agents together, and new ones are refused once the limit is reached. Anyone in the account who can start a task with the agent's role (`ecs:RunTask` on its family, or `RegisterTaskDefinition` plus `iam:PassRole` on the role) can act as an agent. AWS can't scope a task role's trust to one cluster, so grant those permissions narrowly.

The agents enroll by proving they hold that role, with no tokens to copy or leak. They re-enroll on every start, which suits Fargate. To pin the org's signing key, set `required_signers` to the `agent_pin` from `GET /v1/signing-keys` (`key_id=base64-public-key`). Then the agent refuses any runbook that key didn't sign, whatever the control plane says later. A key of the customer's own (co-signing) goes in the same list.

## Operating it

- **Roll out:** run **deploy** with a commit SHA from `main`. It resolves the image to a digest, refuses it unless its Sigstore signature names `images.yml` on `main`, and pins the migrate, service and admin task definitions to that digest. **Roll back:** run it with an earlier SHA. Migrations only move forward, so a rollback to code older than the current schema must still work against that schema. Keep migrations additive.
- **Logs:** CloudWatch `/nightfix/prod/controlplane`. Migrate output is under the `controlplane/migrate` stream prefix.
- **Alarms** (SNS → email): fewer tasks running than desired, API/ingest 5xx, unhealthy ingest targets, database CPU and free storage, **any `level=ERROR` log line** (an alert event that couldn't be processed, a worker or partition-maintenance failure), and **pages failing** (a page or resolve that has failed 3 times, or any notification that was abandoned, Slack updates and approval messages included; the incident's timeline says why). Failed alert events are listed at `GET /v1/alert-events/failed`.
- **Images:** each commit's image is kept, so a rollback can always pull it. Only untagged leftovers expire, after 14 days.
- **Backups:** RDS keeps 14 days of point-in-time recovery, and there's a final snapshot on delete. Deletion protection is on for the database and both load balancers.
- **Rotate the app's database password:** bump `secret_string_wo_version` in `data.tf`, `terraform apply`, then run **deploy**. Migrate sets the new password and the rollout picks it up. Existing tasks keep their open connections, but new connections fail until they're replaced, so do it in a quiet moment.
- **Never delete or change the sealing KMS key.** Without it, every stored customer credential and the agent CA are unrecoverable. It has a 30-day deletion window and automatic rotation, and the control plane refuses to start against a different key.

## Supply-chain items to finish by hand

Two pins need registry access this repository's automation sessions don't have. Do them once from your machine:
- **Base images.** In the `Dockerfile`, pin `golang:1.26`, `gcr.io/distroless/static-debian12:nonroot` and `debian:bookworm-slim` by digest (`docker buildx imagetools inspect <image>` shows it), e.g. `FROM golang:1.26@sha256:…`. Dependabot (`.github/dependabot.yml`) then keeps them current.
- **The RDS CA bundle.** Add `--checksum=sha256:<sum>` to the `ADD` line, where `<sum>` is `curl -s https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | sha256sum`. When AWS updates the bundle the build fails until you update the sum, which is the point.

## Not verified on real AWS yet

CI validates the Terraform against the real providers and builds both images, but nothing has been applied to an AWS account yet. [`aws-smoke-test.md`](aws-smoke-test.md) walks through a first run in a sandbox account. It covers the control plane, an agent and a demo service (`terraform/examples/demo-target`), plus both demo stories, end to end. Check these on that run:
- **The agent's `/tmp`:** a shell step can write files. The image declares `/tmp` as a volume so ECS keeps its permissions.
- **The admin task:** `create-org.sh` stores the key and the script reads it back.
- **Database log settings:** the parameter group sets `log_parameter_max_length` and `log_parameter_max_length_on_error` to 0, so logs carry no query data. Both are standard Postgres 16 settings, but AWS doesn't document whether RDS lets you change them. If `terraform apply` rejects one, remove that `parameter` block.
- **Performance Insights:** it's off by default (`db_performance_insights`). Before turning it on, check that your instance class supports it.
- **Can the agent's role be held to restarts?** In the sandbox, try `ecs:UpdateService` with a different `taskDefinition`, and with `enableExecuteCommand`, using the agent role. If Deny statements on the `ecs:task-definition` and `ecs:enable-execute-command` condition keys stop those calls but still allow `forceNewDeployment`, add them to the example policy. AWS's reference doesn't say which keys UpdateService evaluates, and a wrong key would either do nothing or block the restart runbook.

## Known gaps, accepted for now

- **Migrations run as the RDS master user**, which holds `rds_superuser`. Migrate needs only CREATEROLE and ownership of the schema; a dedicated migrator login would narrow it.
- **The sealing KMS key uses the default key policy**, which delegates to IAM. An account principal with broad `kms:*` could use it. An explicit key policy (task and admin roles only, plus a break-glass role for deletion) is the next step, once there's a break-glass role to name. It has no `prevent_destroy`, so sandboxes can be torn down. Production relies on the 30-day deletion window.
- **No provider lock files are committed.** Sessions that work on this repository can't reach the Terraform registry. Run `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64` in each directory once and commit the `.terraform.lock.hcl` files.
- **No per-tenant rate or concurrency limits.** Each instance has one 20-connection pool for the API, ingest, the agent gateway and the workers. Request sizes, routing rules (100, with a 1s CEL budget per alert), outputs, notes and audit entries are capped, and the expensive audit-chain check runs only on request, one at a time per org. But a tenant sending many requests at once can still slow others. The unauthenticated enrollment-challenge endpoint has no throttle either. Add per-org and per-IP limits, and separate pools for ingest and workers, before onboarding many tenants.
- **Queue claims slow down with one org's backlog.** The alert-event and notification claims scan an org's unprocessed rows. With a 100k-event (or 50k-page) backlog in one org, each claim takes about 0.3–0.4s, which slows every org on the instance. Measure with `NIGHTFIX_LIMITS=1 go test ./internal/e2e -run TestLimits`. Fixing it means a per-org queue-head design.
- **Tables kept for ever.** Alerts, incidents, timelines, notifications, runs and audit events aren't archived yet. The design's monthly audit partitions and S3 export aren't built either. Fine for the first customers; plan archival before a year of volume.
- **One person, two Auth0 accounts.** Approvals count distinct users. Someone with two accounts in the org (say, two logins with the same verified email) that both hold a qualifying binding counts twice toward `count > 1` and can approve their own run. Keep one account per person in the IdP; dedupe by verified email if that ever isn't enforceable.
- **A compromised control plane decides when steps run.** Pinned signers stop it running new code, but it can dispatch any step of a signed runbook directly (skipping `when:` and approval gates) with parameters that pass their patterns. See agent-protocol.md §3.3.
- **Build tooling images** (`tonistiigi/binfmt` for the agent's QEMU, `moby/buildkit`) are pulled by tag in the jobs that sign. Pin them by digest along with the base images (see "Supply-chain items").

## Not here yet

- WAF on the ALB.
- A second region for the notification path (phase 3).
- AWS Private CA in place of the database-held agent CA.
- Cross-region backup copies.
