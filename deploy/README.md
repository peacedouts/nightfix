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
- **Customer credentials** (Slack webhooks, PagerDuty keys, Slack signing secrets): sealed per org.

Nothing on the tasks' disks matters, and nothing secret is in Terraform state.

**Rough cost** (us-east-1, single-AZ database, light traffic): about $130 a month. That's two arm64 Fargate tasks (~$30), `db.t4g.small` (~$26), the NAT gateway (~$33), the ALB and NLB (~$16 each), plus KMS, Secrets Manager and logs. Multi-AZ RDS adds about $26. These are estimates; check the AWS pricing calculator.

## First-time setup

You need:
- An AWS account (a dedicated one is best).
- Terraform 1.11 or newer.
- The AWS CLI and `jq`.
- A Cloudflare API token with **Zone → DNS → Edit** on `nightfix.dev` only.

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

### 4. Build and roll out

- Push to `main`, or re-run the **images** workflow. It pushes the control-plane image to ECR, signed and with an SBOM.
- Run the **deploy** workflow. It runs migrations as the RDS master user, then rolls the service. If new tasks don't become healthy, ECS rolls back by itself.

```bash
curl https://api.nightfix.dev/healthz        # ok
curl https://api.nightfix.dev/v1/agent-ca.pem
```

### 5. Create the first org

```bash
deploy/scripts/create-org.sh "Acme Inc" acme
```

This runs a one-off admin task. The task writes the org's owner API key straight into Secrets Manager (as `nightfix-prod/org-api-keys/acme`), never printing or logging it. The script then shows the key to you once and offers to delete the secret after you've saved it in your password manager. The admin task has its own role. The service can't create secrets, and the migrate task has no AWS access at all. Only the migrate task's execution role can read the RDS master password. It also prints the org's `agent pin` (see below).

### 6. Make the agent image public

Under GitHub → **Packages** → `nightfix-agent` → **Package settings**, set visibility to **Public** so customers can pull it. The repository itself stays private.

Every push to `main` publishes `:sha-<commit>` and nothing else: no `:latest` and no `:main`. The agent runs under the customer's IAM role and decides what to execute, so a moving tag would let any new build reach every customer on their next restart. The agent module refuses anything but a digest or a `sha-` tag. Before handing customers an image, check its signature:

```bash
cosign verify ghcr.io/peacedouts/nightfix-agent@sha256:… \
  --certificate-identity https://github.com/peacedouts/nightfix/.github/workflows/images.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Installing an agent (customer side)

In the customer's AWS account:

```hcl
module "nightfix_agent" {
  source = "github.com/peacedouts/nightfix//deploy/terraform/modules/nightfix-agent"   # or a copy

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

`deploy/terraform/examples/agent` is a complete example. Then let that role in:

```bash
curl -X POST https://api.nightfix.dev/v1/enrollment-rules -H "Authorization: Bearer $NIGHTFIX_API_KEY" \
  -d '{"method": "iam", "role_arn": "<module output role_arn>", "labels": {"env": "prod"}, "max_agents": 4}'
curl https://api.nightfix.dev/v1/agents -H "Authorization: Bearer $NIGHTFIX_API_KEY"   # two agents, online
```

The agents enroll by proving they hold that role, with no tokens to copy or leak. They re-enroll on every start, which suits Fargate. To pin the org's signing key, set `required_signers` to the `agent_pin` from `GET /v1/signing-keys` (`key_id=base64-public-key`). Then the agent refuses any runbook that key didn't sign, whatever the control plane says later. A key of the customer's own (co-signing) goes in the same list.

## Operating it

- **Roll out:** run **deploy** with a commit SHA from `main`. It resolves the image to a digest, refuses it unless its Sigstore signature names `images.yml` on `main`, and pins the migrate, service and admin task definitions to that digest. **Roll back:** run it with an earlier SHA. Migrations only move forward, so a rollback to code older than the current schema must still work against that schema. Keep migrations additive.
- **Logs:** CloudWatch `/nightfix/prod/controlplane`. Migrate output is under the `controlplane/migrate` stream prefix.
- **Alarms** (SNS → email): fewer tasks running than desired, API/ingest 5xx, unhealthy ingest targets, database CPU and free storage.
- **Images:** each commit's image is kept, so a rollback can always pull it. Only untagged leftovers expire, after 14 days.
- **Backups:** RDS keeps 14 days of point-in-time recovery, and there's a final snapshot on delete. Deletion protection is on for the database and both load balancers.
- **Rotate the app's database password:** bump `secret_string_wo_version` in `data.tf`, `terraform apply`, then run **deploy**. Migrate sets the new password and the rollout picks it up. Existing tasks keep their open connections, but new connections fail until they're replaced, so do it in a quiet moment.
- **Never delete or change the sealing KMS key.** Without it, every stored customer credential and the agent CA are unrecoverable. It has a 30-day deletion window and automatic rotation, and the control plane refuses to start against a different key.

## Supply-chain items to finish by hand

Two pins need registry access this repository's automation sessions don't have. Do them once from your machine:
- **Base images.** In the `Dockerfile`, pin `golang:1.26`, `gcr.io/distroless/static-debian12:nonroot` and `debian:bookworm-slim` by digest (`docker buildx imagetools inspect <image>` shows it), e.g. `FROM golang:1.26@sha256:…`. Dependabot (`.github/dependabot.yml`) then keeps them current.
- **The RDS CA bundle.** Add `--checksum=sha256:<sum>` to the `ADD` line, where `<sum>` is `curl -s https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | sha256sum`. When AWS updates the bundle the build fails until you update the sum, which is the point.

## Not verified on real AWS yet

CI validates the Terraform against the real providers and builds both images, but nothing has been applied to an AWS account yet. Check these on the first run:
- **The agent's `/tmp`:** a shell step can write files. The image declares `/tmp` as a volume so ECS keeps its permissions.
- **The admin task:** `create-org.sh` stores the key and the script reads it back.
- **Database log settings:** the parameter group sets `log_parameter_max_length` and `log_parameter_max_length_on_error` to 0, so logs carry no query data. Both are standard Postgres 16 settings, but AWS doesn't document whether RDS lets you change them. If `terraform apply` rejects one, remove that `parameter` block.
- **Performance Insights:** it's off by default (`db_performance_insights`). Before turning it on, check that your instance class supports it.

## Not here yet

- WAF on the ALB.
- A second region for the notification path (phase 3).
- AWS Private CA in place of the database-held agent CA.
- Cross-region backup copies.
