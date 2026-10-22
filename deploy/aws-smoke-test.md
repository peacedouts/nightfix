# First run on real AWS: smoke test

A checklist for the first time Nightfix runs on AWS. It stands up the control plane in a **sandbox account**, connects an agent and a throwaway ECS service, and runs both demo stories for real:

- **Auto-fixed:** the alarm fires, the restart fixes it, and nobody is paged.
- **Paged:** the restart doesn't help, so on-call is paged. When the alarm clears, the page resolves.

Then it tears everything down. Plan on a few hours of wall-clock time, mostly waiting on RDS and DNS. It costs tens of dollars if you tear down the same day.

Each step says what you should see. If you see something else, stop and check **If something goes wrong** at the end.

## 0. Before you start

You need:
- [ ] A **sandbox AWS account**, separate from what will become production. Turn on billing alerts in it.
- [ ] AWS CLI v2, Terraform ≥ 1.11, `jq`, `curl` and `cosign` on your machine. Your AWS credentials must be able to create VPCs, RDS, ECS, IAM roles, KMS keys and SNS topics.
- [ ] A **Cloudflare API token** with Zone → DNS → Edit on `nightfix.dev` only.
- [ ] A **Slack incoming webhook** (`https://hooks.slack.com/services/…`) for a test channel.
- [ ] A **PagerDuty** account (a free developer account works) with a service using the **Events API v2** integration, so you have its routing key.
- [ ] Repository access to set GitHub Actions **variables**, and the `production` environment set up as `deploy/README.md` §3 describes.

Use sandbox host names, so the production ones (`api.`, `ingest.` and `agent.nightfix.dev`) stay free.

## 1. Control plane (≈ 30–40 min, mostly RDS)

Follow `deploy/README.md` §1–2 (state bucket, then `terraform apply`), with this `terraform.tfvars`:

```hcl
environment     = "sandbox"
api_hostname    = "api-sandbox"
ingest_hostname = "ingest-sandbox"
agent_hostname  = "agent-sandbox"
alarm_email     = "you@example.com"
db_multi_az     = false
# auth0_domain left out: API keys only for this test
```

- [ ] `terraform apply` finishes. If it rejects one of the two `log_parameter_max_length*` parameters, delete that `parameter` block and apply again (see "Not verified on real AWS yet" in `deploy/README.md`).
- [ ] Confirm the SNS email subscription for alarms, which arrives at `alarm_email`.
- [ ] The service's tasks are failing to start. That's expected until there's an image.

## 2. Images and first rollout (≈ 15 min)

- [ ] Add the `terraform output github_variables` values as repository **variables** (`deploy/README.md` §3).
- [ ] Re-run the **images** workflow on `main`. Both images are pushed and signed: the control plane to ECR, the agent to GHCR.
- [ ] Run the **deploy** workflow with that commit's SHA. It runs migrations as the RDS master user (a non-superuser, as CI tests), then rolls the service out.
- [ ] Check the endpoints:
  ```bash
  API=$(terraform output -raw api_url)
  curl -fsS $API/healthz            # ok
  curl -fsS $API/readyz             # ok (checks the database)
  curl -fsS $API/v1/agent-ca.pem    # -----BEGIN CERTIFICATE-----
  ```
- [ ] In CloudWatch Logs (`/nightfix/sandbox/controlplane`), there's no `error=` line after startup. There's a warning only if a development setting is on, and none should be.

## 3. An org and its integrations (≈ 10 min)

- [ ] `deploy/scripts/create-org.sh "Sandbox" sandbox`. Save the API key it shows, then `export KEY=…`.
- [ ] Set up the helper and note the org id for step 4:
  ```bash
  api() { curl -fsS -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' "$@"; }
  api $API/v1/me | jq -r .org               # org_…
  api $API/v1/signing-keys | jq -r .agent_pin   # key_id=base64… (empty until a signer is required)
  ```
- [ ] Create the service and its targets. These URLs pass the production allowlist: only `hooks.slack.com` and PagerDuty's event hosts are allowed.
  ```bash
  api -X POST $API/v1/services -d '{"name":"checkout-api","max_hold":"10m","verification_window":"5m"}'
  api -X POST $API/v1/services/checkout-api/escalation-targets -d '{"type":"slack","url":"https://hooks.slack.com/services/…"}'
  api -X POST $API/v1/services/checkout-api/escalation-targets -d '{"type":"pagerduty","routing_key":"<routing key>"}'
  ```
- [ ] Create the CloudWatch integration, pinned to the topic step 5 will create (its ARN is predictable). Save its `ingest_url`.
  ```bash
  ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
  api -X POST $API/v1/integrations -d "{\"type\":\"cloudwatch\",\"name\":\"demo\",\"default_service\":\"checkout-api\",
    \"topic_arn\":\"arn:aws:sns:us-east-1:$ACCOUNT:nightfix-demo-alarms\"}"
  ```
- [ ] Publish the runbook: `api -X PUT $API/v1/runbooks/ecs-service-restart --data-binary @examples/runbooks/ecs-service-restart.yaml`. It returns version 1 and a digest.

## 4. The agent (≈ 10 min)

- [ ] Make the agent image public: GitHub → Packages → `nightfix-agent` → Package settings → visibility **Public** (`deploy/README.md` §6). Then verify the digest you'll pin with the `cosign verify` command there.
- [ ] Apply `deploy/terraform/examples/agent` in the sandbox account:
  ```bash
  terraform apply -var org_id=org_… -var vpc_id=<the control plane's VPC or another with NAT> \
    -var 'subnet_ids=["subnet-…","subnet-…"]' -var agent_image=ghcr.io/peacedouts/nightfix-agent@sha256:… \
    -var nightfix_api_url=$API -var agent_endpoint=https://agent-sandbox.nightfix.dev
  ```
  Signer pinning (`required_signers` on the module) is optional for this test. If your org requires a signer, pass the `agent_pin` from step 3, split on commas, as that list.
- [ ] Register the agent role it outputs:
  `api -X POST $API/v1/enrollment-rules -d '{"method":"iam","role_arn":"<agent_role_arn>","labels":{"env":"prod"},"max_agents":4}'`
- [ ] Within a minute, `api $API/v1/agents` lists **two agents, online**. This is the first test of real STS enrollment (role path, assumed-role ARN).

## 5. The demo service (≈ 5 min)

- [ ] Apply `deploy/terraform/examples/demo-target` in the same account:
  ```bash
  terraform apply -var vpc_id=… -var 'subnet_ids=[…]' -var ingest_url=<the integration's ingest_url>
  ```
  The apply waits for the SNS subscription to be confirmed. Nightfix confirms it after verifying the signature, with a real SNS signing certificate this time.
- [ ] `api $API/v1/integrations` shows the integration's `topic_arn`, with no `problem` and no `last_rejected_topic`.

## 6. Story 1: fixed before anyone is paged (≈ 10 min)

The demo task reports unhealthy 5 minutes after it starts (`break_after_seconds`). Then:

- [ ] The alarm `ecs-unhealthy-checkout-api` goes to ALARM. An incident opens: `api $API/v1/incidents` shows #1 `remediating`.
- [ ] Slack gets "Auto-remediation started … paging held". PagerDuty gets **nothing**.
- [ ] The run's steps succeed against real ECS: DescribeServices, UpdateService, then the wait until the new deployment is stable. `api $API/v1/runs/<run id>` shows each step's output.
- [ ] The new task reports healthy, and within about 2 minutes the alarm goes OK.
- [ ] The incident resolves as `auto_remediated`. Slack gets the summary, and PagerDuty still has nothing.
- [ ] `api "$API/v1/incidents/1/timeline"` tells that story in order.

Record this one: it's the demo.

## 7. Story 2: on-call is paged (≈ 15 min)

- [ ] Re-apply the demo target with `-var heal_on_restart=false`, so every task starts broken.
- [ ] Wait out the runbook's 15-minute cooldown first. Otherwise the guardrail pages at once with "cooldown", which is a fine thing to show too.
- [ ] The alarm fires and the run succeeds, but the alarm stays in ALARM through the 5-minute verification window. Nightfix then pages: PagerDuty gets a **trigger** and Slack gets `@here`.
- [ ] Acknowledge it: `api -X POST $API/v1/incidents/2/acknowledge`. PagerDuty shows the incident **acknowledged**.
- [ ] Fix it "by hand": re-apply with `heal_on_restart=true` and force a deployment (`aws ecs update-service --cluster prod-east --service checkout-api --force-new-deployment`). The alarm goes OK, the incident resolves, and the PagerDuty incident **resolves on its own**.

## 8. Quick checks while it's running

- [ ] **Kill switch:** `api -X POST $API/v1/org/freeze`, then `api -X POST $API/v1/org/unfreeze`. The agents keep heartbeating and nothing runs while frozen.
- [ ] **Agent restart:** stop one agent task in the ECS console. Its replacement enrolls by itself, with a new task and so a new identity.
- [ ] **Control-plane rollout:** run **deploy** again with the same SHA. Nothing is lost or paged twice while tasks are replaced. Shutdown waits for in-flight notifications; the stop timeout is 45s.
- [ ] **Agent certificate renewal** happens at about 16h. If you leave the sandbox up overnight, check that the agents are still online the next day, with no re-enrollment in their logs.

## 9. Tear down

In reverse order: `terraform destroy` the demo target, then the agent example, then the control plane. The database and both load balancers have deletion protection; turn it off first with `terraform apply -var …` or in the console. The KMS key goes into its 30-day deletion window. In a sandbox that's what you want; **never** do this to production's key.

## If something goes wrong

| Symptom | Where to look |
|---|---|
| Tasks don't become healthy after deploy | Container logs. The usual causes: `NIGHTFIX_APP_DB_PASSWORD` mismatch (re-run deploy, which runs migrate first), or the RDS CA bundle path |
| `curl $API/readyz` returns 503 | The database is unreachable from the tasks: security groups, or RDS still being created |
| Agents never appear | Agent task logs. `no IAM enrollment rule matches role …` means the rule's role name differs from the task role (the role path isn't part of the match). `connection refused/timeout` means the agent subnets have no NAT, or the agent endpoint var is wrong |
| SNS subscription never confirms | `api $API/v1/integrations` shows `last_rejected_topic` if the topic ARN doesn't match the pinned one. Otherwise look in the control plane logs for `SNS` |
| The alarm fires but no incident | `api $API/v1/alert-events/failed` shows events that failed processing, with the reason |
| The run fails with `parameters could not be resolved` | The alarm has no ClusterName/ServiceName dimensions. Use a single-metric alarm like the demo target's, not metric math |
| A page or Slack message never arrives | The incident timeline has `notification.failed` with the reason. Targets must be `hooks.slack.com` / `events.pagerduty.com` URLs |
