---
title: Write a runbook
description: Runbooks are versioned YAML with steps the agent runs in your account.
---

A runbook is a YAML file with typed parameters, a target, triggers, and steps that run in order. Publishing creates a new, signed version. Runs always record exactly which version they used.

## A complete example

This runbook restarts an unhealthy ECS service before anyone is paged:

```yaml
apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: ecs-service-restart
  title: Restart unhealthy ECS service
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
      services: [checkout-api]
      match: 'alert.source == "cloudwatch" && alert.labels.alarm_name.startsWith("ecs-unhealthy-")'
      mode: auto
      beforePaging: true
      cooldown: 15m
      maxRunsPerHour: 2
    - type: manual
  policy:
    timeout: 15m
  steps:
    - id: restart
      type: aws
      service: ecs
      action: UpdateService
      input:
        cluster: ${{ params.cluster }}
        service: ${{ params.service }}
        forceNewDeployment: true
    - id: wait-stable
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

## Rules Nightfix enforces when you publish

- A parameter filled from an alert (`from:`) must have a `pattern` or a fixed list of values.
- Script bodies (`run:`) can't contain `${{ }}`. Pass values through `env:` or `files:` instead.
- Secrets can only appear in `env:`, `files:` or HTTP headers, and can never be step outputs.
- Automatic triggers must list their `services`, a `cooldown` and `maxRunsPerHour`.
- Checks in `wait` steps must be read-only (`Describe*`, `List*`, `Get*`).

## Step types available today

| Type | What it does |
|---|---|
| `note` | Adds context to the incident timeline |
| `approval` | Pauses the run until the right people approve it |
| `aws` | Calls an AWS API with the agent's role (ECS, Secrets Manager, SSM, DynamoDB, CloudWatch Logs, KMS) |
| `wait` | Repeats a read-only AWS call until a condition is true |
| `shell` | Runs a bash script on the agent |

Planned: `manual` checklists, `python`, `http`, container tasks, running scripts on EC2 fleets through SSM, and more AWS services such as RDS.

## Require a human OK before risky steps

Add an `approval` step in front of anything you want a person to sign off on, such as a restart in production:

```yaml
    - id: approve
      name: Approve the restart
      type: approval
      count: 1                # approvals needed (default 1)
      fromRoles: [Admin]      # who may approve (default Responder); higher roles also count
      excludeRequester: true  # whoever started the run can't approve it
      expiresAfter: 15m       # default 15m, and never longer than the run timeout
```

When a run reaches the step, it waits:

- **Approving.** Each approval is checked against the approver's role *and* scope at the moment they approve, so a responder scoped to staging can't approve a production run. Approvals always come from a person; API keys can't approve. A runbook with `excludeRequester` can't be started with an API key either, because a key doesn't identify who is behind it.
- **Rejecting.** One rejection from anyone allowed to approve cancels the run, with their reason in the run record.
- **Expiring.** If not enough people approve in time, the run times out and the steps after the approval never run.
- **Paging.** If the run was fixing an alert before paging anyone, Nightfix pages on-call right away, because waiting for a human is no reason to keep humans in the dark.

Approve or reject from the **Approve** and **Reject** buttons on the Slack message, or from the API:

```bash
curl -X POST https://api.nightfix.dev/v1/runs/run_…/steps/approve/approve \
  -H "Authorization: Bearer $AUTH0_TOKEN" -d '{"comment": "checked the dashboards"}'
```

**Where requests go.** For a run tied to an incident, the request goes to the Slack channels for the incident's service, like every other incident message. A run with no incident (one somebody started by hand, say) asks in its runbook team's approval channel, or the org's default one. An Admin sets these once:

```bash
# Org default
curl -X PUT https://api.nightfix.dev/v1/approval-channels -H "Authorization: Bearer $NIGHTFIX_API_KEY" \
  -d '{"url": "https://hooks.slack.com/services/…"}'
# Just for runbooks owned by the payments team
curl -X PUT https://api.nightfix.dev/v1/approval-channels -H "Authorization: Bearer $NIGHTFIX_API_KEY" \
  -d '{"team": "payments", "url": "https://hooks.slack.com/services/…"}'
```

Later steps can read who approved as `steps.approve.outputs.approved_by`. Every request, approval, rejection and expiry is in the audit log.

### Set up Slack buttons

1. In your Slack app's settings, turn on **Interactivity**, add a `/nightfix` **slash command**, and copy the **Signing Secret** from **Basic Information**.
2. Register the app with Nightfix (Admin only):
   ```bash
   curl -X POST https://api.nightfix.dev/v1/slack-apps -H "Authorization: Bearer $NIGHTFIX_API_KEY" \
     -d '{"signing_secret": "…", "team_id": "T0123ABC"}'
   ```
3. Paste the `interactivity_url` it returns into Slack's **Interactivity → Request URL**, and the `commands_url` into the `/nightfix` command's **Request URL**.

Each person links their Slack account once. Signed in to Nightfix, they get a one-time code (`POST /v1/me/slack-link-code`), then type `/nightfix link <code>` in Slack. The code always comes from Nightfix and goes into Slack, never the other way round, so nobody can trick a colleague into linking the trickster's Slack account to the colleague's identity. Nightfix never matches people by Slack profile email. Slack approvals also need a Nightfix sign-in within the last 7 days, so team changes from your identity provider are never more than a week out of date.

Expressions such as `match`, `until` and `${{ }}` use [CEL](https://cel.dev), a small, safe expression language.
