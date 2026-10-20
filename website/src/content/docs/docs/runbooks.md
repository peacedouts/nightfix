---
title: Write a runbook
description: Runbooks are versioned YAML with steps the agent runs in your account.
---

A runbook is a YAML file with typed parameters, a target, triggers, and steps that run in order. Publishing creates a new, signed version. Runs always record exactly which version they used.

## A complete example

This runbook restarts an unhealthy ECS service before anyone is paged:

```yaml
apiVersion: nightfix/v1alpha1
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
| `aws` | Calls an AWS API with the agent's role (ECS, Secrets Manager, SSM, DynamoDB, CloudWatch Logs, KMS) |
| `wait` | Repeats a read-only AWS call until a condition is true |
| `shell` | Runs a bash script on the agent |

Planned: `manual` checklists, `approval` gates, `python`, `http`, container tasks, running scripts on EC2 fleets through SSM, and more AWS services such as RDS.

Expressions such as `match`, `until` and `${{ }}` use [CEL](https://cel.dev), a small, safe expression language.
