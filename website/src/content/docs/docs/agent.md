---
title: Install the agent
description: Run one agent per VPC or cluster, enrolled by its IAM role.
---

The agent is a single binary. Run one per VPC or cluster, not one per host. For production, run two per environment so losing one never blocks a fix.

## 1. Create an IAM role for the agent

Give the role permission for what your runbooks do, and nothing more. For the ECS restart example that's `ecs:DescribeServices` and `ecs:UpdateService` on the services involved, plus `secretsmanager:GetSecretValue` for any secrets your runbooks read.

The identity check the agent uses to enroll, `sts:GetCallerIdentity`, needs no permission.

## 2. Allow the role to enroll

In Nightfix, add an enrollment rule naming the role and the labels its agents get:

```json
{
  "method": "iam",
  "role_arn": "arn:aws:iam::123456789012:role/nightfix-agent",
  "labels": { "env": "prod" },
  "max_agents": 2
}
```

Labels always come from the rule, never from the agent. A runbook that targets `env: prod` only runs on agents enrolled with that label.

## 3. Run the agent under the role

As an ECS service, a Kubernetes deployment, or a systemd unit on EC2:

```sh
nightfix-agent --endpoint https://agent.nightfix.dev --org org_…
```

The agent needs outbound HTTPS to Nightfix and the AWS APIs it calls. It works through an HTTPS proxy.

## Optional hardening

- `--required-signers <key ids>` requires those signatures on every runbook, whatever Nightfix's own settings say.
- `--allowlist <file> --allowlist-mode enforce` runs only the runbook versions you list.
- `--freeze` keeps the agent connected but stops it from running anything.

## Hosts without an IAM role

Use a single-use enrollment token instead: create a rule with `"method": "token"` and start the agent with `--enroll-method token --enroll-token …`.
