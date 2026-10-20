---
title: Security model
description: What runs where, what Nightfix can and can't touch, and the controls you hold.
---

Nightfix runs code in your infrastructure, so the design starts from one question: what happens if Nightfix itself is compromised?

## What runs where

| Nightfix (hosted) | Your AWS account |
|---|---|
| Alert intake, incidents, routing, schedules | The agent: one per VPC or cluster |
| Runbook definitions and their signatures | Execution of every step, under your IAM role |
| The audit log | Your secrets, read at run time and never sent out |

The agent makes **outbound connections only**, over HTTPS on port 443. You open no inbound ports.

## What Nightfix never holds

Nightfix never holds credentials to your infrastructure, or the secrets your runbooks use. Runbooks refer to secrets by name, such as `secret://aws-sm/prod/db-password`. The agent reads them from Secrets Manager or SSM Parameter Store when a step runs and scrubs them, including base64 and URL-encoded forms, from all output.

The only credentials Nightfix stores are for notifications and Slack buttons: your PagerDuty routing key, your Slack webhook or bot token, your Slack app's signing secret, and the secret that signs your webhook alerts. Each is encrypted per organization, never shown again after you save it, and can't reach your infrastructure.

## How the agent proves who it is

The agent enrolls by **proving its IAM role**. It signs an AWS identity request that includes a single-use code from Nightfix, and AWS confirms the signature. You decide which roles may enroll and which labels, such as `env=prod`, each agent gets. There is no long-lived token to leak.

After enrolling, the agent uses a client certificate that expires every 24 hours. You can revoke an agent at any time.

## Nothing runs unsigned

- Every runbook version is **immutable and signed** when it's published.
- Every step sent to an agent is **signed for that agent only** and expires after two minutes, so it can't be replayed or redirected to another agent.
- The agent re-checks everything before running: signatures, expiry, which agent the step is for, and parameter values.

**Require your own signature.** You can require that every runbook also carries a signature from a key you hold, for example one your CI signs with on merge. Pin that requirement in the agent's own config: then even a compromised Nightfix can't get new code run in your account.

## Untrusted input stays out of scripts

Alert contents can be influenced by attackers, so a script body is never built from alert data. Values reach scripts only as environment variables or files. Any value taken from an alert must match a pattern or a fixed list. Nightfix rejects runbooks that break either rule when they're published.

## Your kill switches

- **Freeze your org** from the app. All runs stop and nothing new starts.
- **Freeze an agent locally** with a flag on the agent. It stays connected so you can see it, but runs nothing, whatever Nightfix says.

## Isolation and audit

Each customer's data is isolated in the database itself, not only in application code. Every action is recorded in an audit log that the application can't edit or delete, and the log is chained so tampering is detectable.

## Reporting a vulnerability

Email [security@nightfix.dev](mailto:security@nightfix.dev). We'll acknowledge within two business days. Our [security.txt](/.well-known/security.txt) has the details.
