---
title: What Nightfix does
description: Nightfix matches alerts to runbooks and runs the fix in your AWS account before anyone is paged.
---

Nightfix is incident response for small teams on AWS. When an alert fires, it finds the runbook for it and runs the fix through an agent in your own account. If the fix works and the alert clears, the incident resolves and nobody is woken up. If it doesn't, your on-call is paged with everything Nightfix tried.

:::note[Early access]
Nightfix is in early access with a small group of design partners. These docs describe what's built today and say where something is still planned.
:::

## What it replaces

The manual part of a 3 a.m. page: reading the alert, finding the wiki page, opening a console, running the same three commands as last time, and watching the graph recover.

## What it doesn't replace (yet)

Today Nightfix works alongside your pager. When a page is needed, it sends one through **PagerDuty** or **incident.io**, or posts to **Slack**, and resolves that page automatically when the alert clears. Native on-call schedules and SMS or voice paging are on the roadmap.

## Where to go next

- [How it works](/docs/how-it-works/): the path from alert to fix, and what happens when the fix doesn't hold.
- [Security model](/docs/security/): what runs where, and why your secrets never leave your account.
- [Install the agent](/docs/agent/) and [write a runbook](/docs/runbooks/).
