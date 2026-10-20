---
title: How it works
description: From alert to fix, and what happens when the fix doesn't hold.
---

## 1. An alert arrives

Nightfix accepts alerts from **CloudWatch** (through SNS) and from any system that can send a **signed webhook**. Every delivery is stored before it's processed, so an alert is never lost.

Repeats of the same alarm update one alert instead of creating new ones. If an alarm re-fires within 15 minutes of clearing, the same alert reopens. Routing rules decide which service an alert belongs to, and anything unmatched lands on a catch-all service, so no alert goes unrouted.

## 2. Alerts group into an incident

Alerts on the same service with the same grouping labels join one open incident, so five related alarms page you once. The incident takes the highest severity of its alerts.

## 3. A runbook matches

Each runbook declares which alerts it handles and how it starts:

- **Suggest:** shown on the incident as a recommended next step.
- **One-click:** a button in Slack and the app.
- **Automatic:** runs as soon as the incident opens. An automatic runbook must name the services it may act on, and it needs a cooldown and an hourly run limit.

When an automatic runbook is set to run **before paging**, the page is held for a short window: by default up to 10 minutes, never more than 30.

## 4. The agent runs the fix

The agent in your VPC receives one step at a time, checks its signature, and runs it under your IAM role. Output streams back to the incident timeline with secrets removed.

## 5. Nightfix checks the fix held

The incident resolves as auto-remediated only if the run succeeded **and** every alert cleared within the verification window (5 minutes by default) and stayed clear.

## When the fix doesn't hold

Nightfix pages your on-call immediately, with the run output attached, if any of these happen:

- The run fails, times out, or the agent disappears mid-step.
- The alert is still firing after the fix.
- The hold window runs out.
- No healthy agent can run the runbook, or your org is frozen.
- More than one automatic runbook matches. Nightfix never picks between competing fixes.
- The same alert has been auto-fixed three times in 24 hours, which means the real problem isn't being fixed.

**Critical incidents page at the same moment the fix starts** by default, so you're never in the dark for the big ones. When the alert clears, the page in PagerDuty or incident.io resolves itself.

If the agent disappears in the middle of a step that changes something, such as a restart or a failover, Nightfix doesn't retry it. It pages a human, because the step may or may not have happened.
