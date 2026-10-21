# Nightfix — Alert-to-Incident Model (Draft v1alpha1)

Status: draft for discussion. Defines how alerts arrive, how they're deduplicated and routed, how they become incidents, and how auto-remediation runs before anyone is paged. Companion to `runbook-schema.md` and `agent-protocol.md`.

---

## 1. Design principles

1. **Never lose an alert.** Ingest persists the raw event first and processes it second. The ingest endpoint is the most availability-critical piece after notifications.
2. **One alert per real-world problem.** Repeated firings of the same alarm update one alert; they don't create noise.
3. **One incident per problem a human would treat as one.** Related alerts group into a single incident instead of paging five times.
4. **Remediate first, page second — but never silently.** When an auto runbook can fix the problem, it gets a short, bounded window to do so before paging. If anything goes wrong — the runbook fails, the alert keeps firing, no agent is available, the window expires — we page. Every auto-remediation is visible in Slack and the timeline, even when nobody is paged.
5. **Default to paging when unsure.** Every ambiguity in this model resolves toward "wake someone up". A missed page is worse than an unnecessary one.
6. **Simple enough to explain in one diagram.** No ML correlation, no topology inference in v1.

---

## 2. Core concepts

```
Integration ──► Alert ──(routing rules)──► Service ──(grouping)──► Incident
                  │                           │                       │
            fingerprint dedupe         escalation policy        runbook runs,
                                       runbooks, team            timeline, pages
```

| Concept | What it is |
|---|---|
| **Integration** | A configured inbound source (CloudWatch via SNS, Alertmanager, generic webhook, PagerDuty/incident.io inbound). Each has its own URL and credentials. |
| **Alert event** | One raw delivery from an integration. Immutable, stored as received. |
| **Alert** | The deduplicated, normalized state of one problem signal, identified by a **fingerprint**. Many events update one alert. |
| **Service** | The thing that's broken, from the customer's point of view (e.g. `checkout-api`). Owns a team, an escalation policy, linked runbooks and grouping rules. |
| **Incident** | The unit of response. Groups one or more alerts on a service, has a lifecycle, a timeline, runbook runs and pages. |

---

## 3. Ingestion

### 3.1 Integrations (v1)

| Integration | Auth / verification | Fingerprint source |
|---|---|---|
| **CloudWatch via SNS** | SNS message signature verified against the AWS signing cert; topic ARN must match the integration; handles `SubscriptionConfirmation` automatically | `AlarmArn` |
| **Prometheus Alertmanager** | Bearer token or HMAC header | Alertmanager's per-alert `fingerprint` |
| **Generic webhook** | HMAC-SHA256 signature header with a per-integration secret, plus timestamp (5-minute replay window) | `dedup_key` field if present, else configured label hash |
| **PagerDuty / incident.io inbound** | Their webhook signature schemes | Their incident or alert ID |

Each integration gets a unique URL: `https://ingest.nightfix.dev/v1/i/<integration_id>`. The integration ID identifies the org; the credential proves the sender.

### 3.2 The ingest path

1. Verify the signature or token. Reject with `401` if invalid.
2. **Persist the raw event** to `alert_events` (raw body, headers of interest, received time, integration).
3. Return **`202 Accepted`** immediately. Target p99 under 200 ms.
4. Normalize and process asynchronously from the Postgres queue (`SKIP LOCKED`).

Processing is at-least-once. Every step after persistence is idempotent, keyed on the event ID and the alert fingerprint.

Ingest runs as its own ECS service (same codebase, separate deployment and scaling) so a bad UI deploy or API load can't block alert intake.

### 3.3 Normalized alert schema

Every integration maps into one shape:

| Field | Notes |
|---|---|
| `fingerprint` | Dedupe identity (see 4.1) |
| `status` | `firing` \| `resolved` |
| `severity` | `critical` \| `high` \| `warning` \| `info` |
| `summary` | One line, shown in Slack and pages |
| `description` | Optional longer text |
| `source` | `cloudwatch`, `alertmanager`, `webhook`, … |
| `labels` | Key/values used for routing, grouping and runbook parameters |
| `annotations` | Key/values for display (links, runbook hints) |
| `occurred_at` | From the source when available, else receive time |
| `raw` | Original payload, kept for 30 days |

**Severity mapping** is configured per integration, with sensible defaults (e.g. CloudWatch `ALARM` → `high`, Alertmanager `severity` label passed through, unknown → `high`). Defaulting unknown severity to `high` follows principle 5.

**Label hygiene:** labels are size-capped (64 keys, 256 chars per value). Anything beyond is truncated and flagged. Labels are untrusted input; the runbook schema's pattern/enum rule exists because of this.

---

## 4. Deduplication

### 4.1 Fingerprints

1. Use the source's own stable identity when it has one (table in 3.1).
2. Otherwise, hash the integration ID plus the label keys configured as **dedupe keys** (default: `alertname`, `service`, `instance`).
3. A generic webhook can set `dedup_key` explicitly; that always wins.

### 4.2 Alert lifecycle

- **First firing** for a fingerprint creates an alert in `firing`.
- **Repeat firings** update `last_seen_at`, increment `event_count`, and update summary/labels. They don't create new alerts or new pages.
- **Resolved** event moves the alert to `resolved`.
- **Re-firing after resolution:** if within the **reopen window** (default 15 min), the same alert reopens. After that, it's a new alert. This stops a flapping alarm from generating a stream of separate alerts.
- **Stale alerts:** a `firing` alert with no events for 24h is marked `stale` in the UI but never auto-resolved. Many sources don't resend while firing, so silence doesn't mean healthy.

Uniqueness is enforced in Postgres: one open alert per `(org_id, fingerprint)`.

---

## 5. Routing

Routing decides which **service** an alert belongs to.

- Each integration has a **default service**.
- **Routing rules** override the default. Each rule is a CEL expression evaluated against the normalized alert, in priority order. First match wins.

```yaml
routing:
  - match: 'alert.labels.service == "checkout-api"'
    service: checkout-api
  - match: 'alert.source == "cloudwatch" && alert.labels.alarm_name.startsWith("rds-")'
    service: databases
  - match: 'alert.severity == "info"'
    action: suppress          # store, show in UI, never open an incident
```

- If nothing matches and there's no default, the alert routes to the org's **catch-all service**, which always exists and has an escalation policy. No alert is ever unrouted.
- Rules are versioned and audit-logged like everything else.

---

## 6. Grouping alerts into incidents

### 6.1 Rule

Within a service, an alert joins an **open incident** with the same **group key**. Otherwise it opens a new incident.

- **Group key** = service + configured grouping labels (default: none, meaning one open incident per service at a time).
- Example: grouping labels `[cluster]` on `checkout-api` gives separate incidents for `prod-east` and `prod-west`, but all alerts within one cluster join one incident.
- **Grouping window:** an alert can join an incident only while the incident is open and was created within the window (default 2h). After that, a new incident opens, so one stuck incident doesn't absorb an unrelated problem a day later.

### 6.2 Severity

An incident's severity is the **highest** severity of its alerts. If a `critical` alert joins a `warning` incident, the incident upgrades — and if it wasn't being paged, it now is.

### 6.3 What v1 doesn't do

No cross-service correlation, no time-based "these happened together" heuristics, no ML. Customers can merge incidents manually in the UI or Slack.

---

## 7. Incident lifecycle

```
                  ┌──────────── auto runbook matched, beforePaging ───────────┐
                  │                                                            ▼
 alert ──► [triggered] ◄── remediation failed / timed out / alert still ── [remediating]
                  │            firing / no agent                               │
                  │                                                            │ runbook succeeded
             page sent                                                         │ AND alerts resolved
                  │                                                            ▼
                  ▼                                                     [resolved]
           [acknowledged] ──── human resolves, or all alerts resolve ───►  (auto-remediated)
```

| State | Meaning | Paging |
|---|---|---|
| `remediating` | An auto runbook with `beforePaging: true` is running | **Held**, bounded by the hold window (7.2) |
| `triggered` | Needs a human; escalation policy is active | Paging per escalation policy |
| `acknowledged` | A human owns it | Escalation stops; re-escalates if unacknowledged again or on timeout (configurable) |
| `resolved` | Done | None |

**Auto-resolve:** an incident resolves automatically when all its alerts are resolved — configurable per service, on by default. A human can also resolve it manually; alerts still firing are then detached and will open a new incident if they keep firing.

**Reopen:** a resolved incident reopens if one of its alerts re-fires within the reopen window (default 15 min). This matters for auto-remediation: a restart that "fixes" things for 3 minutes shouldn't count as a success.

---

## 8. Remediate before paging

This is the wedge, so it gets the most care.

### 8.1 Flow

1. A new incident opens. The control plane evaluates the `match` expression of every runbook trigger linked to the incident's service against the alert. `auto` triggers are always linked to named services; `suggest` and `one-click` triggers may also be org-wide.
2. If an `auto` trigger with `beforePaging: true` matches **and** all hold conditions in 8.3 pass, the incident enters `remediating`, and a Slack message posts: "Auto-remediation started: `ecs-service-restart` for `checkout-api` — paging held for up to 10m."
3. The runbook runs through the agent protocol.
4. Outcome:
   - **Runbook succeeds and every alert on the incident resolves** within the **verification window** (default 5 min after the run ends): incident → `resolved`, tagged `auto-remediated`. Slack posts a summary. No page.
   - **Runbook fails, is rejected, is lost, or times out:** incident → `triggered`, page immediately with context ("auto-remediation `ecs-service-restart` failed at step `wait-stable`").
   - **Runbook succeeds but alerts are still firing** after the verification window: incident → `triggered`, page ("remediation ran but the alert is still firing").
5. If the incident reopens within the reopen window after an auto-remediated resolve, it goes straight to `triggered` and pages. The same auto runbook is **not** retried for that incident.

### 8.2 The hold window

Paging is held for at most:

`min(runbook policy.timeout + verification window, service max hold)`

**Service max hold** defaults to **10 minutes** and can't exceed 30. When it expires, we page regardless of what the runbook is doing — the run keeps going, and the page says so.

### 8.3 Hold conditions — page immediately instead if any are true

- The incident severity is `critical` **and** the matched runbook has not earned critical hold on this service (8.6). By default, critical incidents page **in parallel** with remediation, not after.
- No healthy agent matches the runbook's `target`.
- The org or agent is frozen (kill switch).
- The runbook's `cooldown` or `maxRunsPerHour` would be exceeded.
- More than one `auto` + `beforePaging` runbook matches. Ambiguity pages a human; v1 never picks between competing auto-fixes.
- The **flap guard** trips: this fingerprint has been auto-remediated 3+ times in 24h (configurable). Repeated "successful" fixes mean the real problem isn't being addressed.

### 8.4 Non-auto triggers

- `one-click` triggers attach a button to the incident in Slack and the UI. Paging proceeds normally.
- `suggest` triggers attach the runbook as a recommended next step. Paging proceeds normally.

### 8.5 Where pages go in v1

Until our own paging ships (months 3–5), "page" means **escalating to the customer's existing pager**:

- PagerDuty: create an event via the Events API v2, with the incident summary, the remediation outcome, and a link back.
- incident.io: create an alert via their alert source API.
- Slack-only teams: post to the service's channel with an `@here` or user-group mention.

When our own paging ships, this becomes the service's escalation policy. The incident model doesn't change.

**Every page we send carries a stable dedupe key** (the incident ID), so we can update and resolve it later. If the incident is later resolved — by remediation, by the alerts clearing, or by a human in our UI — we resolve the upstream PagerDuty or incident.io page automatically.

### 8.6 Critical incidents

Decided Oct 20, 2026.

**Default: page in parallel.** For a `critical` incident with a matching auto runbook, the runbook starts immediately and the page goes out at the same time. The costs are lopsided: an unnecessary critical page costs a few minutes of sleep; a held page during a real outage while a runbook does the wrong thing costs the customer's trust.

**The parallel page is made cheap for the responder:**
- The page text says remediation is in progress and gives the runbook's typical duration, taken from its recent successful runs (e.g. "Auto-remediation `ecs-service-restart` in progress — usually completes in ~4 min").
- If the runbook succeeds and the alerts clear within the verification window, the upstream page is **resolved automatically** via its dedupe key. Often the responder sees "resolved" before they've opened a laptop, and escalation never reaches the next person.
- The incident's Slack thread shows step-by-step progress, so the responder can watch from a phone.

**Earned critical hold, per runbook per service.** A runbook may hold critical pages on a given service only when both are true:

1. **Track record:** at least **10 verified auto-remediations** on that service in the last **30 days**, with **zero reopens**. "Verified" means the run succeeded and every alert on the incident resolved within the verification window and stayed resolved through the reopen window. Runs of any severity count.
2. **Explicit opt-in:** an Admin turns on critical hold for that runbook on that service. The UI shows the track record (count, success rate, median time to fix, last failure) at the moment of opt-in. The grant is audit-logged with who granted it and the track record at the time.

**Guardrails on a held critical incident:**
- **Max hold is 5 minutes** for critical, regardless of service or runbook settings (versus the 10-minute default for other severities).
- **Automatic revocation:** if a held critical run fails, times out, is lost or rejected, or the incident reopens, the grant is revoked immediately. That runbook returns to parallel paging on that service, the incident pages at once, and the granting Admin and service owners are notified. Re-granting requires the track record to be met again from that point.
- **All other hold conditions in 8.3 still apply:** no healthy agent, frozen org, cooldown or rate limit exceeded, multiple matching auto runbooks, or the flap guard tripping all page immediately.
- **Grants expire:** a grant lapses after 30 days without a verified run, since a runbook nobody has exercised recently hasn't kept its track record.

**Why per runbook and not per service:** the evidence is about a specific fix for a specific failure. A service-wide toggle would let a new, unproven runbook inherit trust earned by a different one.

**Not authored in YAML.** Critical hold is a grant stored by the control plane, not a field in the runbook. A runbook author can't give their own runbook the right to silence critical pages.

**Severity calibration hint.** When a runbook reliably fixes a `critical` alert within minutes, the alert is often miscalibrated: the service never really went down. The service page shows a suggestion when a critical alert's incidents are auto-remediated 90%+ of the time over 30 days: "Consider reclassifying this alert as `high`." Reclassifying is often a better fix than a hold.

---

## 9. Suppression and maintenance

- **Maintenance windows** per service (one-off or recurring). During a window, alerts are stored and shown but don't open incidents or page. Auto runbooks don't run either — maintenance usually means a human is already changing things.
- **Suppress rules** (5) drop alerts from incidents permanently, e.g. `info` noise.
- Both are audit-logged, and the UI shows a banner on any service with an active window so nobody forgets one is on.

---

## 10. Incident timeline

Every incident has an append-only timeline, which is also the basis for postmortems later:

- Alert opened / joined / re-fired / resolved
- Routing and grouping decisions ("joined incident #412 by group key `checkout-api/prod-east`")
- Runbook run started, each step's result, approvals requested/granted, run outcome
- Hold started / released, with the reason
- Pages sent (to which pager, which recipient), acknowledgments, escalations
- Human actions: ack, resolve, merge, notes from Slack or UI

Timeline entries share the ≥1-year immutable retention of audit metadata.

---

## 11. Data model sketch

All tables carry `org_id` with row-level security.

| Table | Key columns |
|---|---|
| `integrations` | `id`, `type`, `default_service_id`, `severity_map`, `dedupe_keys`, credential reference |
| `alert_events` | `id`, `integration_id`, `received_at`, `raw` (30-day retention), `processed_at` |
| `alerts` | `id`, `fingerprint`, `status`, `severity`, `summary`, `labels`, `first_seen_at`, `last_seen_at`, `event_count`, `service_id`, `incident_id` |
| `services` | `id`, `name`, `team_id`, `grouping_labels`, `grouping_window`, `max_hold`, `auto_resolve`, escalation target |
| `critical_hold_grants` | `id`, `runbook_name`, `service_id`, `granted_by`, `granted_at`, `track_record_snapshot`, `last_verified_run_at`, `revoked_at`, `revoked_reason` |
| `routing_rules` | `id`, `priority`, `match` (CEL), `service_id` or `action`, `version` |
| `incidents` | `id`, `number` (per-org sequence), `service_id`, `group_key`, `status`, `severity`, `opened_at`, `ack_at`, `resolved_at`, `resolution` (`human` \| `auto_remediated` \| `alerts_resolved`), `hold_until` |
| `incident_timeline` | `id`, `incident_id`, `at`, `type`, `actor`, `data` (append-only) |
| `runbook_runs` | existing; gains `incident_id`, `trigger_type`, `before_paging`, `held_critical`, `verified` (succeeded, alerts cleared and stayed clear: set true when the alerts clear after a successful auto run of any severity, and false if the incident then reopens; the flap guard counts both, a critical-hold track record only true) |
| `maintenance_windows` | `id`, `service_id`, `starts_at`, `ends_at`, `recurrence` |

Unique index on open alerts: `(org_id, fingerprint) WHERE status <> 'resolved'`. Unique index on open incidents: `(org_id, service_id, group_key) WHERE status <> 'resolved'`. These two indexes make dedupe and grouping safe under concurrent ingest.

---

## 12. Worked example: ECS service auto-fixed overnight

1. **02:14:03** — CloudWatch alarm `ecs-unhealthy-checkout` enters `ALARM`; SNS delivers to the integration. Persisted, `202` returned.
2. **02:14:04** — Normalized: fingerprint = AlarmArn, severity `high`, labels `cluster=prod-east, service=checkout-api`. Routed to service `checkout-api`. No open incident with group key `checkout-api/prod-east` → incident #412 opens.
3. **02:14:04** — `ecs-service-restart` trigger matches (`auto`, `beforePaging`). Hold conditions pass. Incident → `remediating`, hold until 02:24:04 (10m max hold). Slack: "Auto-remediation started…"
4. **02:14:05–02:19:40** — Runbook runs: describe → force new deployment → wait until stable. Succeeds.
5. **02:21:10** — CloudWatch sends `OK`. Alert resolved, within the 5-min verification window. Incident #412 → `resolved` (`auto_remediated`). Slack summary posted. **Nobody was woken up.**
6. If the alarm had still been in `ALARM` at 02:24:40, the incident would have moved to `triggered` and paged through PagerDuty with the full run output attached.

---

## 13. Open questions

1. **Default grouping.** One open incident per service (simplest, may over-group) vs. requiring grouping labels at service setup (more accurate, more setup friction)?
2. ~~Critical-severity behavior.~~ **Resolved:** page in parallel by default, auto-resolve the upstream page on success, and allow earned critical hold per runbook per service (8.6).
3. **Track-record thresholds.** Are 10 verified runs / 30 days / zero reopens the right bar? Tune with design-partner data.
4. **Verification window default.** Five minutes balances "really fixed" against holding pages. CloudWatch alarm periods can be longer than that; should the default adapt to the alarm's evaluation period?
5. **Ack timeout.** Re-escalate an acknowledged incident if it isn't resolved within N hours, or leave that to the escalation policy once paging ships?
6. **Heartbeat / dead-man alerts.** "Alert if we *stop* hearing from X" is a common ask and very cheap to add. v1 or soon after?
