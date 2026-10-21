-- Generic webhook dedup keys are now scoped to their integration (QA
-- follow-up). A webhook's `dedup_key` used to become the fingerprint
-- 'wh:<key>' as is, so two integrations in an org (two tools, or two teams'
-- tools) that used the same key updated and resolved each other's alert. It
-- is now 'wh:<integration id>:<key>'. Fingerprints hashed from labels
-- already included the integration and are unchanged, as are CloudWatch
-- fingerprints ('cw:<AlarmArn>').
--
-- Alerts stored before this change are rewritten to the new form under the
-- integration that created them, so an open alert still resolves (and a
-- recently resolved one still reopens) when its next event arrives. Where
-- two integrations had collided on one alert, it stays with the integration
-- that created it; the other integration's next event starts its own alert.
-- runbook_runs.fingerprint feeds the flap guard (verified auto-fixes per
-- fingerprint in 24h), so runs tied to a rewritten alert move with it.
--
-- A label-hash fingerprint is 'wh:' plus 64 hex characters, which a
-- dedup_key could also be; each candidate is told apart by recomputing its
-- label hash (integration id, then NUL + key=value for each of the
-- integration's dedupe_keys; see normalizeWebhook). If dedupe_keys changed
-- since, a hash-derived fingerprint gets rewritten too, which is harmless:
-- new events no longer produce it either way.
--
-- Data only and idempotent: already-scoped fingerprints are skipped.

SET ROLE nfx_owner;

WITH m AS (
  SELECT a.org_id, a.id, a.fingerprint AS old_fp,
         'wh:' || a.integration_id::text || ':' || substr(a.fingerprint, 4) AS new_fp
  FROM alerts a
  JOIN integrations i ON i.org_id = a.org_id AND i.id = a.integration_id
  WHERE i.type = 'webhook'
    AND a.fingerprint LIKE 'wh:%'
    AND NOT starts_with(a.fingerprint, 'wh:' || a.integration_id::text || ':')
    AND substr(a.fingerprint, 4) <> encode(sha256(
          convert_to(a.integration_id::text, 'UTF8') ||
          coalesce((SELECT string_agg('\x00'::bytea || convert_to(k.key || '=' || coalesce(a.labels ->> k.key, ''), 'UTF8'),
                                      ''::bytea ORDER BY k.ord)
                    FROM unnest(i.dedupe_keys) WITH ORDINALITY AS k(key, ord)), ''::bytea)), 'hex')
    -- Never collide with an open alert that already has the new form.
    AND NOT (a.status <> 'resolved' AND EXISTS (
          SELECT 1 FROM alerts o
          WHERE o.org_id = a.org_id AND o.status <> 'resolved'
            AND o.fingerprint = 'wh:' || a.integration_id::text || ':' || substr(a.fingerprint, 4)))
),
runs AS (
  UPDATE runbook_runs r SET fingerprint = m.new_fp
  FROM incident_alerts ia JOIN m ON m.org_id = ia.org_id AND m.id = ia.alert_id
  WHERE r.org_id = ia.org_id AND r.incident_id = ia.incident_id AND r.fingerprint = m.old_fp
  RETURNING 1
)
UPDATE alerts a SET fingerprint = m.new_fp
FROM m
WHERE a.org_id = m.org_id AND a.id = m.id;

RESET ROLE;
