package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Alert is the normalized form every integration maps into
// (alert-incident-model.md §3.3).
type Alert struct {
	Fingerprint string            `json:"fingerprint"`
	Status      string            `json:"status"` // firing | resolved
	Severity    string            `json:"severity"`
	Summary     string            `json:"summary"`
	Source      string            `json:"source"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	OccurredAt  time.Time         `json:"occurred_at"`
	// StateAt is when the source says this state began (CloudWatch
	// StateChangeTime). Zero when the source has no such timestamp; then
	// events apply in processing order. Otherwise an update that isn't newer
	// than the alert's latest applied state is ignored.
	StateAt time.Time `json:"-"`
}

// errIgnore marks an event that is stored but intentionally not processed
// (e.g. a CloudWatch INSUFFICIENT_DATA transition).
var errIgnore = errors.New("ignored")

var validSeverity = map[string]bool{"critical": true, "high": true, "warning": true, "info": true}

const (
	maxLabels     = 64
	maxLabelValue = 256
)

// capLabels enforces label hygiene: labels are untrusted input.
func capLabels(in map[string]string) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= maxLabels {
			out["_truncated"] = "true"
			break
		}
		v := in[k]
		if len(v) > maxLabelValue {
			v = v[:maxLabelValue]
			out["_truncated"] = "true"
		}
		if len(k) > 128 {
			k = k[:128]
		}
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// CloudWatch (delivered through SNS)
// ---------------------------------------------------------------------------

type cloudWatchAlarm struct {
	AlarmName        string `json:"AlarmName"`
	AlarmDescription string `json:"AlarmDescription"`
	AWSAccountID     string `json:"AWSAccountId"`
	NewStateValue    string `json:"NewStateValue"`
	NewStateReason   string `json:"NewStateReason"`
	StateChangeTime  string `json:"StateChangeTime"`
	Region           string `json:"Region"`
	AlarmArn         string `json:"AlarmArn"`
	Trigger          struct {
		MetricName string `json:"MetricName"`
		Namespace  string `json:"Namespace"`
		Dimensions []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"Dimensions"`
	} `json:"Trigger"`
}

// Common CloudWatch dimension names get short aliases so runbooks can write
// alert.labels.cluster / alert.labels.service.
var dimensionAliases = map[string]string{
	"ClusterName":          "cluster",
	"ServiceName":          "service",
	"DBClusterIdentifier":  "db_cluster",
	"DBInstanceIdentifier": "db_instance",
	"LoadBalancer":         "load_balancer",
	"TargetGroup":          "target_group",
	"CacheClusterId":       "cache_cluster",
	"FunctionName":         "function",
}

// The fingerprint is scoped to the integration: any account that can
// publish to a pinned topic chooses the AlarmArn in its message, so without
// the scope one integration's messages could resolve (or, with a future
// StateChangeTime, silence) another's alarm.
// maxStateClockSkew is how far in the future a source's state-change time
// may be (clock skew) before it's clamped.
const maxStateClockSkew = 5 * time.Minute

func normalizeCloudWatch(integrationID, message string, severityMap map[string]string) (Alert, error) {
	var a cloudWatchAlarm
	if err := json.Unmarshal([]byte(message), &a); err != nil {
		return Alert{}, fmt.Errorf("not a CloudWatch alarm message: %w", err)
	}
	if a.AlarmArn == "" || a.NewStateValue == "" {
		return Alert{}, errors.New("CloudWatch message missing AlarmArn or NewStateValue")
	}
	var status string
	switch a.NewStateValue {
	case "ALARM":
		status = "firing"
	case "OK":
		status = "resolved"
	default: // INSUFFICIENT_DATA: not a signal either way
		return Alert{}, errIgnore
	}
	labels := map[string]string{
		"alarm_name": a.AlarmName,
		"region":     a.Region,
		"account":    a.AWSAccountID,
		"metric":     a.Trigger.MetricName,
		"namespace":  a.Trigger.Namespace,
	}
	for _, d := range a.Trigger.Dimensions {
		labels[d.Name] = d.Value
		if alias, ok := dimensionAliases[d.Name]; ok {
			labels[alias] = d.Value
		}
	}
	sev := severityMap[a.NewStateValue]
	if !validSeverity[sev] {
		sev = "high" // unknown severity defaults toward paging
	}
	t, err := time.Parse("2006-01-02T15:04:05.000-0700", a.StateChangeTime)
	stateAt := t
	if err != nil {
		t, stateAt = time.Now(), time.Time{}
	}
	// A state change can't have happened in the future: clamp it (allowing a
	// little clock skew), or one message dated 2099 would make every later
	// genuine state change look stale and be dropped.
	if limit := time.Now().Add(maxStateClockSkew); stateAt.After(limit) {
		t, stateAt = limit, limit
	}
	summary := a.AlarmName
	if a.NewStateReason != "" {
		summary = a.AlarmName + ": " + a.NewStateReason
	}
	return Alert{
		Fingerprint: "cw:" + integrationID + ":" + a.AlarmArn,
		Status:      status,
		Severity:    sev,
		Summary:     truncate(summary, 300),
		Source:      "cloudwatch",
		Labels:      capLabels(labels),
		Annotations: capLabels(map[string]string{"description": a.AlarmDescription, "alarm_arn": a.AlarmArn}),
		OccurredAt:  t,
		StateAt:     stateAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Generic webhook
// ---------------------------------------------------------------------------

type webhookBody struct {
	DedupKey    string            `json:"dedup_key"`
	Status      string            `json:"status"`
	Severity    string            `json:"severity"`
	Summary     string            `json:"summary"`
	Source      string            `json:"source"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

func normalizeWebhook(integrationID string, body []byte, dedupeKeys []string) (Alert, error) {
	var w webhookBody
	if err := json.Unmarshal(body, &w); err != nil {
		return Alert{}, fmt.Errorf("invalid JSON body: %w", err)
	}
	switch w.Status {
	case "firing", "resolved":
	case "":
		w.Status = "firing"
	default:
		return Alert{}, fmt.Errorf("status must be firing or resolved")
	}
	if w.Summary == "" {
		return Alert{}, errors.New("summary is required")
	}
	if !validSeverity[w.Severity] {
		w.Severity = "high"
	}
	if w.Source == "" {
		w.Source = "webhook"
	}
	labels := capLabels(w.Labels)
	var fp string
	if w.DedupKey != "" {
		// Scoped to the integration: two integrations (or two tools) that
		// happen to use the same key must not update each other's alert.
		// migrations/0015 rewrote alerts stored before this.
		fp = integrationID + ":" + truncate(w.DedupKey, 200)
	} else {
		h := sha256.New()
		h.Write([]byte(integrationID))
		for _, k := range dedupeKeys {
			h.Write([]byte{0})
			h.Write([]byte(k + "=" + labels[k]))
		}
		fp = hex.EncodeToString(h.Sum(nil))
	}
	return Alert{
		Fingerprint: "wh:" + fp,
		Status:      w.Status,
		Severity:    w.Severity,
		Summary:     truncate(w.Summary, 300),
		Source:      truncate(w.Source, 64),
		Labels:      labels,
		Annotations: capLabels(w.Annotations),
		OccurredAt:  time.Now(),
	}, nil
}

// WebhookSignatureHeader carries "t=<unix>,v1=<hex hmac>".
const WebhookSignatureHeader = "X-Nightfix-Signature"

// SignWebhook produces the header value for body (used by tests and senders).
func SignWebhook(secret string, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// verifyWebhook checks the HMAC signature and a 5-minute replay window.
func verifyWebhook(secret string, body []byte, header string, now time.Time) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	if ts == "" || sig == "" {
		return errors.New("missing or malformed signature header")
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad signature timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return errors.New("signature timestamp outside the 5-minute window")
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	want := m.Sum(nil)
	got, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return errors.New("signature mismatch")
	}
	return nil
}

// truncate cuts s to at most n bytes without splitting a UTF-8 character
// (Postgres rejects text with a partial character).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cleanText makes untrusted text storable: valid UTF-8 and no NUL bytes,
// which Postgres rejects in text and jsonb.
func cleanText(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "")
}

func cleanMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[cleanText(k)] = cleanText(v)
	}
	return out
}

// sanitizeAlert is applied to every normalized alert before it's stored, so
// no payload content can make processing fail.
func sanitizeAlert(a Alert) Alert {
	a.Fingerprint = cleanText(a.Fingerprint)
	a.Summary = cleanText(a.Summary)
	a.Source = cleanText(a.Source)
	a.Labels = cleanMap(a.Labels)
	a.Annotations = cleanMap(a.Annotations)
	return a
}
