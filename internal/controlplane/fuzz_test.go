package controlplane

// Fuzz targets for everything the control plane parses from untrusted
// senders: SNS envelopes, CloudWatch alarm messages, webhook bodies and
// webhook signature headers. `go test` runs the seeds; to search, e.g.
//   go test ./internal/controlplane -run '^$' -fuzz FuzzNormalizeWebhook -fuzztime 2m

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzParseSNS(f *testing.F) {
	f.Add([]byte(`{"Type":"Notification","MessageId":"m","TopicArn":"arn:aws:sns:us-east-1:1:t","Message":"x","Timestamp":"2026-10-22T00:00:00Z","SignatureVersion":"2","Signature":"c2ln","SigningCertURL":"https://sns.us-east-1.amazonaws.com/c.pem"}`))
	f.Add([]byte(`{"Type":"SubscriptionConfirmation","SubscribeURL":"https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		m, err := parseSNS(body)
		if err != nil {
			return
		}
		// Whatever parses must be safe to build a string to sign from.
		_, _ = m.stringToSign()
	})
}

func FuzzNormalizeCloudWatch(f *testing.F) {
	f.Add(`{"AlarmName":"ecs-unhealthy-checkout","NewStateValue":"ALARM","NewStateReason":"r","StateChangeTime":"2026-10-21T02:14:03.120+0000","AlarmArn":"arn:aws:cloudwatch:us-east-1:1:alarm:a","Trigger":{"Dimensions":[{"name":"ClusterName","value":"prod-east"}]}}`)
	f.Add(`{"NewStateValue":"OK"}`)
	f.Add(`{"Trigger":{"Metrics":[{"MetricStat":{"Metric":{"Dimensions":[{"name":"ServiceName","value":"x"}]}}}]}}`)
	f.Fuzz(func(t *testing.T, msg string) {
		a, err := normalizeCloudWatch("int1", msg, map[string]string{"ALARM": "critical"})
		if err != nil {
			return
		}
		checkAlert(t, a)
		if a.StateAt.After(time.Now().Add(maxStateClockSkew + time.Minute)) {
			t.Fatalf("state time %v isn't clamped", a.StateAt)
		}
	})
}

func FuzzNormalizeWebhook(f *testing.F) {
	f.Add([]byte(`{"dedup_key":"A","summary":"checkout down","severity":"critical","labels":{"service":"checkout-api"}}`))
	f.Add([]byte(`{"summary":"x","status":"resolved","labels":{"a":"b","c":"d"}}`))
	f.Add([]byte(`{"summary":"` + strings.Repeat("é", 400) + `"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		a, err := normalizeWebhook("int1", body, []string{"service"})
		if err != nil {
			return
		}
		checkAlert(t, a)
	})
}

func FuzzVerifyWebhook(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"summary":"x"}`)
	f.Add(SignWebhook("secret", body, now), body)
	f.Add("t=1,v1=zz", body)
	f.Add("v1=,t=", []byte{})
	f.Fuzz(func(t *testing.T, header string, body []byte) {
		at, sig, err := verifyWebhook("secret", body, header, now)
		if err != nil {
			return
		}
		// Only the correct signature over this body and time passes.
		_, want, _ := strings.Cut(SignWebhook("secret", body, at), ",v1=")
		if sig != want {
			t.Fatalf("accepted header %q (signature %s, want %s)", header, sig, want)
		}
		if d := now.Sub(at); d > webhookWindow || d < -webhookWindow {
			t.Fatalf("accepted a signature from %v", at)
		}
	})
}

// checkAlert: what any normalizer produces must be storable and bounded.
func checkAlert(t *testing.T, a Alert) {
	t.Helper()
	if a.Fingerprint == "" || len(a.Fingerprint) > 600 {
		t.Fatalf("fingerprint of %d bytes", len(a.Fingerprint))
	}
	if !validSeverity[a.Severity] || (a.Status != "firing" && a.Status != "resolved") {
		t.Fatalf("severity %q status %q", a.Severity, a.Status)
	}
	if len(a.Labels) > 64 || len(a.Summary) > 300 {
		t.Fatalf("%d labels, summary of %d bytes", len(a.Labels), len(a.Summary))
	}
	for k, v := range a.Labels {
		if !utf8.ValidString(k) || !utf8.ValidString(v) || strings.ContainsRune(k+v, 0) {
			t.Fatalf("label %q=%q isn't storable text", k, v)
		}
	}
	if !utf8.ValidString(a.Summary) || strings.ContainsRune(a.Summary, 0) {
		t.Fatalf("summary %q isn't storable text", a.Summary)
	}
}
