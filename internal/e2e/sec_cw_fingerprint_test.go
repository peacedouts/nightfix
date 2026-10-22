package e2e_test

// Security review: CloudWatch fingerprints are not scoped to their
// integration. Migration 0015 scoped webhook dedup keys per integration
// because "two integrations ... updated and resolved each other's alert";
// CloudWatch kept 'cw:<AlarmArn>', where AlarmArn is message content that
// anyone able to publish to the *other* pinned topic chooses freely.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/peacedouts/nightfix/internal/devstub"
)

func TestSecCloudWatchAlarmCannotBeResolvedFromAnotherIntegration(t *testing.T) {
	x := setupIngest(t, nil)
	const topicA = "arn:aws:sns:us-east-1:111111111111:team-a-alarms"
	const topicB = "arn:aws:sns:us-east-1:222222222222:team-b-alarms"
	x.call("POST", "/v1/services", map[string]any{"name": "payments"}, nil)
	var a, b map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "team a", "default_service": "checkout-api", "topic_arn": topicA}, &a)
	x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "team b", "default_service": "payments", "topic_arn": topicB}, &b)
	urlA := strings.Replace(a["ingest_url"], "http://ingest", x.ingBase, 1)
	urlB := strings.Replace(b["ingest_url"], "http://ingest", x.ingBase, 1)
	post := func(url, topic string, alarm map[string]any) {
		t.Helper()
		resp, err := http.Post(url, "text/plain", bytes.NewReader(x.stub.SNSEnvelope(topic, alarm)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 202 {
			t.Fatalf("ingest: %d", resp.StatusCode)
		}
	}

	// Team A's real alarm opens an incident.
	alarm := devstub.CloudWatchAlarm("checkout-5xx", "ALARM", "prod-east", "checkout-api")
	alarm["AlarmArn"] = "arn:aws:cloudwatch:us-east-1:111111111111:alarm:checkout-5xx"
	post(urlA, topicA, alarm)
	x.tick()
	if st := x.statuses(); st[1] != "triggered" {
		t.Fatalf("setup: incidents %v", st)
	}

	// Someone who can publish to team B's topic sends an OK naming team A's alarm.
	ok := devstub.CloudWatchAlarm("checkout-5xx", "OK", "prod-east", "checkout-api")
	ok["AlarmArn"] = alarm["AlarmArn"]
	ok["AWSAccountId"] = "222222222222"
	// A far-future state time also makes every later genuine state change
	// for this alarm look stale.
	ok["StateChangeTime"] = "2099-01-01T00:00:00.000+0000"
	post(urlB, topicB, ok)
	x.tick()
	if st := x.statuses(); st[1] == "resolved" {
		t.Errorf("team B's integration resolved team A's incident (and its PagerDuty page): incidents %v, pd %v", st, x.pd)
	}

	// Team A's alarm fires again for real: it must open (or keep) an incident.
	again := devstub.CloudWatchAlarm("checkout-5xx", "ALARM", "prod-east", "checkout-api")
	again["AlarmArn"] = alarm["AlarmArn"]
	post(urlA, topicA, again)
	x.tick()
	open := 0
	for _, s := range x.statuses() {
		if s != "resolved" {
			open++
		}
	}
	if open == 0 {
		t.Fatalf("team A's genuine ALARM after the forged OK was ignored as stale: incidents %v (the alarm is silenced until 2099)", x.statuses())
	}
}
