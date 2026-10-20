package e2e

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agent"
	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/devstub"
)

// gw posts to the agent gateway without a client certificate (enrollment).
func (e *env) gw(path string, in, out any) (int, string) {
	e.t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	b, _ := json.Marshal(in)
	resp, err := c.Post(e.gwURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == 200 {
		json.Unmarshal(body, out)
	}
	return resp.StatusCode, string(body)
}

func (e *env) challenge() string {
	e.t.Helper()
	var ch agentapi.ChallengeResponse
	if code, body := e.gw("/agent/v1/enroll/challenge", agentapi.ChallengeRequest{OrgID: e.orgID}, &ch); code != 200 {
		e.t.Fatalf("challenge: %d %s", code, body)
	}
	return ch.Nonce
}

func (e *env) enrollIAM(signer *awscall.Client, nonce string, headers map[string][]string, body string) (int, string) {
	return e.gw("/agent/v1/enroll", agentapi.EnrollRequest{
		Method: "iam", OrgID: e.orgID, Nonce: nonce, CSRPEM: "unused-until-identity-is-verified", Version: "test",
		IAM: &agentapi.IAMRequest{Region: signer.Region(), Headers: headers, Body: body},
	}, nil)
}

func (e *env) sign(c *awscall.Client, nonce string) map[string][]string {
	e.t.Helper()
	h, err := c.SignGetCallerIdentity(e.ctx, agentapi.STSBody, map[string]string{agentapi.HeaderOrg: e.orgID, agentapi.HeaderNonce: nonce})
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func TestIAMEnrollmentRejectsBadProofs(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))

	// 1. A role with no matching rule is refused, and the denial is audited.
	e.stub.AddIAMIdentity(devstub.IAMIdentity{AccessKey: "AKIDINTRUDER", Secret: "intruder-secret", Account: awsAccount, Role: "some-other-role"})
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDINTRUDER")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "intruder-secret")
	intruder, _ := awscall.New(e.ctx)
	n := e.challenge()
	if code, body := e.enrollIAM(intruder, n, e.sign(intruder, n), agentapi.STSBody); code != 403 || !strings.Contains(body, "some-other-role") {
		t.Fatalf("unmatched role: %d %s", code, body)
	}
	var audit []map[string]any
	e.call("GET", "/v1/audit-events", nil, &audit)
	if !strings.Contains(mustJSON(audit), "agent.enroll_denied") {
		t.Fatal("denied enrollment was not audited")
	}

	// 2. A nonce works once. The legit role is already at max_agents, so the
	// first try is refused for that reason — and the nonce is still burned.
	n = e.challenge()
	h := e.sign(e.aws, n)
	if code, body := e.enrollIAM(e.aws, n, h, agentapi.STSBody); code != 403 || !strings.Contains(body, "at most 1") {
		t.Fatalf("first use: %d %s", code, body)
	}
	if code, body := e.enrollIAM(e.aws, n, h, agentapi.STSBody); code != 401 || !strings.Contains(body, "used or expired") {
		t.Fatalf("replay: %d %s", code, body)
	}

	// 3. The org and nonce must be inside the signature, not just alongside it.
	n = e.challenge()
	unbound, _ := e.aws.SignGetCallerIdentity(e.ctx, agentapi.STSBody, nil)
	unbound[agentapi.HeaderOrg] = []string{e.orgID}
	unbound[agentapi.HeaderNonce] = []string{n}
	if code, body := e.enrollIAM(e.aws, n, unbound, agentapi.STSBody); code != 401 || !strings.Contains(body, "covered by the signature") {
		t.Fatalf("unsigned binding: %d %s", code, body)
	}

	// 4. Only GetCallerIdentity is accepted.
	n = e.challenge()
	if code, body := e.enrollIAM(e.aws, n, e.sign(e.aws, n), "Action=AssumeRole&Version=2011-06-15"); code != 401 || !strings.Contains(body, "GetCallerIdentity") {
		t.Fatalf("other action: %d %s", code, body)
	}

	// 5. A forged signature fails at STS.
	n = e.challenge()
	forged := e.sign(e.aws, n)
	forged["Authorization"] = []string{forged["Authorization"][0][:len(forged["Authorization"][0])-4] + "beef"}
	if code, body := e.enrollIAM(e.aws, n, forged, agentapi.STSBody); code != 401 || !strings.Contains(body, "SignatureDoesNotMatch") {
		t.Fatalf("forged signature: %d %s", code, body)
	}

	// 6. Unknown orgs get no challenge.
	if code, _ := e.gw("/agent/v1/enroll/challenge", agentapi.ChallengeRequest{OrgID: "org_" + strings.Repeat("0", 32)}, nil); code != 403 {
		t.Fatalf("challenge for unknown org: %d", code)
	}
}

func TestTokenEnrollmentStillWorksAsFallback(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	var enr map[string]string
	e.call("POST", "/v1/enrollment-rules", map[string]any{"method": "token", "labels": map[string]string{"env": "staging"}}, &enr)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ag, err := agent.New(agent.Config{Endpoint: e.gwURL, CAPEM: e.caPEM, EnrollMethod: "token", EnrollToken: enr["token"],
		StateDir: t.TempDir(), AWS: e.aws, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	go ag.Run(e.ctx)
	e.waitFor("second agent online", 15*time.Second, func() bool {
		var agents []map[string]any
		e.call("GET", "/v1/agents", nil, &agents)
		online := 0
		for _, a := range agents {
			if a["status"] == "online" {
				online++
			}
		}
		return online == 2
	})
}

// userCall makes an API call with an Auth0 access token and returns the status.
func (e *env) userCall(token, method, path string, body any) (int, string) {
	e.t.Helper()
	var b []byte
	if s, ok := body.(string); ok {
		b = []byte(s)
	} else if body != nil {
		b, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, e.api+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

const paymentsRunbook = `apiVersion: nightfix.dev/v1alpha1
kind: Runbook
metadata:
  name: payments-describe
  title: Describe the payments service
  team: payments
  tags: [payments]
spec:
  target:
    agentSelector:
      env: staging
  triggers:
    - type: manual
  steps:
    - id: describe
      type: aws
      service: ecs
      action: DescribeServices
      input:
        cluster: staging
        services: [payments-api]
`

// The data-model.md example: "Team Payments can run runbooks tagged
// payments, but only Admins can run against env=prod."
func TestScopedRBACThroughAuth0(t *testing.T) {
	e := setup(t, runbookYAML(t, "2m"))
	e.call("PUT", "/v1/org/auth0", map[string]string{"auth0_org_id": "org_acme"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "payments", "auth0_group": "payments-eng"}, nil)
	e.call("POST", "/v1/teams", map[string]string{"slug": "platform-admins", "auth0_group": "platform"}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "payments", "role": "responder",
		"scope": map[string]any{"tags": []string{"payments"}, "env": []string{"staging", "dev"}}}, nil)
	e.call("POST", "/v1/role-bindings", map[string]any{"subject_type": "team", "subject": "platform-admins", "role": "admin"}, nil)
	e.callRaw("PUT", "/v1/runbooks/payments-describe", []byte(paymentsRunbook), nil)

	alice := e.auth0.UserToken("auth0|alice", "alice@acme.dev", "org_acme", "payments-eng")
	bob := e.auth0.UserToken("auth0|bob", "bob@acme.dev", "org_acme", "platform")
	carol := e.auth0.UserToken("auth0|carol", "carol@acme.dev", "org_acme")
	stranger := e.auth0.UserToken("auth0|eve", "eve@evil.dev", "org_unlinked", "platform")

	expect := func(who, tok, method, path string, body any, want int, contains string) {
		t.Helper()
		code, out := e.userCall(tok, method, path, body)
		if code != want || (contains != "" && !strings.Contains(out, contains)) {
			t.Fatalf("%s %s %s: got %d %s, want %d %q", who, method, path, code, out, want, contains)
		}
	}

	// Who am I: alice's team membership came from the IdP groups claim.
	expect("alice", alice, "GET", "/v1/me", nil, 200, `"payments"`)
	// Alice can run the payments runbook in staging…
	expect("alice", alice, "POST", "/v1/runs", map[string]any{"runbook": "payments-describe"}, 200, "run_")
	// …but not the platform runbook against prod.
	expect("alice", alice, "POST", "/v1/runs", map[string]any{"runbook": "ecs-service-restart",
		"params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}}, 403, "targeting prod")
	// She can't take over the platform runbook by republishing it under her scope.
	takeover := strings.NewReplacer("  team: platform\n", "  team: payments\n", "tags: [ecs, restart]", "tags: [payments]",
		"      env: prod\n", "      env: staging\n").Replace(runbookYAML(t, "2m"))
	expect("alice", alice, "PUT", "/v1/runbooks/ecs-service-restart", takeover, 403, "")
	// Nor administer the org.
	expect("alice", alice, "POST", "/v1/services", map[string]string{"name": "x"}, 403, "org-wide admin")

	// Bob (platform admin) can run against prod.
	expect("bob", bob, "POST", "/v1/runs", map[string]any{"runbook": "ecs-service-restart",
		"params": map[string]string{"cluster": "prod-east", "service": "checkout-api"}}, 200, "run_")
	// Admins can't mint admins or owners: that's an owner's call.
	expect("bob", bob, "POST", "/v1/role-bindings", map[string]any{"subject_type": "user", "subject": "alice@acme.dev", "role": "admin"},
		403, "only an owner")

	// Carol has no bindings: she is a viewer (free seat).
	expect("carol", carol, "GET", "/v1/incidents", nil, 200, "")
	expect("carol", carol, "POST", "/v1/runs", map[string]any{"runbook": "payments-describe"}, 403, "")

	// A token from an Auth0 organization that isn't linked gets nothing.
	expect("eve", stranger, "GET", "/v1/me", nil, 401, "not linked")
	// Neither does a token for a different API.
	wrongAud := e.auth0.Mint("RS256", map[string]any{"iss": e.auth0.Issuer, "aud": "https://other.api", "sub": "auth0|alice",
		"org_id": "org_acme", "exp": time.Now().Add(time.Hour).Unix(), "https://nightfix.dev/email": "alice@acme.dev"})
	expect("wrong-aud", wrongAud, "GET", "/v1/me", nil, 401, "audience")

	// Removing alice from the IdP group removes her team membership on next login.
	aliceLeft := e.auth0.UserToken("auth0|alice", "alice@acme.dev", "org_acme")
	expect("alice-after", aliceLeft, "POST", "/v1/runs", map[string]any{"runbook": "payments-describe"}, 403, "")

	// Runs record who started them.
	var audit []map[string]any
	e.call("GET", "/v1/audit-events", nil, &audit)
	if !strings.Contains(mustJSON(audit), "user:usr_") {
		t.Fatal("user actions should be audited under the user's id")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
