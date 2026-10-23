package awscall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var testCreds = aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", SessionToken: "token"}

// seen is one request as the fake AWS endpoint received it.
type seen struct {
	header http.Header
	body   []byte
	method string
	host   string
	uri    string
}

// fakeAWS answers every request with status/body (and headers), recording it.
type fakeAWS struct {
	mu      sync.Mutex
	reqs    []seen
	status  int
	body    string
	headers map[string]string
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, seen{r.Header.Clone(), b, r.Method, r.Host, r.URL.RequestURI()})
	status, body, headers := f.status, f.body, f.headers
	f.mu.Unlock()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func (f *fakeAWS) last(t *testing.T) seen {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		t.Fatal("no request reached the endpoint")
	}
	return f.reqs[len(f.reqs)-1]
}

func newTestClient(t *testing.T, f *fakeAWS) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", srv.URL+"/")
	return &Client{
		cfg: aws.Config{Region: "eu-west-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return testCreds, nil
		})},
		http: srv.Client(), signer: v4.NewSigner(),
	}
}

// signatureFor recomputes the SigV4 Authorization header for a received
// request as if its body were body.
func signatureFor(t *testing.T, s seen, body []byte, service, region string) string {
	t.Helper()
	when, err := time.Parse("20060102T150405Z", s.header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatalf("X-Amz-Date: %v", err)
	}
	req, _ := http.NewRequest(s.method, "http://"+s.host+s.uri, bytes.NewReader(body))
	for _, h := range []string{"Content-Type", "X-Amz-Target", "X-Amz-Security-Token"} {
		if v := s.header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	for k, v := range s.header {
		if strings.HasPrefix(strings.ToLower(k), "x-nightfix-") {
			req.Header[k] = v
		}
	}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(context.Background(), testCreds, req, hex.EncodeToString(sum[:]), service, region, when); err != nil {
		t.Fatal(err)
	}
	return req.Header.Get("Authorization")
}

func TestCallSendsSignedJSON(t *testing.T) {
	f := &fakeAWS{body: `{"services":[{"serviceName":"api","runningCount":2}]}`}
	c := newTestClient(t, f)
	out, err := c.Call(context.Background(), "ecs", "DescribeServices", map[string]any{"cluster": "prod", "services": []any{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	svc := out["services"].([]any)[0].(map[string]any)
	if svc["runningCount"] != 2.0 {
		t.Fatalf("response: %v", out)
	}
	r := f.last(t)
	if r.method != http.MethodPost || r.header.Get("Content-Type") != "application/x-amz-json-1.1" ||
		r.header.Get("X-Amz-Target") != "AmazonEC2ContainerServiceV20141113.DescribeServices" {
		t.Fatalf("headers: %v %v", r.method, r.header)
	}
	if string(r.body) != `{"cluster":"prod","services":["api"]}` {
		t.Fatalf("body %s", r.body)
	}
	auth := r.header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/eu-west-1/ecs/aws4_request") {
		t.Fatalf("Authorization %q", auth)
	}
	// The action and content type are signed, not just sent.
	for _, h := range []string{"content-type", "host", "x-amz-date", "x-amz-target", "x-amz-security-token"} {
		if !strings.Contains(auth, h) {
			t.Errorf("%s is not a signed header: %s", h, auth)
		}
	}
	// The signature covers the body: it verifies for the body sent, and not
	// for any other.
	if got := signatureFor(t, r, r.body, "ecs", "eu-west-1"); got != auth {
		t.Fatalf("signature doesn't verify:\n got  %s\n want %s", got, auth)
	}
	for _, other := range []string{`{"cluster":"prod","services":["api"]} `, `{"cluster":"evil","services":["api"]}`, ``} {
		if signatureFor(t, r, []byte(other), "ecs", "eu-west-1") == auth {
			t.Fatalf("signature also verifies for body %q", other)
		}
	}
}

func TestCallProtocolPerService(t *testing.T) {
	f := &fakeAWS{body: `{}`}
	c := newTestClient(t, f)
	for svc, want := range map[string][2]string{
		"dynamodb":       {"application/x-amz-json-1.0", "DynamoDB_20120810.GetItem"},
		"ssm":            {"application/x-amz-json-1.1", "AmazonSSM.GetItem"},
		"kms":            {"application/x-amz-json-1.1", "TrentService.GetItem"},
		"secretsmanager": {"application/x-amz-json-1.1", "secretsmanager.GetItem"},
		"logs":           {"application/x-amz-json-1.1", "Logs_20140328.GetItem"},
	} {
		if _, err := c.Call(context.Background(), svc, "GetItem", nil); err != nil {
			t.Fatalf("%s: %v", svc, err)
		}
		r := f.last(t)
		if r.header.Get("Content-Type") != want[0] || r.header.Get("X-Amz-Target") != want[1] {
			t.Errorf("%s: %s / %s", svc, r.header.Get("Content-Type"), r.header.Get("X-Amz-Target"))
		}
		if string(r.body) != "{}" {
			t.Errorf("%s: nil input sent as %q", svc, r.body)
		}
		if !strings.Contains(r.header.Get("Authorization"), "/eu-west-1/"+svc+"/aws4_request") {
			t.Errorf("%s: signed for the wrong service: %s", svc, r.header.Get("Authorization"))
		}
	}
	if _, err := c.Call(context.Background(), "rds", "DescribeDBClusters", nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported service: %v", err)
	}
	if _, err := c.Call(context.Background(), "ecs", "X", map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("unencodable input accepted")
	}
}

func TestCallErrors(t *testing.T) {
	for _, c := range []struct {
		name    string
		status  int
		body    string
		headers map[string]string
		code    string
		msg     string
	}{
		{"json error", 400, `{"__type":"com.amazonaws.ecs#ClusterNotFoundException","message":"Cluster not found."}`, nil,
			"ClusterNotFoundException", "Cluster not found."},
		{"capital Message", 400, `{"__type":"ThrottlingException","Message":"Rate exceeded"}`, nil, "ThrottlingException", "Rate exceeded"},
		{"dynamodb throttling", 400, `{"__type":"com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException","message":"slow down"}`, nil,
			"ProvisionedThroughputExceededException", "slow down"},
		{"code with uri suffix", 400, `{"__type":"ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/","message":"Rate exceeded"}`, nil,
			"ThrottlingException", "Rate exceeded"},
		{"code only in header", 429, `{"message":"Too Many Requests"}`, map[string]string{"X-Amzn-ErrorType": "TooManyRequestsException:http://internal.amazon.com/"},
			"TooManyRequestsException", "Too Many Requests"},
		{"access denied", 400, `{"__type":"AccessDeniedException","Message":"User: arn:aws:sts::1:assumed-role/x is not authorized"}`, nil,
			"AccessDeniedException", "is not authorized"},
		{"server error", 500, `{"__type":"ServerException","message":"oops"}`, nil, "ServerException", "oops"},
		{"html from a proxy", 502, "<html><body>Bad Gateway</body></html>\n", nil, "Bad Gateway", "<html><body>Bad Gateway</body></html>"},
		{"empty body", 503, "", nil, "Service Unavailable", ""},
		{"plain text", 413, "request entity too large", nil, "Request Entity Too Large", "request entity too large"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAWS{status: c.status, body: c.body, headers: c.headers}
			cl := newTestClient(t, f)
			out, err := cl.Call(context.Background(), "ecs", "DescribeClusters", nil)
			var ae *Error
			if !errors.As(err, &ae) {
				t.Fatalf("got %v, %v; want an *Error", out, err)
			}
			if ae.Code != c.code || !strings.Contains(ae.Message, c.msg) || ae.Status != c.status || ae.Service != "ecs" || ae.Action != "DescribeClusters" {
				t.Fatalf("got %+v; want code %q, message containing %q, status %d", *ae, c.code, c.msg, c.status)
			}
			if s := ae.Error(); !strings.HasPrefix(s, "ecs:DescribeClusters failed: "+c.code+": ") || !strings.HasSuffix(s, "(HTTP "+strconv.Itoa(c.status)+")") {
				t.Fatalf("Error() = %q", s)
			}
		})
	}
	// A huge non-AWS error body is cut, not copied into the step error.
	f := &fakeAWS{status: 502, body: strings.Repeat("é", 10000)}
	_, err := newTestClient(t, f).Call(context.Background(), "ecs", "X", nil)
	var ae *Error
	if !errors.As(err, &ae) || len(ae.Message) > maxErrorBody+8 || !strings.HasSuffix(ae.Message, "…") || strings.ContainsRune(ae.Message, '�') {
		t.Fatalf("got %v", err)
	}
}

func TestCallResponses(t *testing.T) {
	for _, c := range []struct {
		body    string
		want    int // keys
		wantErr string
	}{
		{`{"a":1,"b":{"c":[1,2]}}`, 2, ""},
		{"", 0, ""},
		{"  \n", 0, ""},
		{`{}`, 0, ""},
		{`not json`, 0, "invalid JSON response"},
		{`[1,2]`, 0, "invalid JSON response"},
		{`{"a":`, 0, "invalid JSON response"},
	} {
		out, err := newTestClient(t, &fakeAWS{body: c.body}).Call(context.Background(), "ecs", "X", nil)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("body %q: got %v, %v", c.body, out, err)
			}
			continue
		}
		if err != nil || out == nil || len(out) != c.want {
			t.Errorf("body %q: got %v, %v", c.body, out, err)
		}
	}
}

func TestCallTransportAndCredentialFailures(t *testing.T) {
	f := &fakeAWS{body: "{}"}
	c := newTestClient(t, f)
	c.cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("no IMDS")
	})
	if _, err := c.Call(context.Background(), "ecs", "X", nil); err == nil || !strings.Contains(err.Error(), "AWS credentials") {
		t.Fatalf("credentials failure: %v", err)
	}
	if len(f.reqs) != 0 {
		t.Fatal("an unsigned request was sent")
	}

	c = newTestClient(t, f)
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", "http://127.0.0.1:1/")
	if _, err := c.Call(context.Background(), "ecs", "DescribeServices", nil); err == nil || !strings.HasPrefix(err.Error(), "ecs:DescribeServices: ") {
		t.Fatalf("connection failure: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Call(ctx, "ecs", "X", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestEndpoint(t *testing.T) {
	c := &Client{cfg: aws.Config{Region: "ap-south-1"}}
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", "")
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL_ECS", "")
	if got := c.endpoint("ecs"); got != "https://ecs.ap-south-1.amazonaws.com/" {
		t.Fatalf("default endpoint %q", got)
	}
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL", "http://localstack:4566/")
	if got := c.endpoint("ssm"); got != "http://localstack:4566/" {
		t.Fatalf("global override %q", got)
	}
	t.Setenv("NIGHTFIX_AWS_ENDPOINT_URL_ECS", "http://ecs-mock/")
	if got, other := c.endpoint("ecs"), c.endpoint("ssm"); got != "http://ecs-mock/" || other != "http://localstack:4566/" {
		t.Fatalf("per-service override %q / %q", got, other)
	}
	if c.Region() != "ap-south-1" {
		t.Fatal(c.Region())
	}
	t.Setenv("NIGHTFIX_STS_ENDPOINT_URL", "")
	if got := c.STSEndpoint(); got != "https://sts.ap-south-1.amazonaws.com/" {
		t.Fatalf("sts endpoint %q", got)
	}
}

// The enrollment proof: the org and nonce headers are signed, as is the body.
func TestSignGetCallerIdentity(t *testing.T) {
	f := &fakeAWS{}
	c := newTestClient(t, f)
	t.Setenv("NIGHTFIX_STS_ENDPOINT_URL", "http://sts.example.test/")
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	h, err := c.SignGetCallerIdentity(context.Background(), body, map[string]string{"X-Nightfix-Org": "org_1", "X-Nightfix-Nonce": "n1"})
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header(h)
	auth := hdr.Get("Authorization")
	for _, s := range []string{"/eu-west-1/sts/aws4_request", "x-nightfix-nonce", "x-nightfix-org", "content-type", "host"} {
		if !strings.Contains(auth, s) {
			t.Errorf("Authorization %q lacks %s", auth, s)
		}
	}
	s := seen{header: hdr, method: http.MethodPost, host: "sts.example.test", uri: "/"}
	if signatureFor(t, s, []byte(body), "sts", "eu-west-1") != auth {
		t.Fatal("signature doesn't verify for the body")
	}
	if signatureFor(t, s, []byte(body+"&x=1"), "sts", "eu-west-1") == auth {
		t.Fatal("signature verifies for a different body")
	}
	s.header = hdr.Clone()
	s.header.Set("X-Nightfix-Nonce", "n2")
	if signatureFor(t, s, []byte(body), "sts", "eu-west-1") == auth {
		t.Fatal("signature verifies for a different nonce")
	}
}

// JSON-protocol services report throttling as HTTP 400: the code decides.
func TestErrorRetryable(t *testing.T) {
	for _, c := range []struct {
		e    Error
		want bool
	}{
		{Error{Code: "ThrottlingException", Status: 400}, true},
		{Error{Code: "TooManyRequestsException", Status: 400}, true},
		{Error{Code: "InternalFailure", Status: 500}, true},
		{Error{Status: 503}, true},
		{Error{Status: 429}, true},
		{Error{Code: "AccessDeniedException", Status: 400}, false},
		{Error{Code: "ClusterNotFoundException", Status: 400}, false},
		{Error{Code: "ValidationException", Status: 400}, false},
	} {
		if got := c.e.Retryable(); got != c.want {
			t.Errorf("%s (HTTP %d): Retryable() = %v, want %v", c.e.Code, c.e.Status, got, c.want)
		}
	}
}
