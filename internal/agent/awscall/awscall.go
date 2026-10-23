// Package awscall makes signed AWS API calls for the agent's `aws` and `wait`
// steps using the AWS JSON protocol, so a runbook's input and output are
// exactly the service's wire format (e.g. result.services[0].runningCount
// for ECS DescribeServices).
//
// Credentials come from the standard AWS chain (ECS task role, IRSA,
// instance profile, environment) — the customer's own IAM role. Query/XML
// protocol services (RDS, ElastiCache, EC2) are not supported yet.
package awscall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

type serviceInfo struct {
	signingName  string
	targetPrefix string
	jsonVersion  string
}

// Services this caller supports.
var Services = map[string]serviceInfo{
	"ecs":            {"ecs", "AmazonEC2ContainerServiceV20141113", "1.1"},
	"secretsmanager": {"secretsmanager", "secretsmanager", "1.1"},
	"ssm":            {"ssm", "AmazonSSM", "1.1"},
	"dynamodb":       {"dynamodb", "DynamoDB_20120810", "1.0"},
	"logs":           {"logs", "Logs_20140328", "1.1"},
	"kms":            {"kms", "TrentService", "1.1"},
}

// Client signs and sends calls.
type Client struct {
	cfg    aws.Config
	http   *http.Client
	signer *v4.Signer
}

// New loads the default AWS configuration (region and credentials).
func New(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 60 * time.Second}, signer: v4.NewSigner()}, nil
}

// endpoint returns the service URL. NIGHTFIX_AWS_ENDPOINT_URL (or a per-service
// NIGHTFIX_AWS_ENDPOINT_URL_ECS etc.) overrides it, for local testing.
func (c *Client) endpoint(service string) string {
	if u := os.Getenv("NIGHTFIX_AWS_ENDPOINT_URL_" + strings.ToUpper(service)); u != "" {
		return u
	}
	if u := os.Getenv("NIGHTFIX_AWS_ENDPOINT_URL"); u != "" {
		return u
	}
	return fmt.Sprintf("https://%s.%s.amazonaws.com/", service, c.cfg.Region)
}

// maxErrorBody bounds how much of a non-AWS error body an Error keeps.
const maxErrorBody = 256

// Error is an AWS API error.
type Error struct {
	Service, Action, Code, Message string
	Status                         int
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s:%s failed: %s: %s (HTTP %d)", e.Service, e.Action, e.Code, e.Message, e.Status)
}

// Retryable reports whether the same call might succeed later: server
// errors, timeouts and throttling. JSON-protocol services report throttling
// as HTTP 400 with a throttling code, so the code matters, not just the
// status. Anything else (access denied, validation, not found) won't change
// by retrying.
func (e *Error) Retryable() bool {
	if e.Status >= 500 || e.Status == 429 || e.Status == 408 {
		return true
	}
	switch e.Code {
	case "Throttling", "ThrottlingException", "ThrottledException", "RequestThrottledException", "RequestThrottled",
		"TooManyRequestsException", "ProvisionedThroughputExceededException", "TransactionInProgressException",
		"RequestLimitExceeded", "BandwidthLimitExceeded", "LimitExceededException", "SlowDown", "PriorRequestNotComplete",
		"EC2ThrottledException", "RequestTimeout", "RequestTimeoutException", "InternalFailure", "InternalError",
		"ServiceUnavailable", "ServiceUnavailableException":
		return true
	}
	return false
}

// Throttled reports whether AWS refused the call for rate (so it wasn't
// performed).
func (e *Error) Throttled() bool {
	if e.Status == 429 {
		return true
	}
	switch e.Code {
	case "Throttling", "ThrottlingException", "ThrottledException", "RequestThrottledException", "RequestThrottled",
		"TooManyRequestsException", "RequestLimitExceeded", "SlowDown", "EC2ThrottledException":
		return true
	}
	return false
}

// Call invokes service:action with input and returns the parsed response.
func (c *Client) Call(ctx context.Context, service, action string, input map[string]any) (map[string]any, error) {
	info, ok := Services[service]
	if !ok {
		return nil, fmt.Errorf("aws service %q is not supported", service)
	}
	if input == nil {
		input = map[string]any{}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(service), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-"+info.jsonVersion)
	req.Header.Set("X-Amz-Target", info.targetPrefix+"."+action)
	creds, err := c.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}
	sum := sha256.Sum256(body)
	if err := c.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), info.signingName, c.cfg.Region, time.Now()); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s:%s: %w", service, action, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
			Msg     string `json:"Message"`
		}
		json.Unmarshal(raw, &e)
		// The code is in the body's __type, or only in X-Amzn-ErrorType
		// ("Code:http://…"); either may carry a "namespace#" prefix.
		code := e.Type
		if code == "" {
			code = resp.Header.Get("X-Amzn-ErrorType")
		}
		if i := strings.Index(code, ":"); i >= 0 {
			code = code[:i]
		}
		if i := strings.LastIndex(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		msg := e.Message
		if msg == "" {
			msg = e.Msg
		}
		if code == "" && msg == "" {
			// Not an AWS error document (a proxy or load balancer page):
			// keep the start of the body so the failure says something.
			msg = string(bytes.TrimSpace(raw))
			if len(msg) > maxErrorBody {
				msg = strings.ToValidUTF8(msg[:maxErrorBody], "") + "…"
			}
			code = http.StatusText(resp.StatusCode)
		}
		return nil, &Error{Service: service, Action: action, Code: code, Message: msg, Status: resp.StatusCode}
	}
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("%s:%s: invalid JSON response: %w", service, action, err)
		}
	}
	return out, nil
}

// Region is the configured AWS region.
func (c *Client) Region() string { return c.cfg.Region }

// STSEndpoint is where the control plane will send the signed
// GetCallerIdentity request. NIGHTFIX_STS_ENDPOINT_URL overrides it for local
// testing; the control plane must be configured with the same value.
func (c *Client) STSEndpoint() string {
	if u := os.Getenv("NIGHTFIX_STS_ENDPOINT_URL"); u != "" {
		return u
	}
	return fmt.Sprintf("https://sts.%s.amazonaws.com/", c.cfg.Region)
}

// SignGetCallerIdentity builds and signs, but does not send, an
// sts:GetCallerIdentity request carrying extra headers (the enrollment org
// and nonce), which the signature then covers. Returns the headers to forward.
func (c *Client) SignGetCallerIdentity(ctx context.Context, body string, extra map[string]string) (map[string][]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.STSEndpoint(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	creds, err := c.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}
	sum := sha256.Sum256([]byte(body))
	if err := c.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "sts", c.cfg.Region, time.Now()); err != nil {
		return nil, err
	}
	return map[string][]string(req.Header), nil
}
