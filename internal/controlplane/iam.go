package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/ids"
)

// IAM enrollment (agent-protocol.md §3.1, decision #21). The agent proves its
// AWS identity with a SigV4-signed sts:GetCallerIdentity request it builds but
// doesn't send — the same pattern as Vault's AWS IAM auth method. There is no
// long-lived secret to leak, and nothing needs persistent disk.

const challengeTTL = 5 * time.Minute

var regionRe = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d$`)

// Challenge issues a single-use nonce for an org.
func (s *Server) Challenge(ctx context.Context, req agentapi.ChallengeRequest) (*agentapi.ChallengeResponse, error) {
	orgID, err := ids.Decode("org", req.OrgID)
	if err != nil {
		return nil, httpError{400, "org_id must look like org_…"}
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	var ok bool
	if err := s.DB.QueryRowContext(ctx, `SELECT nfx_create_enroll_challenge($1, $2, $3::interval)`,
		orgID, hashSecret(nonce), pgInterval(challengeTTL)).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		// Same answer for unknown and frozen orgs.
		return nil, httpError{403, "enrollment is not available for this org"}
	}
	return &agentapi.ChallengeResponse{Nonce: nonce, ExpiresAt: time.Now().Add(challengeTTL).UTC().Format(time.RFC3339)}, nil
}

// stsEndpoint returns the STS URL for a region. The URL is always built
// here, never taken from the agent, so enrollment can't be used to make the
// control plane fetch arbitrary URLs.
func (s *Server) stsEndpoint(region string) (string, error) {
	if !regionRe.MatchString(region) {
		return "", fmt.Errorf("invalid AWS region %q", region)
	}
	if s.Cfg.STSEndpoint != "" {
		return s.Cfg.STSEndpoint, nil // local development only
	}
	return fmt.Sprintf("https://sts.%s.amazonaws.com/", region), nil
}

// callerIdentity is what STS says about the signer.
type callerIdentity struct {
	Arn, Account, UserID string
	RoleName             string // from the assumed-role ARN
}

type stsResponse struct {
	Result struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

type stsError struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// forwarded headers: everything SigV4 needs, nothing else.
var stsForwardHeaders = []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token", "Content-Type",
	agentapi.HeaderOrg, agentapi.HeaderNonce}

// verifyIAM checks the request is bound to this org and nonce, has STS verify
// the signature, and returns the caller's identity.
func (s *Server) verifyIAM(ctx context.Context, orgAPIID, nonce string, r *agentapi.IAMRequest) (*callerIdentity, error) {
	if r == nil {
		return nil, errors.New("iam enrollment needs a signed STS request")
	}
	if r.Body != agentapi.STSBody {
		return nil, errors.New("the signed request must be sts:GetCallerIdentity")
	}
	h := http.Header{}
	for k, vs := range r.Headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	if h.Get(agentapi.HeaderOrg) != orgAPIID || h.Get(agentapi.HeaderNonce) != nonce {
		return nil, errors.New("the signed request is not bound to this org and challenge")
	}
	auth := h.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return nil, errors.New("the request is not SigV4-signed")
	}
	signed := ""
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "SignedHeaders="); ok {
			signed = ";" + v + ";"
		}
	}
	for _, need := range []string{"host", "x-nightfix-org", "x-nightfix-nonce"} {
		if !strings.Contains(signed, ";"+need+";") {
			return nil, fmt.Errorf("header %s must be covered by the signature", need)
		}
	}

	endpoint, err := s.stsEndpoint(r.Region)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	req.Host = u.Host
	for _, k := range stsForwardHeaders {
		if v := h.Values(k); len(v) > 0 {
			req.Header[http.CanonicalHeaderKey(k)] = v
		}
	}
	resp, err := s.Cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call STS: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e stsError
		xml.Unmarshal(body, &e)
		return nil, fmt.Errorf("STS rejected the signed request: %s %s", e.Error.Code, e.Error.Message)
	}
	var out stsResponse
	if err := xml.Unmarshal(body, &out); err != nil || out.Result.Arn == "" {
		return nil, errors.New("unexpected STS response")
	}
	id := &callerIdentity{Arn: out.Result.Arn, Account: out.Result.Account, UserID: out.Result.UserID}
	// arn:aws:sts::123456789012:assumed-role/nightfix-agent/<session>
	parts := strings.SplitN(out.Result.Arn, ":", 6)
	if len(parts) != 6 || parts[2] != "sts" || !strings.HasPrefix(parts[5], "assumed-role/") {
		return nil, fmt.Errorf("agents must enroll with an IAM role (got %s)", out.Result.Arn)
	}
	segs := strings.Split(parts[5], "/")
	if len(segs) < 3 {
		return nil, fmt.Errorf("unexpected assumed-role ARN %s", out.Result.Arn)
	}
	id.RoleName = segs[1]
	return id, nil
}

// roleNameFromARN accepts arn:aws:iam::<acct>:role/[path/]<name> or a bare
// role name, and returns the account (if present) and the name. Assumed-role
// ARNs from STS don't carry the role's path, so rules match on account + name.
func roleNameFromARN(s string) (account, name string, err error) {
	if !strings.HasPrefix(s, "arn:") {
		if s == "" || strings.ContainsAny(s, "/: ") {
			return "", "", fmt.Errorf("invalid role name %q", s)
		}
		return "", s, nil
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return "", "", fmt.Errorf("role_arn must be arn:aws:iam::<account>:role/<name>")
	}
	segs := strings.Split(parts[5], "/")
	return parts[4], segs[len(segs)-1], nil
}
