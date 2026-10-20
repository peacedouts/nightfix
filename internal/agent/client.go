package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/signing"
)

// identity is what enrollment produced. The private key is generated here and
// never sent anywhere; only a CSR is.
type identity struct {
	AgentID string              `json:"agent_id"`
	OrgID   string              `json:"org_id"`
	Labels  map[string]string   `json:"labels"`
	Trust   signing.TrustConfig `json:"trust_config"`
	CertPEM string              `json:"cert_pem"`
	CAPEM   string              `json:"ca_pem"`
	KeyPEM  string              `json:"key_pem"`
}

// client talks to the agent gateway over mutual TLS.
type client struct {
	endpoint string
	http     *http.Client

	mu   sync.Mutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

func newClient(endpoint string, caPEM []byte) (*client, error) {
	pool := x509.NewCertPool()
	if len(caPEM) > 0 && !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("could not parse CA certificate")
	}
	c := &client{endpoint: endpoint}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.cert == nil {
				return &tls.Certificate{}, nil // enrollment: no client cert yet
			}
			return c.cert, nil
		},
	}
	c.http = &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 8},
	}
	return c, nil
}

func (c *client) setCert(certPEM, keyPEM string) error {
	kp, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cert, c.leaf = &kp, leaf
	c.mu.Unlock()
	// Drop pooled connections so the next request presents the new cert.
	c.http.Transport.(*http.Transport).CloseIdleConnections()
	return nil
}

func (c *client) certExpiry() (issued, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaf == nil {
		return time.Time{}, time.Time{}
	}
	return c.leaf.NotBefore, c.leaf.NotAfter
}

// statusError is a non-2xx response from the gateway.
type statusError struct {
	Code int
	Msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("gateway returned %d: %s", e.Code, e.Msg) }

func (c *client) post(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = string(bytes.TrimSpace(body))
		}
		return &statusError{resp.StatusCode, e.Error}
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// newKeyAndCSR generates an Ed25519 key and a CSR for it.
func newKeyAndCSR() (keyPEM, csrPEM string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nightfix-agent"}}, priv)
	if err != nil {
		return "", "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func loadIdentity(dir string) (*identity, error) {
	if dir == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, err
	}
	var id identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	return &id, nil
}

func saveIdentity(dir string, id *identity) error {
	if dir == "" {
		return nil // no persistent disk (e.g. Fargate): re-enroll on restart
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(id, "", "  ")
	tmp := filepath.Join(dir, "identity.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "identity.json"))
}

func (c *client) enroll(ctx context.Context, token, version string) (*identity, error) {
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return nil, err
	}
	var resp agentapi.EnrollResponse
	if err := c.post(ctx, "/agent/v1/enroll", agentapi.EnrollRequest{Method: "token", Token: token, CSRPEM: csrPEM, Version: version}, &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return &identity{AgentID: resp.AgentID, OrgID: resp.OrgID, Labels: resp.Labels, Trust: resp.TrustConfig,
		CertPEM: resp.CertPEM, CAPEM: resp.CAPEM, KeyPEM: keyPEM}, nil
}

// IAMSigner signs an sts:GetCallerIdentity request without sending it.
type IAMSigner interface {
	Region() string
	SignGetCallerIdentity(ctx context.Context, body string, extra map[string]string) (map[string][]string, error)
}

// enrollIAM proves the agent's AWS identity (agent-protocol.md §3.1): get a
// single-use nonce, sign a GetCallerIdentity request that covers the org and
// the nonce, and let the control plane have STS verify it.
func (c *client) enrollIAM(ctx context.Context, orgID string, signer IAMSigner, version string) (*identity, error) {
	var ch agentapi.ChallengeResponse
	if err := c.post(ctx, "/agent/v1/enroll/challenge", agentapi.ChallengeRequest{OrgID: orgID}, &ch); err != nil {
		return nil, fmt.Errorf("enrollment challenge: %w", err)
	}
	headers, err := signer.SignGetCallerIdentity(ctx, agentapi.STSBody, map[string]string{
		agentapi.HeaderOrg: orgID, agentapi.HeaderNonce: ch.Nonce,
	})
	if err != nil {
		return nil, err
	}
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return nil, err
	}
	var resp agentapi.EnrollResponse
	err = c.post(ctx, "/agent/v1/enroll", agentapi.EnrollRequest{
		Method: "iam", OrgID: orgID, Nonce: ch.Nonce, CSRPEM: csrPEM, Version: version,
		IAM: &agentapi.IAMRequest{Region: signer.Region(), Headers: headers, Body: agentapi.STSBody},
	}, &resp)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return &identity{AgentID: resp.AgentID, OrgID: resp.OrgID, Labels: resp.Labels, Trust: resp.TrustConfig,
		CertPEM: resp.CertPEM, CAPEM: resp.CAPEM, KeyPEM: keyPEM}, nil
}

func (c *client) renew(ctx context.Context) (certPEM, keyPEM string, err error) {
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return "", "", err
	}
	var resp agentapi.RenewResponse
	if err := c.post(ctx, "/agent/v1/renew", agentapi.RenewRequest{CSRPEM: csrPEM}, &resp); err != nil {
		return "", "", err
	}
	return resp.CertPEM, keyPEM, nil
}
