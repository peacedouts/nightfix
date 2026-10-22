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
	http     *http.Client // its Transport is always the current one (currentTransport)
	pool     *x509.CertPool

	mu   sync.Mutex
	leaf *x509.Certificate
	tr   *http.Transport // presents the current certificate
}

func newClient(endpoint string, caPEM []byte) (*client, error) {
	// Without a CA file, trust the system roots (a publicly trusted
	// gateway). An empty pool would trust nothing at all.
	var pool *x509.CertPool
	if len(caPEM) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("could not parse CA certificate")
		}
	}
	c := &client{endpoint: endpoint, pool: pool}
	c.tr = c.newTransport(nil)
	c.http = &http.Client{Timeout: 60 * time.Second, Transport: currentTransport{c}}
	return c, nil
}

// newTransport returns a transport whose connections present cert (none
// when nil: enrollment).
func (c *client) newTransport(cert *tls.Certificate) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    c.pool,
			MinVersion: tls.VersionTLS13,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if cert == nil {
					return &tls.Certificate{}, nil
				}
				return cert, nil
			},
		},
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 8,
		// Connections left on a replaced transport are closed once idle.
		IdleConnTimeout: 90 * time.Second,
	}
}

// currentTransport sends each request with the transport for the current
// certificate.
type currentTransport struct{ c *client }

func (t currentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.c.transport().RoundTrip(r)
}

func (c *client) transport() *http.Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tr
}

// switchCert starts presenting cert. A connection is tied to the certificate
// it was opened with, so this needs a new transport: closing idle
// connections isn't enough, because one busy at the time (a long poll)
// would go back to the pool and carry later requests with the old
// certificate. Once the gateway has seen the renewed certificate it retires
// the old one, and that request would be refused as a revoked identity.
func (c *client) switchCert(cert *tls.Certificate, leaf *x509.Certificate) {
	c.mu.Lock()
	old := c.tr
	c.leaf, c.tr = leaf, c.newTransport(cert)
	c.mu.Unlock()
	old.CloseIdleConnections()
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
	c.switchCert(&kp, leaf)
	return nil
}

// clearCert stops presenting a client certificate. Enrollment needs none,
// and one the gateway rejects at the TLS layer (expired, say) would fail the
// enrollment's handshake as well.
func (c *client) clearCert() { c.switchCert(nil, nil) }

func (c *client) certExpiry() (issued, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaf == nil {
		return time.Time{}, time.Time{}
	}
	return c.leaf.NotBefore, c.leaf.NotAfter
}

// certExpired reports whether the current certificate's NotAfter has passed.
func (c *client) certExpired(now time.Time) bool {
	_, exp := c.certExpiry()
	return !exp.IsZero() && now.After(exp)
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
	// A unique temp file (created 0600) so concurrent saves can't clobber
	// each other's half-written file before the atomic rename.
	f, err := os.CreateTemp(dir, "identity-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "identity.json")); err != nil {
		os.Remove(tmp) // it holds the private key
		return err
	}
	return nil
}

// checkStateDir makes sure the identity can be saved before enrolling.
func checkStateDir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("state dir %s is not writable: %w", dir, err)
	}
	f.Close()
	return os.Remove(f.Name())
}

// expired reports whether the identity's certificate is no longer valid.
func (id *identity) expired(now time.Time) bool {
	block, _ := pem.Decode([]byte(id.CertPEM))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err != nil || now.After(cert.NotAfter)
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
