package controlplane

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SNS SignatureVersion 1 is SHA1withRSA
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// snsMessage is an Amazon SNS HTTP(S) delivery.
type snsMessage struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	Token            string `json:"Token"`
	TopicArn         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
	SubscribeURL     string `json:"SubscribeURL"`
}

var snsHostRe = regexp.MustCompile(`^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

// allowedSNSURL reports whether u is an SNS-owned URL (or an explicitly
// configured development prefix).
func (s *Server) allowedSNSURL(raw string) bool {
	for _, p := range s.Cfg.SNSCertURLPrefixes {
		if p != "" && strings.HasPrefix(raw, p) {
			return true
		}
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && snsHostRe.MatchString(u.Hostname())
}

// stringToSign builds the canonical SNS signing string.
func (m snsMessage) stringToSign() (string, error) {
	var fields [][2]string
	switch m.Type {
	case "Notification":
		fields = append(fields, [2]string{"Message", m.Message}, [2]string{"MessageId", m.MessageID})
		if m.Subject != "" {
			fields = append(fields, [2]string{"Subject", m.Subject})
		}
		fields = append(fields, [2]string{"Timestamp", m.Timestamp}, [2]string{"TopicArn", m.TopicArn}, [2]string{"Type", m.Type})
	case "SubscriptionConfirmation", "UnsubscribeConfirmation":
		fields = append(fields,
			[2]string{"Message", m.Message}, [2]string{"MessageId", m.MessageID},
			[2]string{"SubscribeURL", m.SubscribeURL}, [2]string{"Timestamp", m.Timestamp},
			[2]string{"Token", m.Token}, [2]string{"TopicArn", m.TopicArn}, [2]string{"Type", m.Type})
	default:
		return "", fmt.Errorf("unknown SNS message type %q", m.Type)
	}
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(f[0])
		b.WriteByte('\n')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// verifySNS checks the message signature against the SNS signing certificate.
func (s *Server) verifySNS(ctx context.Context, m snsMessage) error {
	if !s.allowedSNSURL(m.SigningCertURL) || !strings.HasSuffix(m.SigningCertURL, ".pem") {
		return fmt.Errorf("signing certificate URL %q is not an SNS URL", m.SigningCertURL)
	}
	cert, err := s.snsCert(ctx, m.SigningCertURL)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("SNS certificate is not RSA")
	}
	sts, err := m.stringToSign()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return errors.New("SNS signature is not base64")
	}
	switch m.SignatureVersion {
	case "1":
		h := sha1.Sum([]byte(sts)) //nolint:gosec
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, h[:], sig)
	case "2":
		h := sha256.Sum256([]byte(sts))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	default:
		return fmt.Errorf("unsupported SNS SignatureVersion %q", m.SignatureVersion)
	}
}

func (s *Server) snsCert(ctx context.Context, u string) (*x509.Certificate, error) {
	s.snsCertMu.Lock()
	der, ok := s.snsCerts[u]
	s.snsCertMu.Unlock()
	if !ok {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := s.Cfg.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch SNS certificate: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil || resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch SNS certificate: status %d", resp.StatusCode)
		}
		b, _ := pem.Decode(body)
		if b == nil {
			return nil, errors.New("SNS certificate is not PEM")
		}
		der = b.Bytes
		s.snsCertMu.Lock()
		s.snsCerts[u] = der
		s.snsCertMu.Unlock()
	}
	return x509.ParseCertificate(der)
}

// confirmSNSSubscription visits SubscribeURL after the confirmation message
// has been verified.
func (s *Server) confirmSNSSubscription(ctx context.Context, m snsMessage) error {
	if !s.allowedSNSURL(m.SubscribeURL) {
		return fmt.Errorf("SubscribeURL %q is not an SNS URL", m.SubscribeURL)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.SubscribeURL, nil)
	resp, err := s.Cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SubscribeURL returned %d", resp.StatusCode)
	}
	return nil
}

func parseSNS(body []byte) (snsMessage, error) {
	var m snsMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("not an SNS message: %w", err)
	}
	if m.Type == "" || m.Signature == "" {
		return m, errors.New("not an SNS message: missing Type or Signature")
	}
	return m, nil
}
