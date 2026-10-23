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

var snsTopicArnRe = regexp.MustCompile(`^arn:aws(-cn|-us-gov)?:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]{1,256}(\.fifo)?$`)

// snsHostRe matches SNS's regional endpoints only. The label after "sns."
// must be a region: "[a-z0-9-]+" also matched S3 virtual-hosted buckets
// (sns.s3.amazonaws.com is the bucket named "sns"), whose owner could have
// served a signing certificate for forged notifications.
var snsHostRe = regexp.MustCompile(`^sns\.[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d+\.amazonaws\.com(\.cn)?$`)

// allowedSNSURL reports whether u is an SNS-owned URL (or an explicitly
// configured development prefix).
func (s *Server) allowedSNSURL(raw string) bool {
	for _, p := range s.Cfg.SNSCertURLPrefixes {
		if p != "" && strings.HasPrefix(raw, p) {
			return true
		}
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Port() == "" && u.User == nil && snsHostRe.MatchString(u.Hostname())
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
	if !s.allowedSNSURL(m.SigningCertURL) || !s.snsCertPath(m.SigningCertURL) {
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
	for {
		s.snsCertMu.Lock()
		if der, ok := s.snsCerts[u]; ok {
			s.snsCertMu.Unlock()
			return x509.ParseCertificate(der)
		}
		// One fetch per URL at a time: a burst of real deliveries after a
		// restart waits for the first fetch instead of each making its own.
		if wait, ok := s.snsInflight[u]; ok {
			s.snsCertMu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, errSNSCertUnavailable{ctx.Err()}
			}
		}
		if s.snsInflight == nil {
			s.snsInflight = map[string]chan struct{}{}
		}
		done := make(chan struct{})
		s.snsInflight[u] = done
		s.snsCertMu.Unlock()

		der, err := s.fetchSNSCert(ctx, u)
		s.snsCertMu.Lock()
		delete(s.snsInflight, u)
		if err == nil {
			if len(s.snsCerts) >= maxCachedSNSCerts {
				s.snsCerts = map[string][]byte{} // AWS uses a handful; just stop growth
			}
			s.snsCerts[u] = der
		}
		s.snsCertMu.Unlock()
		close(done)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	}
}

func (s *Server) fetchSNSCert(ctx context.Context, u string) ([]byte, error) {
	// Anyone who knows an integration's URL can make this fetch happen (the
	// signature can only be checked after it), so only a few distinct URLs
	// are fetched at once; the rest are answered 503, which SNS retries. AWS
	// signs with a handful of certificates, so real deliveries hit the cache.
	if s.snsFetch != nil {
		select {
		case s.snsFetch <- struct{}{}:
			defer func() { <-s.snsFetch }()
		default:
			return nil, errSNSCertUnavailable{errors.New("fetch SNS certificate: too many fetches in progress")}
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := s.Cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, errSNSCertUnavailable{fmt.Errorf("fetch SNS certificate: %w", err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errSNSCertUnavailable{fmt.Errorf("fetch SNS certificate: status %d", resp.StatusCode)}
	}
	b, _ := pem.Decode(body)
	if b == nil {
		return nil, errors.New("SNS certificate is not PEM")
	}
	return b.Bytes, nil
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

// errSNSCertUnavailable means the signing certificate couldn't be fetched,
// which says nothing about the message. Ingest answers 503 so SNS retries;
// SNS treats any other 4xx as permanent and drops the alarm.
type errSNSCertUnavailable struct{ error }

func (e errSNSCertUnavailable) Unwrap() error { return e.error }

const maxCachedSNSCerts = 64

// snsCertPathRe is the shape of every SNS signing-certificate URL path.
var snsCertPathRe = regexp.MustCompile(`^/SimpleNotificationService-[0-9a-f]{16,64}\.pem$`)

// snsCertPath checks the certificate URL has nothing beyond SNS's fixed
// shape: no query, fragment or credentials (which would otherwise make each
// variant a separate cache entry and fetch).
func (s *Server) snsCertPath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return false
	}
	for _, p := range s.Cfg.SNSCertURLPrefixes {
		if p != "" && strings.HasPrefix(raw, p) {
			return strings.HasSuffix(u.Path, ".pem") // local development stand-ins
		}
	}
	return snsCertPathRe.MatchString(u.Path)
}
