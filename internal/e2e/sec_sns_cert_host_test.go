package e2e_test

// Security review: SNS signing-certificate host pinning.
//
// allowedSNSURL accepts any host matching ^sns\.[a-z0-9-]+\.amazonaws\.com$.
// That shape is not reserved for SNS: S3 serves a bucket named "sns" at
// https://sns.s3.amazonaws.com/ (and sns.s3-<region>.amazonaws.com,
// sns.s3-accelerate.amazonaws.com, ...). Whoever owns that bucket can host a
// PEM at the path SNS uses and sign arbitrary "SNS" notifications that every
// CloudWatch integration then accepts as genuine.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecSNSCertFromS3BucketNamedSNSIsRefused(t *testing.T) {
	// The attacker's key and self-signed certificate.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Stands in for the internet: the only host it answers for is the S3
	// virtual-hosted bucket "sns" (owned by the attacker in this scenario).
	var fetched []string
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		fetched = append(fetched, r.URL.String())
		if r.URL.Host == "sns.s3.amazonaws.com" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(certPEM)), Header: http.Header{}}, nil
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}

	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{PublicIngestURL: "http://ingest", HTTPClient: client}, log)
	api := httptest.NewServer(srv.APIHandler())
	defer api.Close()
	ing := httptest.NewServer(srv.IngestHandler())
	defer ing.Close()
	org, err := srv.CreateOrg(context.Background(), "Victim", "victim")
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body any, out any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", api.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+org.APIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", path, err, resp)
		}
		defer resp.Body.Close()
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
	}
	call("/v1/services", map[string]any{"name": "checkout-api"}, nil)
	var integ map[string]string
	call("/v1/integrations", map[string]any{"type": "cloudwatch", "name": "prod", "default_service": "checkout-api",
		"topic_arn": snsTestTopic}, &integ)
	url := strings.Replace(integ["ingest_url"], "http://ingest", ing.URL, 1)

	// A forged ALARM (it could as well be an OK that silently resolves a real incident).
	msg, _ := json.Marshal(devstub.CloudWatchAlarm("forged", "ALARM", "prod-east", "checkout-api"))
	m := map[string]string{
		"Type": "Notification", "MessageId": "forged-1", "TopicArn": snsTestTopic, "Message": string(msg),
		"Timestamp": time.Now().UTC().Format(time.RFC3339Nano), "SignatureVersion": "2",
		"SigningCertURL": "https://sns.s3.amazonaws.com/SimpleNotificationService-0123456789abcdef0123456789abcdef.pem",
	}
	sts := "Message\n" + m["Message"] + "\nMessageId\n" + m["MessageId"] + "\nTimestamp\n" + m["Timestamp"] +
		"\nTopicArn\n" + m["TopicArn"] + "\nType\n" + m["Type"] + "\n"
	h := sha256.Sum256([]byte(sts))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	m["Signature"] = base64.StdEncoding.EncodeToString(sig)
	body, _ := json.Marshal(m)

	resp, err := http.Post(url, "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Fatalf("a notification signed with a certificate from the S3 bucket \"sns\" was accepted as SNS: %d %s (fetched %v)",
			resp.StatusCode, strings.TrimSpace(string(out)), fetched)
	}
}
