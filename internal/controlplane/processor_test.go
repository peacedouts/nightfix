package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/lib/pq"
)

func TestIsTransient(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{context.Canceled, true},
		{fmt.Errorf("wrapped: %w", driver.ErrBadConn), true},
		{&pq.Error{Code: "40P01"}, true},         // deadlock
		{&pq.Error{Code: "08006"}, true},         // connection failure
		{&pq.Error{Code: "23505"}, false},        // unique violation
		{&pq.Error{Code: "22021"}, false},        // invalid byte sequence
		{errors.New("some bug"), false},          // retrying won't help
		{processError{errors.New("bad")}, false}, // malformed payload
	}
	for _, c := range cases {
		if got := isTransient(c.err); got != c.want {
			t.Errorf("isTransient(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestSanitizeAlert(t *testing.T) {
	a := sanitizeAlert(Alert{
		Summary: "a\x00b\xffc",
		Labels:  map[string]string{"k\x00": "v\x00"},
	})
	if a.Summary != "ab�c" || a.Labels["k"] != "v" {
		t.Fatalf("got %q %v", a.Summary, a.Labels)
	}
	s := truncate(strings.Repeat("a", 299)+"é", 300)
	if !utf8.ValidString(s) || len(s) != 299 {
		t.Fatalf("truncate split a rune: %q", s)
	}
}

// Alert summaries, run errors and comments are untrusted; Slack must not
// treat them as mentions or links.
func TestSlackMessagesEscapeUntrustedText(t *testing.T) {
	evil := "disk full <!channel> <https://evil.example/login|Open runbook> <@U012ADMIN> & more"
	check := func(name, s string) {
		t.Helper()
		for _, bad := range []string{"<!channel>", "<https://evil", "<@U012ADMIN>"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: %q passed through unescaped: %s", name, bad, s)
			}
		}
		if !strings.Contains(s, "&lt;!channel&gt;") || !strings.Contains(s, "&amp; more") {
			t.Errorf("%s: not escaped as Slack expects: %s", name, s)
		}
	}
	page := slackText("page", map[string]any{"incident_number": 7, "title": evil, "service": "checkout-api", "severity": "warning", "reason": "x"})
	check("page", page)
	if !strings.Contains(page, "<!here>") {
		t.Error("the page's own <!here> was escaped")
	}
	check("update", slackText("update", map[string]any{"incident_number": 7, "service": "svc", "reason": "Run failed: " + evil}))
	check("no incident", slackText("update", map[string]any{"reason": evil}))
	msg := slackApprovalMessage(map[string]any{"incident_number": 7, "service": "svc", "reason": evil,
		"approval": map[string]any{"interactive": true, "gate": "apr_x", "runbook": "rb", "step_name": evil}})
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // see the text exactly as Slack will
	enc.Encode(msg)
	check("approval", buf.String())
}

func TestSNSCertURLShape(t *testing.T) {
	s := &Server{}
	good := "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0123456789abcdef0123456789abcdef.pem"
	if !s.snsCertPath(good) {
		t.Fatal("real SNS cert URL refused")
	}
	for _, bad := range []string{good + "?x=1.pem", good + "#a", "https://u:p@sns.us-east-1.amazonaws.com/SimpleNotificationService-0123456789abcdef.pem",
		"https://sns.us-east-1.amazonaws.com/other.pem", "https://sns.us-east-1.amazonaws.com/a/SimpleNotificationService-0123456789abcdef.pem"} {
		if s.snsCertPath(bad) {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The certificate and subscription URLs must be SNS's own: no other port,
// no credentials, and the client doesn't follow redirects off the host.
func TestSNSURLPortAndRedirects(t *testing.T) {
	s := New(nil, nil, nil, Config{}, nil)
	good := "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0123456789abcdef0123456789abcdef.pem"
	if !s.allowedSNSURL(good) {
		t.Fatal("real SNS URL refused")
	}
	for _, bad := range []string{
		"https://sns.us-east-1.amazonaws.com:8443/SimpleNotificationService-0123456789abcdef.pem",
		"https://sns.us-east-1.amazonaws.com:443/SimpleNotificationService-0123456789abcdef.pem",
		"https://u@sns.us-east-1.amazonaws.com/SimpleNotificationService-0123456789abcdef.pem",
	} {
		if s.allowedSNSURL(bad) {
			t.Errorf("accepted %s", bad)
		}
	}
	redirect := httptest.NewServer(http.RedirectHandler("http://169.254.169.254/latest/meta-data/", http.StatusFound))
	defer redirect.Close()
	resp, err := s.Cfg.HTTPClient.Get(redirect.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("followed a redirect: status %d", resp.StatusCode)
	}
}

// A burst of deliveries with a cold cache makes one certificate fetch, not
// one per delivery (which the fetch limit would turn into 503s).
func TestSNSCertFetchedOncePerURL(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}))
	defer srv.Close()
	s := New(nil, nil, nil, Config{}, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.snsCert(context.Background(), srv.URL+"/cert.pem")
			errs <- err
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches for one URL", n)
	}
}
