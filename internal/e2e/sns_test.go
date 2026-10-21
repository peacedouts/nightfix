package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/devstub"
	"github.com/peacedouts/nightfix/internal/signing"
	"github.com/peacedouts/nightfix/internal/testdb"
)

// A transient failure fetching the SNS signing certificate must be answered
// with a status SNS retries.
const snsTestTopic = "arn:aws:sns:us-east-1:123456789012:nightfix-alarms"

func TestSNSCertFetchFailureIsRetryable(t *testing.T) {
	pool := testdb.New(t)
	mk := make([]byte, 32)
	rand.Read(mk)
	sealer, _ := signing.NewSealer(mk)
	ca, _ := controlplane.LoadOrCreateCA(t.TempDir())
	stub := devstub.New(3 * time.Second)
	var certHits atomic.Int32
	inner := stub.Handler()
	stubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sns/") && certHits.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer stubSrv.Close()
	stub.BaseURL = stubSrv.URL
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := controlplane.New(pool, sealer, ca, controlplane.Config{PublicIngestURL: "http://ingest",
		SNSCertURLPrefixes: []string{stubSrv.URL + "/sns/"}}, log)
	api := httptest.NewServer(srv.APIHandler())
	defer api.Close()
	ing := httptest.NewServer(srv.IngestHandler())
	defer ing.Close()
	org, _ := srv.CreateOrg(context.Background(), "A", "a1")
	x := &ingestHarness{t: t, srv: srv, api: api.URL, key: org.APIKey}
	x.call("POST", "/v1/services", map[string]any{"name": "svc"}, nil)
	var integ map[string]string
	x.call("POST", "/v1/integrations", map[string]any{"type": "cloudwatch", "name": "cw", "default_service": "svc", "topic_arn": snsTestTopic}, &integ)
	url := strings.Replace(integ["ingest_url"], "http://ingest", ing.URL, 1)

	alarm := devstub.CloudWatchAlarm("a", "ALARM", "prod", "svc")
	post := func() (int, string) {
		resp, err := http.Post(url, "text/plain", bytes.NewReader(stub.SNSEnvelope(snsTestTopic, alarm)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(bytes.Buffer)
		b.ReadFrom(resp.Body)
		return resp.StatusCode, strings.TrimSpace(b.String())
	}
	c1, b1 := post()
	c2, _ := post()
	// SNS drops a message on any 4xx except 429, so a certificate-fetch
	// failure must be a 5xx for SNS to retry it.
	if c1 != 503 {
		t.Errorf("cert fetch failure answered %d %q, want 503", c1, b1)
	}
	if c2 != 202 {
		t.Errorf("retry after the cert became available: got %d, want 202", c2)
	}

	// Cross-org and non-cloudwatch PUT /snsTestTopic.
	org2, _ := srv.CreateOrg(context.Background(), "B", "b1")
	y := &ingestHarness{t: t, srv: srv, api: api.URL, key: org2.APIKey}
	if code := y.call("PUT", "/v1/integrations/"+integ["id"]+"/topic", map[string]string{"topic_arn": snsTestTopic}, nil); code != 404 {
		t.Errorf("other org's integration: got %d, want 404", code)
	}
}
