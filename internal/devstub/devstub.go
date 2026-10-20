// Package devstub simulates the outside world for local demos and tests:
//
//   - a fake ECS + Secrets Manager speaking the AWS JSON protocol (requests
//     must carry a SigV4 Authorization header, as the real ones do)
//   - an SNS "publisher" that wraps a CloudWatch alarm in a signed SNS
//     notification and delivers it to an ingest URL, plus the signing cert
//   - Slack and PagerDuty sinks that record what they receive
//
// None of this is used in production.
package devstub

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Stub is the simulated world.
type Stub struct {
	BaseURL string // set by the caller once listening, e.g. http://127.0.0.1:9100

	mu       sync.Mutex
	services map[string]*ecsService
	Calls    []string // "ecs:DescribeServices", …
	Slack    []string
	PD       []map[string]any
	healIn   time.Duration
	heal     bool

	snsKey  *rsa.PrivateKey
	snsCert []byte
}

type ecsService struct {
	Cluster, Name   string
	Desired         int
	Running         int
	Deployments     int
	RolloutFinishAt time.Time
}

// New builds a stub whose ECS services heal healIn after a forced deployment.
func New(healIn time.Duration) *Stub {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "devstub SNS signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return &Stub{services: map[string]*ecsService{}, healIn: healIn, heal: true, snsKey: key,
		snsCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// SetHeals controls whether forced deployments stabilize (false simulates a
// fix that doesn't work, e.g. a bad image).
func (s *Stub) SetHeals(v bool) {
	s.mu.Lock()
	s.heal = v
	s.mu.Unlock()
}

// AddService registers an unhealthy ECS service (1 of 2 tasks running).
func (s *Stub) AddService(cluster, name string) {
	s.mu.Lock()
	s.services[cluster+"/"+name] = &ecsService{Cluster: cluster, Name: name, Desired: 2, Running: 1, Deployments: 1}
	s.mu.Unlock()
}

// Snapshot returns copies of what the sinks and fake AWS have seen.
func (s *Stub) Snapshot() (calls, slack []string, pd []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Calls...), append([]string(nil), s.Slack...), append([]map[string]any(nil), s.PD...)
}

// Handler serves every stub endpoint.
func (s *Stub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /aws", s.handleAWS)
	mux.HandleFunc("POST /aws/", s.handleAWS)
	mux.HandleFunc("GET /sns/cert.pem", func(w http.ResponseWriter, _ *http.Request) { w.Write(s.snsCert) })
	mux.HandleFunc("GET /sns/subscribe", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<ConfirmSubscriptionResponse/>")) })
	mux.HandleFunc("POST /slack", func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			Text string `json:"text"`
		}
		json.NewDecoder(r.Body).Decode(&m)
		s.mu.Lock()
		s.Slack = append(s.Slack, m.Text)
		s.mu.Unlock()
		fmt.Printf("[slack] %s\n", m.Text)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /pagerduty", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		s.mu.Lock()
		s.PD = append(s.PD, m)
		s.mu.Unlock()
		summary := ""
		if p, ok := m["payload"].(map[string]any); ok {
			summary = fmt.Sprint(p["summary"])
		}
		fmt.Printf("[pagerduty] %v %v %s\n", m["event_action"], m["dedup_key"], summary)
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"success"}`))
	})
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		calls, slack, pd := s.Snapshot()
		json.NewEncoder(w).Encode(map[string]any{"aws_calls": calls, "slack": slack, "pagerduty": pd})
	})
	mux.HandleFunc("POST /ecs/heals", func(w http.ResponseWriter, r *http.Request) {
		s.SetHeals(r.URL.Query().Get("value") != "false")
	})
	mux.HandleFunc("POST /ecs/services", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Cluster, Service string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Cluster == "" || req.Service == "" {
			http.Error(w, "cluster and service are required", http.StatusBadRequest)
			return
		}
		s.AddService(req.Cluster, req.Service)
		fmt.Printf("[ecs] %s/%s is unhealthy (1 of 2 tasks running)\n", req.Cluster, req.Service)
	})
	// Simulates CloudWatch publishing an alarm state change to SNS, which
	// delivers a signed notification to the integration's ingest URL.
	mux.HandleFunc("POST /sns/publish", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IngestURL string `json:"ingest_url"`
			TopicArn  string `json:"topic_arn"`
			Alarm     string `json:"alarm"`
			State     string `json:"state"`
			Cluster   string `json:"cluster"`
			Service   string `json:"service"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		code, err := s.Publish(req.IngestURL, req.TopicArn, CloudWatchAlarm(req.Alarm, req.State, req.Cluster, req.Service))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		fmt.Printf("[sns] delivered %s %s -> ingest returned %d\n", req.Alarm, req.State, code)
		json.NewEncoder(w).Encode(map[string]int{"ingest_status": code})
	})
	return mux
}

// ---------------------------------------------------------------------------
// Fake AWS (JSON protocol)
// ---------------------------------------------------------------------------

func awsError(w http.ResponseWriter, code int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func (s *Stub) handleAWS(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=") {
		awsError(w, 403, "MissingAuthenticationTokenException", "request is not SigV4-signed")
		return
	}
	target := r.Header.Get("X-Amz-Target")
	var in map[string]any
	json.NewDecoder(r.Body).Decode(&in)
	s.mu.Lock()
	defer s.mu.Unlock()

	switch target {
	case "AmazonEC2ContainerServiceV20141113.DescribeServices":
		s.Calls = append(s.Calls, "ecs:DescribeServices")
		cluster, _ := in["cluster"].(string)
		var out []map[string]any
		var failures []map[string]any
		names, _ := in["services"].([]any)
		for _, n := range names {
			svc, ok := s.services[cluster+"/"+fmt.Sprint(n)]
			if !ok {
				failures = append(failures, map[string]any{"arn": n, "reason": "MISSING"})
				continue
			}
			s.tick(svc)
			deps := []map[string]any{{"id": "ecs-svc/new", "status": "PRIMARY", "runningCount": svc.Running}}
			if svc.Deployments > 1 {
				deps = append(deps, map[string]any{"id": "ecs-svc/old", "status": "ACTIVE", "runningCount": 0})
			}
			out = append(out, map[string]any{
				"serviceName": svc.Name, "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/" + cluster,
				"status": "ACTIVE", "desiredCount": svc.Desired, "runningCount": svc.Running, "pendingCount": svc.Desired - svc.Running,
				"deployments": deps,
			})
		}
		if failures == nil {
			failures = []map[string]any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"services": out, "failures": failures})

	case "AmazonEC2ContainerServiceV20141113.UpdateService":
		s.Calls = append(s.Calls, "ecs:UpdateService")
		cluster, _ := in["cluster"].(string)
		name, _ := in["service"].(string)
		svc, ok := s.services[cluster+"/"+name]
		if !ok {
			awsError(w, 400, "ServiceNotFoundException", "Service not found.")
			return
		}
		if force, _ := in["forceNewDeployment"].(bool); force {
			svc.Deployments = 2
			svc.Running = 0
			if s.heal {
				svc.RolloutFinishAt = time.Now().Add(s.healIn)
			} else {
				svc.RolloutFinishAt = time.Time{}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"service": map[string]any{"serviceName": name, "status": "ACTIVE"}})

	case "secretsmanager.GetSecretValue":
		s.Calls = append(s.Calls, "secretsmanager:GetSecretValue")
		id, _ := in["SecretId"].(string)
		json.NewEncoder(w).Encode(map[string]any{"Name": id, "SecretString": "s3cr3t-value-for-" + id})

	default:
		awsError(w, 400, "UnknownOperationException", "devstub does not implement "+target)
	}
}

// tick advances a rollout once its finish time passes.
func (s *Stub) tick(svc *ecsService) {
	if svc.Deployments > 1 && !svc.RolloutFinishAt.IsZero() && time.Now().After(svc.RolloutFinishAt) {
		svc.Deployments = 1
		svc.Running = svc.Desired
	}
}

// ---------------------------------------------------------------------------
// SNS
// ---------------------------------------------------------------------------

// CloudWatchAlarm builds an alarm state-change message for an ECS service.
func CloudWatchAlarm(alarm, state, cluster, service string) map[string]any {
	return map[string]any{
		"AlarmName":        alarm,
		"AlarmDescription": "Running task count below desired",
		"AWSAccountId":     "123456789012",
		"NewStateValue":    state,
		"NewStateReason":   "Threshold Crossed: 1 datapoint [1.0] was less than the threshold (2.0).",
		"StateChangeTime":  time.Now().UTC().Format("2006-01-02T15:04:05.000-0700"),
		"Region":           "US East (N. Virginia)",
		"AlarmArn":         "arn:aws:cloudwatch:us-east-1:123456789012:alarm:" + alarm,
		"Trigger": map[string]any{
			"MetricName": "RunningTaskCount", "Namespace": "ECS/ContainerInsights",
			"Dimensions": []map[string]string{{"name": "ClusterName", "value": cluster}, {"name": "ServiceName", "value": service}},
		},
	}
}

// SNSEnvelope wraps message in a signed SNS notification (SignatureVersion 2).
func (s *Stub) SNSEnvelope(topicArn string, message any) []byte {
	msg, _ := json.Marshal(message)
	m := map[string]string{
		"Type":             "Notification",
		"MessageId":        fmt.Sprintf("devstub-%d", time.Now().UnixNano()),
		"TopicArn":         topicArn,
		"Subject":          "ALARM",
		"Message":          string(msg),
		"Timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"SignatureVersion": "2",
		"SigningCertURL":   s.BaseURL + "/sns/cert.pem",
	}
	sts := "Message\n" + m["Message"] + "\nMessageId\n" + m["MessageId"] + "\nSubject\n" + m["Subject"] +
		"\nTimestamp\n" + m["Timestamp"] + "\nTopicArn\n" + m["TopicArn"] + "\nType\n" + m["Type"] + "\n"
	h := sha256.Sum256([]byte(sts))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, s.snsKey, crypto.SHA256, h[:])
	m["Signature"] = base64.StdEncoding.EncodeToString(sig)
	b, _ := json.Marshal(m)
	return b
}

// Publish delivers a signed SNS notification to an ingest URL.
func (s *Stub) Publish(ingestURL, topicArn string, message any) (int, error) {
	resp, err := http.Post(ingestURL, "text/plain; charset=UTF-8", bytes.NewReader(s.SNSEnvelope(topicArn, message)))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
