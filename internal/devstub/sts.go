package devstub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// IAMIdentity is a fake principal: credentials and the role it maps to.
type IAMIdentity struct {
	AccessKey, Secret string
	Account, Role     string
}

// AddIAMIdentity registers credentials the fake STS will recognize.
func (s *Stub) AddIAMIdentity(id IAMIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iam == nil {
		s.iam = map[string]IAMIdentity{}
	}
	s.iam[id.AccessKey] = id
}

// handleSTS implements sts:GetCallerIdentity. Like the real STS it verifies
// the SigV4 signature (by recomputing it), rejects stale requests, and
// answers with the caller's assumed-role ARN.
func (s *Stub) handleSTS(w http.ResponseWriter, r *http.Request) {
	fail := func(code, msg string) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>`, code, msg)
	}
	body, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	// AWS4-HMAC-SHA256 Credential=AKID/20261020/us-east-1/sts/aws4_request, SignedHeaders=a;b, Signature=hex
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		fields[k] = v
	}
	cred := strings.Split(fields["Credential"], "/")
	if len(cred) != 5 || fields["SignedHeaders"] == "" || fields["Signature"] == "" {
		fail("IncompleteSignature", "Authorization header is incomplete")
		return
	}
	s.mu.Lock()
	id, ok := s.iam[cred[0]]
	s.mu.Unlock()
	if !ok {
		fail("InvalidClientTokenId", "The security token included in the request is invalid.")
		return
	}
	t, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || time.Since(t) > 15*time.Minute || time.Until(t) > 15*time.Minute {
		fail("SignatureDoesNotMatch", "Signature expired")
		return
	}

	// Rebuild the request from exactly the signed headers and sign it again.
	re, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	re.Host = r.Host
	for _, h := range strings.Split(fields["SignedHeaders"], ";") {
		if h == "host" || h == "x-amz-date" {
			continue
		}
		re.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
	}
	sum := sha256.Sum256(body)
	creds := aws.Credentials{AccessKeyID: id.AccessKey, SecretAccessKey: id.Secret}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, re, hex.EncodeToString(sum[:]), cred[3], cred[2], t); err != nil {
		fail("SignatureDoesNotMatch", err.Error())
		return
	}
	if re.Header.Get("Authorization") != auth {
		fail("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
		return
	}
	if string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
		fail("InvalidAction", "only GetCallerIdentity is implemented")
		return
	}
	s.mu.Lock()
	s.Calls = append(s.Calls, "sts:GetCallerIdentity")
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::%[1]s:assumed-role/%[2]s/ecs-task-1234</Arn>
    <UserId>AROAEXAMPLE:ecs-task-1234</UserId>
    <Account>%[1]s</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>devstub</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`, id.Account, id.Role)
}
