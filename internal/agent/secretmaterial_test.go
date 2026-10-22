package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/runbook"
)

// awsFunc is an AWSCaller that answers every call itself.
type awsFunc func(ctx context.Context, service, action string, input map[string]any) (map[string]any, error)

func (f awsFunc) Call(ctx context.Context, service, action string, input map[string]any) (map[string]any, error) {
	return f(ctx, service, action, input)
}

func awsStep(service, action string) runbook.Step {
	return runbook.Step{ID: "s", Type: "aws", Service: service, Action: action}
}

// decodeJSON gives a response the shapes awscall returns.
func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Every AWS action that returns secret material, in the response shapes
// AWS documents, yields exactly its secret values.
func TestSecretMaterial(t *testing.T) {
	keyB64 := b64("data-key-plaintext-32-bytes!!!!!")
	pairB64 := b64("-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----\n")
	binB64 := b64("binary secret value")
	for _, c := range []struct {
		name string
		step runbook.Step
		resp string
		want []string
	}{
		{"GetSecretValue string", awsStep("secretsmanager", "GetSecretValue"),
			`{"ARN":"arn:aws:secretsmanager:us-east-1:1:secret:db","Name":"db","SecretString":"{\"password\":\"hunter2-hunter2\"}","VersionId":"v1"}`,
			[]string{`{"password":"hunter2-hunter2"}`}},
		{"GetSecretValue binary", awsStep("secretsmanager", "GetSecretValue"),
			`{"Name":"db","SecretBinary":"` + binB64 + `"}`, []string{binB64, "binary secret value"}},
		{"BatchGetSecretValue", awsStep("secretsmanager", "BatchGetSecretValue"),
			`{"SecretValues":[{"Name":"a","SecretString":"first-secret"},{"Name":"b","SecretBinary":"` + binB64 + `"},{"Name":"c"}],"Errors":[{"SecretId":"d","ErrorCode":"ResourceNotFoundException"}]}`,
			[]string{"first-secret", binB64, "binary secret value"}},
		{"GetRandomPassword", awsStep("secretsmanager", "GetRandomPassword"), `{"RandomPassword":"Zq8#pL2!vX9@"}`, []string{"Zq8#pL2!vX9@"}},
		{"DescribeSecret", awsStep("secretsmanager", "DescribeSecret"), `{"Name":"db","ARN":"arn"}`, nil},
		{"GetParameter secure", awsStep("ssm", "GetParameter"),
			`{"Parameter":{"Name":"/db/pw","Type":"SecureString","Value":"ssm-secret-value","Version":3}}`, []string{"ssm-secret-value"}},
		{"GetParameter plain", awsStep("ssm", "GetParameter"),
			`{"Parameter":{"Name":"/db/host","Type":"String","Value":"db.internal"}}`, nil},
		{"GetParameters mixed", awsStep("ssm", "GetParameters"),
			`{"Parameters":[{"Name":"/a","Type":"String","Value":"plain-config"},{"Name":"/b","Type":"SecureString","Value":"secure-one"},{"Name":"/c","Type":"StringList","Value":"x,y"}],"InvalidParameters":["/d"]}`,
			[]string{"secure-one"}},
		{"GetParametersByPath mixed", awsStep("ssm", "GetParametersByPath"),
			`{"Parameters":[{"Name":"/app/a","Type":"SecureString","Value":"path-secret-1"},{"Name":"/app/b","Type":"String","Value":"plain"},{"Name":"/app/c","Type":"SecureString","Value":"path-secret-2"}],"NextToken":"t"}`,
			[]string{"path-secret-1", "path-secret-2"}},
		{"GetParameterHistory", awsStep("ssm", "GetParameterHistory"),
			`{"Parameters":[{"Name":"/db/pw","Type":"SecureString","Value":"old-password","Version":1},{"Name":"/db/pw","Type":"SecureString","Value":"new-password","Version":2}]}`,
			[]string{"old-password", "new-password"}},
		{"DescribeParameters", awsStep("ssm", "DescribeParameters"), `{"Parameters":[{"Name":"/db/pw","Type":"SecureString"}]}`, nil},
		{"kms Decrypt", awsStep("kms", "Decrypt"), `{"KeyId":"arn:k","Plaintext":"` + keyB64 + `","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`,
			[]string{keyB64, "data-key-plaintext-32-bytes!!!!!"}},
		{"kms GenerateDataKey", awsStep("kms", "GenerateDataKey"), `{"CiphertextBlob":"AQIDBAUG","KeyId":"arn:k","Plaintext":"` + keyB64 + `"}`,
			[]string{keyB64, "data-key-plaintext-32-bytes!!!!!"}},
		{"kms GenerateRandom", awsStep("kms", "GenerateRandom"), `{"Plaintext":"` + keyB64 + `"}`, []string{keyB64, "data-key-plaintext-32-bytes!!!!!"}},
		{"kms GenerateDataKeyPair", awsStep("kms", "GenerateDataKeyPair"),
			`{"KeyId":"arn:k","KeyPairSpec":"RSA_2048","PrivateKeyCiphertextBlob":"AQID","PrivateKeyPlaintext":"` + pairB64 + `","PublicKey":"MIIBIj"}`,
			[]string{pairB64, "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----\n"}},
		{"kms DeriveSharedSecret", awsStep("kms", "DeriveSharedSecret"), `{"KeyId":"arn:k","SharedSecret":"` + keyB64 + `"}`,
			[]string{keyB64, "data-key-plaintext-32-bytes!!!!!"}},
		{"kms GenerateDataKeyWithoutPlaintext", awsStep("kms", "GenerateDataKeyWithoutPlaintext"), `{"CiphertextBlob":"AQID","KeyId":"arn:k"}`, nil},
		{"kms Decrypt for a recipient", awsStep("kms", "Decrypt"), `{"CiphertextForRecipient":"AQID","KeyId":"arn:k"}`, nil},
		{"kms Plaintext not base64", awsStep("kms", "Decrypt"), `{"Plaintext":"not base64!"}`, []string{"not base64!"}},
		// Action names compared without case: a miss would publish a secret.
		{"odd case", awsStep("secretsmanager", "getSecretValue"), `{"SecretString":"cased-secret"}`, []string{"cased-secret"}},
		// Other services never yield material, whatever their fields are called.
		{"other service", awsStep("ecs", "DescribeServices"), `{"SecretString":"not-a-secret","Plaintext":"x"}`, nil},
		{"wait check", runbook.Step{ID: "w", Type: "wait", Check: &runbook.Check{AWS: &runbook.AWSCall{Service: "ssm", Action: "GetParameter"}}},
			`{"Parameter":{"Type":"SecureString","Value":"polled-secret"}}`, []string{"polled-secret"}},
		{"wait http check", runbook.Step{ID: "w", Type: "wait", Check: &runbook.Check{}}, `{"SecretString":"x"}`, nil},
		// Odd shapes are ignored, not a panic.
		{"wrong types", awsStep("secretsmanager", "BatchGetSecretValue"), `{"SecretValues":{"a":"b"}}`, nil},
		{"wrong element types", awsStep("ssm", "GetParameters"), `{"Parameters":["x",1,null,{"Type":"SecureString","Value":7}]}`, nil},
		{"empty secret", awsStep("secretsmanager", "GetSecretValue"), `{"SecretString":""}`, nil},
		{"non-string secret", awsStep("secretsmanager", "GetSecretValue"), `{"SecretString":{"a":"b"}}`, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := secretMaterial(c.step, decodeJSON(t, c.resp))
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("secretMaterial = %q, want %q", got, want)
			}
		})
	}
	if got := secretMaterial(awsStep("secretsmanager", "GetSecretValue"), nil); len(got) != 0 {
		t.Fatalf("nil response: %q", got)
	}
}

// End to end: an aws step that reads secrets and copies them into outputs
// (directly, decoded, or as one JSON field) reports only redacted values,
// while the non-secret parts of the response stay readable.
func TestSecretMaterialIsRedactedFromStepResults(t *testing.T) {
	dataKey := "0123456789abcdef-raw-data-key!!"
	for _, c := range []struct {
		name      string
		service   string
		action    string
		resp      map[string]any
		outputs   map[string]string
		forbidden []string
		visible   map[string]any // outputs that must come through unchanged
	}{
		{"secrets manager", "secretsmanager", "GetSecretValue",
			map[string]any{"Name": "db", "SecretString": `{"username":"app","password":"s3cr3t-Pa55w0rd"}`},
			map[string]string{"whole": "result.SecretString", "name": "result.Name", "b64": "base64.encode(bytes(result.SecretString))"},
			[]string{"s3cr3t-Pa55w0rd", b64(`{"username":"app","password":"s3cr3t-Pa55w0rd"}`)},
			map[string]any{"name": "db"}},
		{"parameters by path", "ssm", "GetParametersByPath",
			map[string]any{"Parameters": []any{
				map[string]any{"Name": "/app/url", "Type": "String", "Value": "https://api.internal"},
				map[string]any{"Name": "/app/key", "Type": "SecureString", "Value": "api-key-0f9e8d7c"},
			}},
			map[string]string{"url": "result.Parameters[0].Value", "key": "result.Parameters[1].Value", "all": "result.Parameters"},
			[]string{"api-key-0f9e8d7c"},
			map[string]any{"url": "https://api.internal"}},
		{"batch", "secretsmanager", "BatchGetSecretValue",
			map[string]any{"SecretValues": []any{map[string]any{"Name": "a", "SecretString": "batch-secret-aaaa"}, map[string]any{"Name": "b", "SecretString": "batch-secret-bbbb"}}},
			map[string]string{"values": "result.SecretValues.map(v, v.SecretString)"},
			[]string{"batch-secret-aaaa", "batch-secret-bbbb"}, nil},
		{"data key", "kms", "GenerateDataKey",
			map[string]any{"CiphertextBlob": "AQIDBAUGBwg=", "KeyId": "arn:aws:kms:k", "Plaintext": b64(dataKey)},
			map[string]string{"plain": "result.Plaintext", "raw": "base64.decode(result.Plaintext)", "blob": "result.CiphertextBlob"},
			[]string{b64(dataKey), dataKey},
			map[string]any{"blob": "AQIDBAUGBwg="}},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := c.resp
			h := newVHarness(t, awsFunc(func(context.Context, string, string, map[string]any) (map[string]any, error) {
				return resp, nil
			}))
			st := awsStep(c.service, c.action)
			st.Outputs = c.outputs
			res, sent := h.run(vStep(st, nil), 10*time.Second)
			if res.Status != "succeeded" {
				t.Fatalf("status %s: %s", res.Status, res.Error)
			}
			if leaks := findLeaks(res, sent, c.forbidden...); len(leaks) > 0 {
				t.Fatalf("leaked: %+v (outputs %v)", leaks, res.Outputs)
			}
			for k, want := range c.visible {
				if !reflect.DeepEqual(res.Outputs[k], want) {
					t.Errorf("output %s = %#v, want %#v (over-redacted)", k, res.Outputs[k], want)
				}
			}
			if !strings.Contains(resultStrings(res), Redacted) {
				t.Errorf("nothing was redacted: %v", res.Outputs)
			}
		})
	}
}

func TestSecretMaterialDecodesStandardBase64Only(t *testing.T) {
	// AWS JSON blobs are standard base64; URL-safe or unpadded text is
	// treated as an opaque string.
	raw := "\xff\xfe raw bytes \x00"
	got := secretMaterial(awsStep("kms", "Decrypt"), map[string]any{"Plaintext": base64.StdEncoding.EncodeToString([]byte(raw))})
	if len(got) != 2 || got[1] != raw {
		t.Fatalf("got %q", got)
	}
}
