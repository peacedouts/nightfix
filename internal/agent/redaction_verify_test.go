package agent

// Verification suite for output redaction (run with -run Verify).
//
// Every test asserts that a resolved secret value -- or a common encoding of
// it -- never reaches the fake control plane (streamed chunks) or the
// returned Result (Error, Outputs including map keys).

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/runbook"
	"github.com/peacedouts/nightfix/internal/signing"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// vSink is a fake control plane that records output chunks per attempt.
type vSink struct {
	mu        sync.Mutex
	byAttempt map[string][]agentapi.OutputChunk
}

func (s *vSink) chunks(att string) []agentapi.OutputChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agentapi.OutputChunk(nil), s.byAttempt[att]...)
}

func (s *vSink) text(att string, streams ...string) string {
	var b strings.Builder
	for _, c := range s.chunks(att) {
		if len(streams) == 0 || vContains(streams, c.Stream) {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

func vContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// vAWS is a fake AWSCaller: it serves secrets and delegates step calls.
type vAWS struct {
	ssm  map[string]string // parameter name (leading /) -> value
	sm   map[string]string // secret id -> SecretString
	step func(service, action string, input map[string]any, n int) (map[string]any, error)

	mu sync.Mutex
	n  int
}

func (f *vAWS) Call(_ context.Context, service, action string, input map[string]any) (map[string]any, error) {
	switch service + ":" + action {
	case "secretsmanager:GetSecretValue":
		id, _ := input["SecretId"].(string)
		if v, ok := f.sm[id]; ok {
			return map[string]any{"ARN": "arn:aws:secretsmanager:x", "Name": id, "SecretString": v}, nil
		}
		return nil, fmt.Errorf("secretsmanager:GetSecretValue failed: ResourceNotFoundException: %s (HTTP 400)", id)
	case "ssm:GetParameter":
		name, _ := input["Name"].(string)
		if v, ok := f.ssm[name]; ok {
			return map[string]any{"Parameter": map[string]any{"Name": name, "Type": "SecureString", "Value": v}}, nil
		}
		if f.step == nil {
			return nil, fmt.Errorf("ssm:GetParameter failed: ParameterNotFound: %s (HTTP 400)", name)
		}
	}
	if f.step == nil {
		return nil, errors.New("unexpected call " + service + ":" + action)
	}
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	return f.step(service, action, input, n)
}

type vHarness struct {
	t    *testing.T
	sink *vSink
	a    *Agent
	seq  int
}

func newVHarness(t *testing.T, aws AWSCaller) *vHarness {
	t.Helper()
	s := &vSink{byAttempt: map[string][]agentapi.OutputChunk{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/agent/v1/attempts/"), "/output")
		var b agentapi.OutputBatch
		json.NewDecoder(r.Body).Decode(&b)
		s.mu.Lock()
		s.byAttempt[att] = append(s.byAttempt[att], b.Chunks...)
		s.mu.Unlock()
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AWS: aws}, c: c,
		id: &identity{}, inflight: map[string]context.CancelFunc{}, seen: map[string]time.Time{}}
	return &vHarness{t: t, sink: s, a: a}
}

func (h *vHarness) nextAttempt() string {
	h.seq++
	return fmt.Sprintf("att-%d", h.seq)
}

// run executes v and returns the Result and everything the control plane got.
func (h *vHarness) run(v *verified, timeout time.Duration) (agentapi.Result, string) {
	h.t.Helper()
	v.env.AttemptID = h.nextAttempt()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res := h.a.execute(ctx, v)
	return res, h.sink.text(v.env.AttemptID)
}

func vStep(step runbook.Step, secrets map[string]runbook.SecretRef) *verified {
	if step.ID == "" {
		step.ID = "s"
	}
	return &verified{env: signing.Envelope{AttemptID: "att"}, rb: &runbook.Runbook{Spec: runbook.Spec{Secrets: secrets}}, step: step}
}

// ssmSecret declares a single SSM secret "pw" holding value.
func ssmSecret(value string) (*vAWS, map[string]runbook.SecretRef) {
	return &vAWS{ssm: map[string]string{"/pw": value}},
		map[string]runbook.SecretRef{"pw": {Ref: "secret://aws-ssm/pw"}}
}

// resultStrings flattens a Result into every string it carries, map keys
// included.
func resultStrings(res agentapi.Result) string {
	var parts []string
	parts = append(parts, res.Error)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			parts = append(parts, x)
		case map[string]any:
			for k, e := range x {
				parts = append(parts, k)
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case nil:
		default:
			parts = append(parts, fmt.Sprint(x))
		}
	}
	walk(res.Outputs)
	return strings.Join(parts, "\x00")
}

type leak struct{ where, what string }

func findLeaks(res agentapi.Result, sent string, forbidden ...string) []leak {
	var out []leak
	rs := resultStrings(res)
	for _, f := range forbidden {
		if f == "" {
			continue
		}
		if strings.Contains(sent, f) {
			out = append(out, leak{"control-plane stream", f})
		}
		if strings.Contains(rs, f) {
			out = append(out, leak{"Result", f})
		}
	}
	return out
}

// rawOutput runs script with env directly (no agent, no redaction) so a case
// can prove its forbidden string really is what the tool prints.
func rawOutput(t *testing.T, script string, env map[string]string) string {
	t.Helper()
	cmd := exec.Command("bash", "-euo", "pipefail", "-c", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("raw run of %q: %v: %s", script, err, out)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func wrapAt(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

// jsonInner is the JSON string encoding of s without the surrounding quotes
// and without HTML escaping (what jq and most encoders print).
func jsonInner(s string) string {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}

// jsonInnerHTML is Go's json.Marshal form (escapes <, >, &).
func jsonInnerHTML(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// jsonInnerASCII is Python's json.dumps default (ensure_ascii=True).
func jsonInnerASCII(s string) string {
	var b strings.Builder
	for _, r := range jsonInner(s) {
		switch {
		case r < 0x80:
			b.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// lowerPct lower-cases the hex digits of every %XX escape.
func lowerPct(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = strings.ToLower(string(b[i+1]))[0]
			b[i+2] = strings.ToLower(string(b[i+2]))[0]
		}
	}
	return string(b)
}

// uriComponent is encodeURIComponent / Python quote(safe=”): QueryEscape
// with %20 for space.
func uriComponent(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

func needTools(t *testing.T, tools ...string) {
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// 1. Common transformations of a printed value
// ---------------------------------------------------------------------------

func TestVerifyTransformations(t *testing.T) {
	type tc struct {
		name      string
		value     string
		run       string
		extraEnv  map[string]string // plain (non-secret) env
		forbidden []string
		stripNL   bool // also check the stream with newlines removed (wrapped encodings)
		tools     []string
	}
	long := "tok_" + strings.Repeat("A1b2C3d4E5", 9) // 94 bytes > 57, so base64 wraps
	cases := []tc{
		{name: "base64_exact_control", value: "hunter2-Secret!", run: `printf %s "$V" | base64 -w0; echo`,
			forbidden: []string{b64("hunter2-Secret!")}},
		// len%3 = 0, 1, 2: RawStdEncoding(value) is a prefix of base64(value+"\n")
		// only because '\n' (0x0A) has its top four bits clear.
		{name: "base64_echo_pipe_value_plus_newline_len3k", value: "hunter2-Secret!", run: `echo "$V" | base64`,
			forbidden: []string{b64("hunter2-Secret!\n")}},
		{name: "base64_echo_pipe_value_plus_newline_len3k+1", value: "hunter2-Secret!x", run: `echo "$V" | base64`,
			forbidden: []string{b64("hunter2-Secret!x\n")}},
		{name: "base64_echo_pipe_value_plus_newline_len3k+2", value: "hunter2-Secret!xy", run: `echo "$V" | base64`,
			forbidden: []string{b64("hunter2-Secret!xy\n")}},
		{name: "base64_value_plus_crlf", value: "hunter2-Secret!x", run: `printf '%s\r\n' "$V" | base64 -w0; echo`,
			forbidden: []string{b64("hunter2-Secret!x\r\n")}},
		{name: "base64_wrapped_76", value: long, run: `printf %s "$V" | base64`,
			forbidden: []string{wrapAt(b64(long), 76), b64(long)}, stripNL: true},
		{name: "base64_wrapped_76_echo_pipe", value: long, run: `echo "$V" | base64`,
			forbidden: []string{wrapAt(b64(long+"\n"), 76), b64(long + "\n")}, stripNL: true},
		{name: "base64_offset_basic_auth", value: "hunter2-Secret!", run: `printf %s "svc:$V" | base64 -w0; echo`,
			forbidden: []string{b64("svc:hunter2-Secret!")}},
		{name: "hex_lower", value: "hunter2-Secret!", run: `printf %s "$V" | od -An -tx1 -v | tr -d ' \n'; echo`,
			forbidden: []string{hex.EncodeToString([]byte("hunter2-Secret!"))}},
		{name: "hex_upper", value: "hunter2-Secret!", run: `printf %s "$V" | od -An -tx1 -v | tr -d ' \n' | tr a-f A-F; echo`,
			forbidden: []string{strings.ToUpper(hex.EncodeToString([]byte("hunter2-Secret!")))}},
		{name: "url_upper_no_space_control", value: "p@ss:w/rd#1x", tools: []string{"python3"},
			run:       `python3 -c 'import os,urllib.parse;print(urllib.parse.quote(os.environ["V"],safe=""))'`,
			forbidden: []string{url.QueryEscape("p@ss:w/rd#1x")}},
		{name: "url_lower_hex", value: "p@ss:w/rd#1x", run: `echo "u=$ENC"`,
			extraEnv:  map[string]string{"ENC": lowerPct(url.QueryEscape("p@ss:w/rd#1x"))},
			forbidden: []string{lowerPct(url.QueryEscape("p@ss:w/rd#1x"))}},
		{name: "url_space_as_pct20", value: "correct horse@battery", tools: []string{"python3"},
			run:       `python3 -c 'import os,urllib.parse;print(urllib.parse.quote(os.environ["V"],safe=""))'`,
			forbidden: []string{uriComponent("correct horse@battery")}},
		{name: "url_space_as_plus_control", value: "correct horse@battery", tools: []string{"python3"},
			run:       `python3 -c 'import os,urllib.parse;print(urllib.parse.quote_plus(os.environ["V"],safe=""))'`,
			forbidden: []string{url.QueryEscape("correct horse@battery")}},
		{name: "json_quote_backslash", value: `pa"ss\word-1`, tools: []string{"jq"},
			run: `jq -cn --arg v "$V" '{v:$v}'`, forbidden: []string{jsonInner(`pa"ss\word-1`)}},
		{name: "json_slash_escaped", value: "abc/def/ghi", run: `echo "{\"v\":\"$ENC\"}"`,
			extraEnv:  map[string]string{"ENC": strings.ReplaceAll("abc/def/ghi", "/", `\/`)},
			forbidden: []string{strings.ReplaceAll("abc/def/ghi", "/", `\/`)}},
		{name: "json_control_chars_multiline", value: "-----BEGIN KEY-----\nMIIEabc123\tx\n-----END KEY-----", tools: []string{"jq"},
			run:       `jq -cn --arg v "$V" '{key:$v}'`,
			forbidden: []string{jsonInner("-----BEGIN KEY-----\nMIIEabc123\tx\n-----END KEY-----")}},
		{name: "json_non_ascii_raw_control", value: "pässwörd-ü1", tools: []string{"jq"},
			run: `jq -cn --arg v "$V" '{v:$v}'`, forbidden: []string{"pässwörd-ü1"}},
		{name: "json_non_ascii_u_escaped", value: "pässwörd-ü1", tools: []string{"python3"},
			run:       `python3 -c 'import json,os;print(json.dumps({"v":os.environ["V"]}))'`,
			forbidden: []string{jsonInnerASCII("pässwörd-ü1")}},
		{name: "json_go_html_escape", value: "a<b>&c-secret", run: `echo "{\"v\":\"$ENC\"}"`,
			extraEnv:  map[string]string{"ENC": jsonInnerHTML("a<b>&c-secret")},
			forbidden: []string{jsonInnerHTML("a<b>&c-secret")}},
		{name: "stored_trailing_newline_printed_as_is_control", value: "s3cr3t-value\n", run: `printf '%s' "$V"`,
			forbidden: []string{"s3cr3t-value\n"}},
		{name: "stored_trailing_newline_via_cmd_subst", value: "s3cr3t-value\n", run: `X=$(printf %s "$V"); echo "token=$X;"`,
			forbidden: []string{"s3cr3t-value"}},
		{name: "stored_crlf_normalized_to_lf", value: "line-one-secret\r\nline-two-secret", run: `printf '%s\n' "$V" | tr -d '\r'`,
			forbidden: []string{"line-one-secret\nline-two-secret"}},
		{name: "stored_trailing_crlf_trimmed", value: "s3cr3t-value\r\n", run: `X=$(printf %s "$V" | tr -d '\r'); echo "token=$X;"`,
			forbidden: []string{"s3cr3t-value"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			needTools(t, c.tools...)
			env := map[string]string{"V": c.value}
			for k, v := range c.extraEnv {
				env[k] = v
			}
			raw := rawOutput(t, c.run, env)
			rawCheck := raw
			if c.stripNL {
				rawCheck = strings.ReplaceAll(raw, "\n", "")
			}
			if !strings.Contains(rawCheck, c.forbidden[len(c.forbidden)-1]) && !strings.Contains(raw, c.forbidden[0]) {
				t.Fatalf("test bug: tool output %q does not contain the expected form %q", raw, c.forbidden)
			}

			aws, secrets := ssmSecret(c.value)
			h := newVHarness(t, aws)
			stepEnv := map[string]string{"V": "${{ secrets.pw }}"}
			for k, v := range c.extraEnv {
				stepEnv[k] = v
			}
			res, sent := h.run(vStep(runbook.Step{Type: "shell", Run: c.run, Env: stepEnv,
				Outputs: map[string]string{"out": "result.stdout"}}, secrets), 20*time.Second)
			if res.Status != "succeeded" {
				t.Fatalf("status %s: %s", res.Status, res.Error)
			}
			leaks := findLeaks(res, sent, c.forbidden...)
			if c.stripNL {
				for _, f := range c.forbidden {
					if strings.Contains(strings.ReplaceAll(sent, "\n", ""), strings.ReplaceAll(f, "\n", "")) {
						leaks = append(leaks, leak{"control-plane stream (newlines removed)", f})
					}
				}
			}
			for _, l := range leaks {
				t.Errorf("NOT SCRUBBED: %q reached the %s; sent=%q", l.what, l.where, sent)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Structured (JSON) secret values
// ---------------------------------------------------------------------------

func TestVerifyStructuredSecret(t *testing.T) {
	needTools(t, "jq")
	const js = `{"username":"u","password":"p@ss-123"}`
	const pw = "p@ss-123"
	smWhole := map[string]runbook.SecretRef{"db": {Ref: "secret://aws-sm/prod/db"}}
	smKey := map[string]runbook.SecretRef{"db": {Ref: "secret://aws-sm/prod/db", Key: "password"}}
	cases := []struct {
		name    string
		secrets map[string]runbook.SecretRef
		run     string
	}{
		{"whole_json_printed_verbatim_control", smWhole, `printf '%s\n' "$DB"`},
		{"whole_json_extract_password_jq_r", smWhole, `printf %s "$DB" | jq -r .password`},
		{"whole_json_pretty_printed", smWhole, `printf %s "$DB" | jq .`},
		{"whole_json_connection_string", smWhole, `echo "postgres://$(printf %s "$DB" | jq -r .username):$(printf %s "$DB" | jq -r .password)@db:5432/app"`},
		{"key_password_selected_control", smKey, `echo "pw=$DB"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newVHarness(t, &vAWS{sm: map[string]string{"prod/db": js}})
			res, sent := h.run(vStep(runbook.Step{Type: "shell", Run: c.run, Env: map[string]string{"DB": "${{ secrets.db }}"},
				Outputs: map[string]string{"out": "result.stdout"}}, c.secrets), 20*time.Second)
			if res.Status != "succeeded" {
				t.Fatalf("status %s: %s", res.Status, res.Error)
			}
			for _, l := range findLeaks(res, sent, pw, js) {
				t.Errorf("NOT SCRUBBED: %q reached the %s; sent=%q", l.what, l.where, sent)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Every exit path
// ---------------------------------------------------------------------------

func TestVerifyExitPaths(t *testing.T) {
	const val = `Sup3r-"Secr\et"-ä€😀`
	shellCase := func(t *testing.T, step runbook.Step, timeout time.Duration, wantStatus string) (agentapi.Result, string) {
		t.Helper()
		aws, secrets := ssmSecret(val)
		h := newVHarness(t, aws)
		if step.Env == nil {
			step.Env = map[string]string{}
		}
		if _, ok := step.Env["V"]; !ok {
			step.Env["V"] = "${{ secrets.pw }}"
		}
		step.Type = "shell"
		res, sent := h.run(vStep(step, secrets), timeout)
		if wantStatus != "" && res.Status != wantStatus {
			t.Fatalf("status %s (%s), want %s", res.Status, res.Error, wantStatus)
		}
		return res, sent
	}
	check := func(t *testing.T, res agentapi.Result, sent string, forbidden ...string) {
		t.Helper()
		if len(forbidden) == 0 {
			forbidden = []string{val}
		}
		for _, l := range findLeaks(res, sent, forbidden...) {
			t.Errorf("LEAK: %q reached the %s\n  sent=%q\n  result=%+v", l.what, l.where, sent, res)
		}
	}

	t.Run("shell_stdout_stream", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `echo "a $V b"; printf %s "$V"; printf '%s' "$V" | cat`}, 20*time.Second, "succeeded")
		if !strings.Contains(sent, Redacted) {
			t.Errorf("no redaction marker in %q", sent)
		}
		check(t, res, sent)
	})
	t.Run("shell_stderr_stream", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `echo "err $V" >&2; printf %s "$V" >&2`}, 20*time.Second, "succeeded")
		check(t, res, sent)
	})
	t.Run("shell_result_stdout_stderr_outputs", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `echo "o $V"; echo "e $V" >&2`,
			Outputs: map[string]string{"out": "result.stdout", "err": "result.stderr", "both": "[result.stdout, {'e': result.stderr}]"}},
			20*time.Second, "succeeded")
		if s, _ := res.Outputs["out"].(string); !strings.Contains(s, Redacted) {
			t.Errorf("outputs.out = %q, want a redaction marker", s)
		}
		check(t, res, sent)
	})
	t.Run("shell_outputs_decoded_from_unscrubbed_base64", func(t *testing.T) {
		// base64 at a non-zero offset is not scrubbed (see
		// TestVerifyTransformations); the output decodes it back. redactAny
		// must catch the decoded value.
		res, sent := shellCase(t, runbook.Step{Run: `printf %s "svc:$V" | base64 -w0; echo`,
			Outputs: map[string]string{"dec": "string(base64.decode(result.stdout.trim()))"}}, 20*time.Second, "")
		check(t, res, sent, val)
	})
	t.Run("shell_outputs_value_reversed_back", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `printf %s "$V" | rev; echo`,
			Outputs: map[string]string{"r": "result.stdout.trim().reverse()"}}, 20*time.Second, "succeeded")
		check(t, res, sent, val)
	})
	t.Run("shell_outputs_value_as_map_key", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `printf %s "$V" | rev; echo`,
			Outputs: map[string]string{"m": "{result.stdout.trim().reverse(): true}"}}, 20*time.Second, "succeeded")
		check(t, res, sent, val)
	})
	t.Run("shell_env_render_error_no_such_key", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `true`, Env: map[string]string{"V": `${{ {"k": 1}[secrets.pw] }}`}},
			20*time.Second, "failed")
		t.Logf("res.Error = %q", res.Error)
		check(t, res, sent)
	})
	t.Run("shell_env_render_error_conversion", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `true`, Env: map[string]string{"V": `${{ int(secrets.pw) }}`}},
			20*time.Second, "failed")
		t.Logf("res.Error = %q", res.Error)
		check(t, res, sent, val, strconv.Quote(val)[1:len(strconv.Quote(val))-1], "Secr")
	})
	t.Run("shell_env_render_error_double", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `true`, Env: map[string]string{"V": `${{ double(secrets.pw) }}`}},
			20*time.Second, "failed")
		t.Logf("res.Error = %q", res.Error)
		check(t, res, sent, val, strconv.Quote(val)[1:len(strconv.Quote(val))-1], "Secr")
	})
	t.Run("shell_timeout_flushes_held_tail", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `printf 'start %s' "$V"; sleep 30`, Timeout: "1s"}, time.Second, "timed_out")
		check(t, res, sent)
	})
	t.Run("shell_exit_nonzero", func(t *testing.T) {
		res, sent := shellCase(t, runbook.Step{Run: `echo "$V" >&2; exit 7`}, 20*time.Second, "failed")
		check(t, res, sent)
	})

	// AWS steps. The step references the secret in env so the redactor knows it
	// (SecretsUsed scans Env for every step type).
	awsCase := func(t *testing.T, step runbook.Step, handler func(string, string, map[string]any, int) (map[string]any, error)) (agentapi.Result, string) {
		t.Helper()
		aws, secrets := ssmSecret(val)
		aws.step = handler
		h := newVHarness(t, aws)
		step.Env = map[string]string{"X": "${{ secrets.pw }}"}
		res, sent := h.run(vStep(step, secrets), 20*time.Second)
		return res, sent
	}
	echo := func(string, string, map[string]any, int) (map[string]any, error) {
		return map[string]any{"Echo": val, "Nested": map[string]any{"list": []any{"pre-" + val + "-post"}}}, nil
	}
	t.Run("aws_outputs_values", func(t *testing.T) {
		res, sent := awsCase(t, runbook.Step{Type: "aws", Service: "ssm", Action: "Echo",
			Outputs: map[string]string{"all": "result", "echo": "result.Echo", "n": "result.Nested.list[0]"}}, echo)
		if res.Status != "succeeded" {
			t.Fatalf("status %s: %s", res.Status, res.Error)
		}
		check(t, res, sent)
	})
	t.Run("aws_outputs_map_key", func(t *testing.T) {
		res, sent := awsCase(t, runbook.Step{Type: "aws", Service: "ssm", Action: "Echo",
			Outputs: map[string]string{"all": "result"}},
			func(string, string, map[string]any, int) (map[string]any, error) {
				return map[string]any{"Tags": map[string]any{val: "v"}}, nil
			})
		if res.Status != "succeeded" {
			t.Fatalf("status %s: %s", res.Status, res.Error)
		}
		check(t, res, sent)
	})
	t.Run("aws_call_error", func(t *testing.T) {
		res, sent := awsCase(t, runbook.Step{Type: "aws", Service: "ssm", Action: "Echo"},
			func(string, string, map[string]any, int) (map[string]any, error) {
				return nil, fmt.Errorf("ssm:Echo failed: ValidationException: Value '%s' at 'name' failed to satisfy constraint (HTTP 400)", val)
			})
		if res.Status != "failed" {
			t.Fatalf("status %s", res.Status)
		}
		check(t, res, sent)
	})
	t.Run("aws_output_expression_error", func(t *testing.T) {
		res, sent := awsCase(t, runbook.Step{Type: "aws", Service: "ssm", Action: "Echo",
			Outputs: map[string]string{"bad": `{"k": 1}[result.Echo]`}}, echo)
		if res.Status != "failed" {
			t.Fatalf("status %s, outputs %v", res.Status, res.Outputs)
		}
		t.Logf("res.Error = %q", res.Error)
		check(t, res, sent)
	})
	t.Run("aws_output_conversion_error", func(t *testing.T) {
		res, sent := awsCase(t, runbook.Step{Type: "aws", Service: "ssm", Action: "Echo",
			Outputs: map[string]string{"bad": `int(result.Echo)`}}, echo)
		t.Logf("status %s res.Error = %q", res.Status, res.Error)
		check(t, res, sent, val, strconv.Quote(val)[1:len(strconv.Quote(val))-1], "Secr")
	})
	t.Run("aws_get_secret_value_step_outputs", func(t *testing.T) {
		// A plain aws step reading a secret the runbook declares; lint accepts it
		// (outputs only refuse the literal "secrets"). No secret is "used", so the
		// redactor is empty.
		aws := &vAWS{sm: map[string]string{"prod/db": val}}
		h := newVHarness(t, aws)
		res, sent := h.run(vStep(runbook.Step{Type: "aws", Service: "secretsmanager", Action: "GetSecretValue",
			Input: map[string]any{"SecretId": "prod/db"}, Outputs: map[string]string{"pw": "result.SecretString"}},
			map[string]runbook.SecretRef{"db": {Ref: "secret://aws-sm/prod/db"}}), 20*time.Second)
		if res.Status != "succeeded" {
			t.Fatalf("status %s: %s", res.Status, res.Error)
		}
		if issues := runbook.Lint(&runbook.Runbook{APIVersion: runbook.APIVersion, Kind: runbook.Kind,
			Metadata: runbook.Metadata{Name: "verify-rb", Title: "r"},
			Spec: runbook.Spec{Secrets: map[string]runbook.SecretRef{"db": {Ref: "secret://aws-sm/prod/db"}},
				Steps: []runbook.Step{{ID: "s", Type: "aws", Service: "secretsmanager", Action: "GetSecretValue",
					Input: map[string]any{"SecretId": "prod/db"}, Outputs: map[string]string{"pw": "result.SecretString"}}}}}); true {
			t.Logf("lint issues for this step: %d %v", len(issues), issues)
		}
		check(t, res, sent)
	})

	t.Run("wait_step_logs_and_result", func(t *testing.T) {
		aws, secrets := ssmSecret(val)
		aws.step = func(_, _ string, _ map[string]any, n int) (map[string]any, error) {
			switch n {
			case 1:
				return nil, fmt.Errorf("ssm:Poll failed: Throttling: rate exceeded for '%s' (HTTP 400)", val)
			case 2:
				return map[string]any{"state": "pending", "v": val}, nil
			default:
				return map[string]any{"state": "done", "v": val}, nil
			}
		}
		h := newVHarness(t, aws)
		res, sent := h.run(vStep(runbook.Step{Type: "wait", Env: map[string]string{"X": "${{ secrets.pw }}"},
			Check:    &runbook.Check{AWS: &runbook.AWSCall{Service: "ssm", Action: "Poll"}},
			Until:    `result.state == "done" || {"x": true}[result.v]`,
			Interval: "10ms", Outputs: map[string]string{"r": "result"}}, secrets), 20*time.Second)
		if res.Status != "succeeded" {
			t.Fatalf("status %s: %s", res.Status, res.Error)
		}
		logs := h.sink.text(fmt.Sprintf("att-%d", h.seq), "log")
		if !strings.Contains(logs, "check 1:") || !strings.Contains(logs, "check 2: until:") {
			t.Fatalf("log lines missing: %q", logs)
		}
		t.Logf("log stream: %q", logs)
		check(t, res, sent)
	})
}

// ---------------------------------------------------------------------------
// 4. Differential property test: streamed vs whole-output redaction
// ---------------------------------------------------------------------------

func TestVerifyStreamDifferential(t *testing.T) {
	seed := int64(20261021)
	if s := os.Getenv("NIGHTFIX_REDACT_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	iters := 20000
	if testing.Short() {
		iters = 2000
	}
	rng := mrand.New(mrand.NewSource(seed))
	alpha := []rune{'a', 'b', 'z', '1', 'é', '€', '😀', ' ', '\n'}
	word := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteRune(alpha[rng.Intn(len(alpha))])
		}
		return b.String()
	}
	runePrefix := func(s string, n int) string {
		r := []rune(s)
		if n > len(r) {
			n = len(r)
		}
		return string(r[:n])
	}
	runeSuffix := func(s string, n int) string {
		r := []rune(s)
		if n > len(r) {
			n = len(r)
		}
		return string(r[len(r)-n:])
	}
	h := newVHarness(t, nil)
	leaks, mismatches, badUTF8 := 0, 0, 0
	for iter := 0; iter < iters; iter++ {
		var values []string
		for i := 0; i < 1+rng.Intn(4); i++ {
			v := word(2 + rng.Intn(9))
			if len(values) > 0 && rng.Intn(2) == 0 {
				o := values[rng.Intn(len(values))]
				switch rng.Intn(3) {
				case 0: // shared prefix
					v = runePrefix(o, 1+rng.Intn(4)) + v
				case 1: // shared suffix
					v = v + runeSuffix(o, 1+rng.Intn(4))
				case 2: // overlap: o's end is v's start
					v = runeSuffix(o, 1+rng.Intn(4)) + v
				}
			}
			for len(v) < 4 {
				v += word(1)
			}
			values = append(values, v)
		}
		red := newRedactor(values)
		full := word(5 + rng.Intn(80))
		for i := 0; i < 1+rng.Intn(4); i++ {
			r := []rune(full)
			at := rng.Intn(len(r) + 1)
			ins := values[rng.Intn(len(values))]
			if rng.Intn(4) == 0 { // chain two values back to back
				ins += values[rng.Intn(len(values))]
			}
			if rng.Intn(5) == 0 && len(red.needles) > 0 { // an encoded variant
				ins = red.needles[rng.Intn(len(red.needles))]
			}
			full = string(r[:at]) + ins + string(r[at:])
		}
		var writes []string
		for rest := full; rest != ""; {
			n := 1 + rng.Intn(len(rest))
			writes, rest = append(writes, rest[:n]), rest[n:] // may split a character
		}

		att := h.nextAttempt()
		st := newStreamer(h.a, att)
		st.red = red
		w := st.writer("stdout")
		for _, p := range writes {
			w.Write([]byte(p))
		}
		st.close()
		chunks := h.sink.chunks(att)
		var got strings.Builder
		for _, c := range chunks {
			if !utf8.ValidString(c.Data) {
				badUTF8++
				if badUTF8 <= 3 {
					t.Errorf("seed=%d iter=%d: chunk %d is not valid UTF-8: %q (writes %q)", seed, iter, c.Seq, c.Data, writes)
				}
			}
			got.WriteString(c.Data)
		}
		whole := red.apply(full)
		for _, n := range red.needles {
			if !strings.Contains(whole, n) && strings.Contains(got.String(), n) {
				leaks++
				if leaks <= 3 {
					t.Errorf("seed=%d iter=%d: LEAK %q\n values=%q\n writes=%q\n streamed=%q\n whole=%q", seed, iter, n, values, writes, got.String(), whole)
				}
			}
		}
		if got.String() != whole {
			mismatches++
			if mismatches <= 3 {
				t.Errorf("seed=%d iter=%d: streamed output differs from whole-output redaction\n values=%q\n writes=%q\n streamed=%q\n whole=%q", seed, iter, values, writes, got.String(), whole)
			}
		}
	}
	t.Logf("seed=%d iterations=%d leaks=%d mismatches=%d invalid-utf8-chunks=%d", seed, iters, leaks, mismatches, badUTF8)
	if leaks+mismatches+badUTF8 > 0 {
		t.Errorf("seed=%d: %d leaks, %d mismatches, %d invalid UTF-8 chunks", seed, leaks, mismatches, badUTF8)
	}
}

// ---------------------------------------------------------------------------
// 5. Performance
// ---------------------------------------------------------------------------

func TestVerifyStreamPerformance(t *testing.T) {
	rng := mrand.New(mrand.NewSource(7))
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_@:"
	rnd := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = chars[rng.Intn(len(chars))]
		}
		return string(b)
	}
	var values []string
	for i := 0; i < 200; i++ {
		values = append(values, rnd(64))
	}
	t0 := time.Now()
	red := newRedactor(values)
	tBuild := time.Since(t0)

	var b strings.Builder
	for b.Len() < 1<<20 {
		b.WriteString(rnd(200 + rng.Intn(400)))
		b.WriteString("\n")
		if rng.Intn(10) == 0 {
			b.WriteString("token=" + values[rng.Intn(len(values))] + "\n")
		}
	}
	out := b.String()[:1<<20]

	timeStream := func(red *redactor, out string) (time.Duration, time.Duration, string, int) {
		h := newVHarness(t, nil)
		att := h.nextAttempt()
		st := newStreamer(h.a, att)
		st.red = red
		w := st.writer("stdout")
		start := time.Now()
		for i := 0; i < len(out); i += 4 << 10 {
			w.Write([]byte(out[i:min(i+4<<10, len(out))]))
		}
		writes := time.Since(start)
		st.mu.Lock()
		held := len(st.tails["stdout"])
		st.mu.Unlock()
		c0 := time.Now()
		st.close()
		return writes, time.Since(c0), h.sink.text(att, "stdout"), held
	}

	t.Run("200x64B_needles_1MiB_in_4KiB_writes", func(t *testing.T) {
		writes, closing, sent, _ := timeStream(red, out)
		t1 := time.Now()
		resultText(red, out)
		tResult := time.Since(t1)
		t.Logf("needles=%d (from 200 values) newRedactor=%v streamer writes=%v close=%v resultText(1MiB)=%v",
			len(red.needles), tBuild, writes, closing, tResult)
		for _, v := range values {
			if strings.Contains(sent, v) {
				t.Fatalf("value leaked in perf run")
			}
		}
		if total := writes + closing; total > time.Second {
			t.Errorf("SLOW: streamer spent %v on 1 MiB (limit ~1s)", total)
		}
		if writes+closing+tResult > time.Second {
			t.Errorf("SLOW: streamer + result redaction for one 1 MiB step = %v", writes+closing+tResult)
		}
	})

	// A value whose prefix equals its suffix, in output that repeats it
	// (e.g. a PIN "00000000" and a run of zeros): split moves the cut back one
	// overlap at a time.
	t.Run("self_overlapping_value_in_repetitive_output", func(t *testing.T) {
		red := newRedactor([]string{"00000000"})
		for _, size := range []int{16 << 10, 32 << 10, 64 << 10, 128 << 10} {
			out := strings.Repeat("0", size)
			done := make(chan struct{})
			var writes, closing time.Duration
			var held int
			go func() {
				defer close(done)
				writes, closing, _, held = timeStream(red, out)
			}()
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				t.Fatalf("SLOW: %d KiB still streaming after 60s", size>>10)
			}
			t.Logf("%4d KiB of '0' in 4 KiB writes: streamer writes=%v close=%v; held back until close=%d bytes",
				size>>10, writes, closing, held)
			if held > red.maxNeedle() {
				t.Errorf("STALL: %d of %d bytes held back (not streamed) until the step ended; hold should be < %d", held, size, red.maxNeedle())
			}
			if writes+closing > time.Second {
				t.Errorf("SLOW: %v for only %d KiB (budget ~1s per MiB)", writes+closing, size>>10)
			}
		}
	})

	// Non-UTF-8 output (binary) with a long run of continuation bytes: split
	// walks the cut back to a rune start that never comes.
	t.Run("binary_continuation_byte_run", func(t *testing.T) {
		red := newRedactor([]string{"hunter2-Secret!"})
		h := newVHarness(t, nil)
		att := h.nextAttempt()
		st := newStreamer(h.a, att)
		st.red = red
		w := st.writer("stdout")
		run := strings.Repeat("\x80", 64<<10)
		for i := 0; i < len(run); i += 4 << 10 {
			w.Write([]byte(run[i : i+4<<10]))
		}
		st.mu.Lock()
		held := len(st.tails["stdout"])
		st.mu.Unlock()
		st.close()
		maxChunk := 0
		for _, c := range h.sink.chunks(att) {
			maxChunk = max(maxChunk, len(c.Data))
		}
		t.Logf("held back until close=%d bytes; largest chunk=%d bytes (MaxChunkBytes=%d)", held, maxChunk, agentapi.MaxChunkBytes)
		if held > red.maxNeedle()+utf8.UTFMax {
			t.Errorf("STALL: %d bytes held back until the step ended", held)
		}
		if maxChunk > agentapi.MaxChunkBytes {
			t.Errorf("CORRUPTION: a %d-byte chunk exceeds MaxChunkBytes; the control plane truncates it to %d and drops the rest", maxChunk, agentapi.MaxChunkBytes)
		}
	})
}
