package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/runbook"
)

// stepVars is the CEL context for a wait step's until condition.
func (a *Agent) stepVars(v *verified, secrets map[string]any) expr.Vars {
	return a.vars(v, secrets, []string{"alert", "incident", "run", "steps"})
}

// inputVars is the context for a step's inputs (aws input, env, files) and
// its outputs, which later steps' inputs can use. It
// leaves out alert and incident data: they're shaped by whoever publishes the
// alert and arrive in the envelope unvalidated, while parameters derived from
// them are checked against the runbook's patterns (ValidateParams). The
// linter refuses runbooks that use them there; this holds even for a bundle
// that skipped the linter.
func (a *Agent) inputVars(v *verified, secrets map[string]any) expr.Vars {
	return a.vars(v, secrets, []string{"run", "steps"})
}

func (a *Agent) vars(v *verified, secrets map[string]any, context []string) expr.Vars {
	vars := expr.Vars{"params": v.env.Params, "target": a.id.Labels}
	for _, k := range context {
		if x, ok := v.env.Context[k]; ok {
			vars[k] = x
		}
	}
	if secrets != nil {
		vars["secrets"] = secrets
	}
	return vars
}

// execute runs one step and returns its result. Output is streamed as it's
// produced, redacted first.
func (a *Agent) execute(ctx context.Context, v *verified) agentapi.Result {
	out := newStreamer(a, v.env.AttemptID)
	defer out.close()

	secrets, values, err := a.resolveSecrets(ctx, v)
	if err != nil {
		return agentapi.Result{Status: "failed", Error: err.Error()}
	}
	out.red, out.secretValues = newRedactor(values), values

	var res agentapi.Result
	var result map[string]any
	switch v.step.Type {
	case "aws":
		result, err = a.runAWS(ctx, v, out)
	case "wait":
		result, err = a.runWait(ctx, v, out)
	case "shell":
		result, res.ExitCode, err = a.runShell(ctx, v, secrets, out)
	default:
		err = fmt.Errorf("step type %q is not supported by this agent", v.step.Type)
	}

	// A response that carries secret material is redacted like a resolved
	// secret, whatever the step does with it.
	if m := secretMaterial(v.step, result); len(m) > 0 {
		out.red = newRedactor(append(values, m...))
	}

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status = "timed_out"
		res.Error = "step exceeded its timeout of " + v.step.StepTimeout().String()
		var wt waitTimeout
		if errors.As(err, &wt) && wt.last != nil {
			res.Error += "; last check: " + out.red.apply(wt.last.Error())
		}
	case errors.Is(ctx.Err(), context.Canceled):
		res.Status = "cancelled"
		res.Error = "cancelled by the control plane"
		if a.isStopping() {
			res.Error = "the agent shut down before the step finished"
		}
	case err != nil:
		res.Status = "failed"
		res.Error = out.red.apply(err.Error())
	default:
		res.Status = "succeeded"
	}
	if res.Status == "succeeded" && len(v.step.Outputs) > 0 {
		// Outputs never see secrets, nor alert data: they feed later steps'
		// inputs, which mustn't carry unvalidated alert values.
		vars := a.inputVars(v, nil)
		vars["result"] = result
		res.Outputs = map[string]any{}
		for name, src := range v.step.Outputs {
			val, err := expr.Eval(src, vars)
			if err != nil {
				res.Status, res.Error = "failed", out.red.apply(fmt.Sprintf("output %s: %v", name, err))
				break
			}
			res.Outputs[name] = out.red.redactAny(val)
		}
	}
	// The control plane accepts results up to 4 MiB of JSON. A result over
	// that was refused and dropped, and the step ended up "lost"; fail it
	// with a clear reason instead.
	if b, err := json.Marshal(res.Outputs); err == nil && len(b) > maxOutputsBytes {
		res.Status, res.Outputs = "failed", nil
		res.Error = fmt.Sprintf("step outputs are %d bytes of JSON; the limit is %d (output less, or extract fields)", len(b), maxOutputsBytes)
	}
	res.Error = truncateUTF8(res.Error, maxErrorBytes)
	return res
}

// Result size limits, well under the control plane's 4 MiB request limit.
const (
	maxOutputsBytes = 1 << 20
	maxErrorBytes   = 16 << 10
)

// secretMaterial returns the secret values in an AWS response.
func secretMaterial(step runbook.Step, res map[string]any) []string {
	service, action := step.Service, step.Action
	if step.Type == "wait" && step.Check != nil && step.Check.AWS != nil {
		service, action = step.Check.AWS.Service, step.Check.AWS.Action
	}
	var out []string
	str := func(m any, k string) {
		if mm, ok := m.(map[string]any); ok {
			if s, ok := mm[k].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	// A blob is base64 on the wire; an output can decode it
	// (base64.decode(result.Plaintext)), so the raw bytes are secret too.
	blob := func(m any, k string) {
		if mm, ok := m.(map[string]any); ok {
			if s, ok := mm[k].(string); ok && s != "" {
				out = append(out, s)
				if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
					out = append(out, string(b))
				}
			}
		}
	}
	param := func(p any) {
		if mm, ok := p.(map[string]any); ok && mm["Type"] == "SecureString" {
			str(mm, "Value")
		}
	}
	list := func(k string, fn func(any)) {
		if l, ok := res[k].([]any); ok {
			for _, e := range l {
				fn(e)
			}
		}
	}
	// AWS matches operation names exactly, but compare without case anyway:
	// a miss here would publish a secret.
	switch strings.ToLower(service + ":" + action) {
	case "secretsmanager:getsecretvalue":
		str(res, "SecretString")
		blob(res, "SecretBinary")
	case "secretsmanager:batchgetsecretvalue":
		list("SecretValues", func(e any) { str(e, "SecretString"); blob(e, "SecretBinary") })
	case "secretsmanager:getrandompassword":
		str(res, "RandomPassword")
	case "ssm:getparameter":
		param(res["Parameter"])
	case "ssm:getparameters", "ssm:getparametersbypath", "ssm:getparameterhistory":
		list("Parameters", param)
	case "kms:decrypt", "kms:generatedatakey", "kms:generaterandom":
		blob(res, "Plaintext")
	case "kms:generatedatakeypair":
		blob(res, "PrivateKeyPlaintext")
	case "kms:derivesharedsecret":
		blob(res, "SharedSecret")
	}
	return out
}

func (a *Agent) resolveSecrets(ctx context.Context, v *verified) (map[string]any, []string, error) {
	used := runbook.SecretsUsed(v.step)
	if len(used) == 0 {
		return nil, nil, nil
	}
	if a.cfg.AWS == nil {
		return nil, nil, errors.New("no AWS client configured for secret resolution")
	}
	secrets := map[string]any{}
	var values []string
	for _, name := range used {
		ref, ok := v.rb.Spec.Secrets[name]
		if !ok {
			return nil, nil, fmt.Errorf("secret %q is not declared", name)
		}
		val, err := a.fetchSecret(ctx, ref)
		if err != nil {
			return nil, nil, fmt.Errorf("secret %s: %w", name, err)
		}
		secrets[name] = val
		values = append(values, val)
	}
	return secrets, values, nil
}

func (a *Agent) fetchSecret(ctx context.Context, ref runbook.SecretRef) (string, error) {
	provider, name, err := runbook.ParseSecretRef(ref.Ref)
	if err != nil {
		return "", err
	}
	switch provider {
	case "aws-sm":
		resp, err := a.cfg.AWS.Call(ctx, "secretsmanager", "GetSecretValue", map[string]any{"SecretId": name})
		if err != nil {
			return "", err
		}
		s, _ := resp["SecretString"].(string)
		if ref.Key == "" {
			return s, nil
		}
		var m map[string]any
		if err := jsonUnmarshal([]byte(s), &m); err != nil {
			return "", fmt.Errorf("secret is not JSON, so key %q can't be selected", ref.Key)
		}
		v, ok := m[ref.Key].(string)
		if !ok {
			return "", fmt.Errorf("secret has no string key %q", ref.Key)
		}
		return v, nil
	case "aws-ssm":
		resp, err := a.cfg.AWS.Call(ctx, "ssm", "GetParameter", map[string]any{"Name": "/" + strings.TrimPrefix(name, "/"), "WithDecryption": true})
		if err != nil {
			return "", err
		}
		p, _ := resp["Parameter"].(map[string]any)
		s, _ := p["Value"].(string)
		return s, nil
	}
	return "", fmt.Errorf("unsupported secret provider %q", provider)
}

func (a *Agent) renderInput(v *verified, input map[string]any) (map[string]any, error) {
	r, err := expr.Render(input, a.inputVars(v, nil))
	if err != nil {
		return nil, err
	}
	m, _ := r.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func (a *Agent) runAWS(ctx context.Context, v *verified, out *streamer) (map[string]any, error) {
	if a.cfg.AWS == nil {
		return nil, errors.New("no AWS client configured")
	}
	if v.step.AssumeRole != "" {
		return nil, errors.New("assumeRole is not supported in this build")
	}
	input, err := a.renderInput(v, v.step.Input)
	if err != nil {
		return nil, err
	}
	out.log(fmt.Sprintf("calling %s:%s", v.step.Service, v.step.Action))
	var res map[string]any
	for i, backoff := 0, time.Second; ; i, backoff = i+1, backoff*2 {
		res, err = a.cfg.AWS.Call(ctx, v.step.Service, v.step.Action, input)
		// Throttling is likely during an incident, and a throttled call
		// wasn't performed, so retrying it is safe even for a change. A
		// server error might have been performed, so it isn't retried.
		var ae *awscall.Error
		if err == nil || !errors.As(err, &ae) || !ae.Throttled() || i >= 4 || ctx.Err() != nil {
			break
		}
		out.log(fmt.Sprintf("%s:%s throttled (%s); retrying", v.step.Service, v.step.Action, ae.Code))
		select {
		case <-ctx.Done():
		case <-time.After(jitter(backoff)):
		}
	}
	if err != nil {
		return nil, err
	}
	out.log(fmt.Sprintf("%s:%s succeeded", v.step.Service, v.step.Action))
	return res, nil
}

func (a *Agent) runWait(ctx context.Context, v *verified, out *streamer) (map[string]any, error) {
	if v.step.Check == nil || v.step.Check.AWS == nil {
		return nil, errors.New("only aws checks are supported in this build")
	}
	if a.cfg.AWS == nil {
		return nil, errors.New("no AWS client configured")
	}
	c := v.step.Check.AWS
	input, err := a.renderInput(v, c.Input)
	if err != nil {
		return nil, err
	}
	var last error // the latest check problem, for the timeout's message
	for i := 1; ; i++ {
		res, err := a.cfg.AWS.Call(ctx, c.Service, c.Action, input)
		if err != nil {
			if ctx.Err() != nil {
				return nil, waitTimeout{ctx.Err(), last}
			}
			out.log(fmt.Sprintf("check %d: %v", i, err))
			// A check that can never succeed (access denied, no such
			// cluster, invalid input) fails the step now, rather than
			// polling out the whole timeout and reporting "timed out".
			var ae *awscall.Error
			if errors.As(err, &ae) && !ae.Retryable() {
				return nil, fmt.Errorf("check %d: %w", i, err)
			}
			last = err
		} else {
			// Secret material in the response (a SecureString, a decrypted
			// key) must be redacted from this check's log lines too: an until
			// error can quote values from the result.
			if m := secretMaterial(v.step, res); len(m) > 0 {
				out.addSecretMaterial(m)
			}
			vars := a.stepVars(v, nil)
			vars["result"] = res
			done, err := expr.EvalBool(v.step.Until, vars)
			if err != nil {
				out.log(fmt.Sprintf("check %d: until: %v", i, err))
				last = fmt.Errorf("until: %w", err)
			} else if done {
				out.log(fmt.Sprintf("check %d: condition met", i))
				return res, nil
			} else {
				out.log(fmt.Sprintf("check %d: not yet", i))
			}
		}
		select {
		case <-ctx.Done():
			return nil, waitTimeout{ctx.Err(), last}
		case <-time.After(v.step.WaitInterval()):
		}
	}
}

// waitTimeout is a wait step's context error with its last check problem,
// so a timeout says why the condition was never met.
type waitTimeout struct{ ctx, last error }

func (w waitTimeout) Error() string {
	if w.last == nil {
		return w.ctx.Error()
	}
	return w.ctx.Error() + "; last check: " + w.last.Error()
}
func (w waitTimeout) Unwrap() error { return w.ctx }

func (a *Agent) runShell(ctx context.Context, v *verified, secrets map[string]any, out *streamer) (map[string]any, *int, error) {
	vars := a.inputVars(v, secrets)
	dir, err := os.MkdirTemp("", "nfx-step-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	// A minimal environment: nothing from the agent's own environment except
	// what a script needs to find programs. Values arrive only through env.
	env := []string{"PATH=" + envOr("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME=" + dir, "TMPDIR=" + dir, "LANG=C.UTF-8"}
	for k, tmpl := range v.step.Env {
		if runbook.ReservedEnv(k) { // also refused at publish; checked again here
			return nil, nil, fmt.Errorf("env %s is reserved", k)
		}
		val, err := expr.RenderString(tmpl, vars)
		if err != nil {
			return nil, nil, fmt.Errorf("env %s: %w", k, err)
		}
		env = append(env, k+"="+fmt.Sprint(val))
	}
	for name, tmpl := range v.step.Files {
		val, err := expr.RenderString(tmpl, vars)
		if err != nil {
			return nil, nil, fmt.Errorf("file %s: %w", name, err)
		}
		p := filepath.Join(dir, filepath.Clean("/"+name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(p, []byte(fmt.Sprint(val)), 0o600); err != nil {
			return nil, nil, err
		}
	}

	cmd := exec.Command("bash", "-euo", "pipefail", "-c", v.step.Run)
	cmd.Dir, cmd.Env = dir, env
	// Own process group so timeouts kill the whole tree; Pdeathsig so the
	// script dies with the agent instead of running on unobserved.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	// A background child can keep stdout open after bash exits; without a
	// WaitDelay, Wait would block until the step timeout (or forever if the
	// child escaped the process group).
	cmd.WaitDelay = 2 * time.Second
	// The result buffers keep a little extra so a secret cut by the 1 MiB
	// limit is still redacted before the buffer is trimmed to the limit.
	extra := out.red.maxNeedle()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = io.MultiWriter(&limited{w: &stdout, n: agentapi.MaxOutputBytes + extra}, out.writer("stdout"))
	cmd.Stderr = io.MultiWriter(&limited{w: &stderr, n: agentapi.MaxOutputBytes + extra}, out.writer("stderr"))
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		// SIGTERM the whole process group, then SIGKILL after 10s.
		syscall.Kill(-pgid, syscall.SIGTERM)
		select {
		case waitErr = <-done:
		case <-time.After(10 * time.Second):
			syscall.Kill(-pgid, syscall.SIGKILL)
			select {
			case waitErr = <-done:
			case <-time.After(10 * time.Second):
				waitErr = errors.New("script did not exit after SIGKILL")
			}
		}
	}
	// Nothing a step started may outlive it: it would run unobserved, with
	// no timeout, holding the step's temp dir and secret files.
	syscall.Kill(-pgid, syscall.SIGKILL)
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	result := map[string]any{
		"exitCode": code,
		"stdout":   resultText(out.red, stdout.String()),
		"stderr":   resultText(out.red, stderr.String()),
	}
	if ctx.Err() != nil {
		return result, &code, ctx.Err()
	}
	if waitErr != nil && !errors.Is(waitErr, exec.ErrWaitDelay) {
		return result, &code, fmt.Errorf("script exited with code %d", code)
	}
	if code != 0 {
		return result, &code, fmt.Errorf("script exited with code %d", code)
	}
	return result, &code, nil
}

// resultText redacts captured output and trims it to MaxOutputBytes. When the
// capture was cut off, its last bytes may be the start of a secret that no
// longer matches whole, so they're dropped (split) rather than kept. Redacting
// first and then trimming isn't enough: replacements shorten the text, which
// would pull a partial secret from past the cut back under the limit.
func resultText(red *redactor, raw string) string {
	if len(raw) > agentapi.MaxOutputBytes {
		raw, _ = red.split(raw)
	} else {
		raw = red.apply(raw)
	}
	return truncateUTF8(raw, agentapi.MaxOutputBytes)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	l.w.Write(q)
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Output streaming
// ---------------------------------------------------------------------------

// streamer batches redacted output and sends it to the control plane.
type streamer struct {
	a       *Agent
	attempt string
	red     *redactor
	// secretValues are what red redacts: the step's resolved secrets, plus
	// secret material from AWS responses as it arrives.
	secretValues []string

	mu        sync.Mutex
	seq       int
	attempted int // highest seq handed to an upload; those chunks are never changed
	pending   []agentapi.OutputChunk
	tails     map[string]string // per stream: raw bytes held back in case a secret continues in the next write
	states    map[string]*scanState
	sent      int // bytes queued for upload so far (the per-attempt cap)
	truncated bool
	done      chan struct{}
	wg        sync.WaitGroup
}

// truncatedMarker is appended once when an attempt's output exceeds the cap.
const truncatedMarker = "\n[output truncated: limit reached]\n"

func newStreamer(a *Agent, attempt string) *streamer {
	s := &streamer{a: a, attempt: attempt, red: newRedactor(nil), tails: map[string]string{}, states: map[string]*scanState{}, done: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				s.flush()
				return
			case <-t.C:
				s.flush()
			}
		}
	}()
	return s
}

// addSecretMaterial adds values to what is redacted from now on.
func (s *streamer) addSecretMaterial(m []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secretValues = append(s.secretValues, m...)
	s.red = newRedactor(s.secretValues)
}

// add redacts data and queues it in chunks of at most MaxChunkBytes, stopping
// at MaxOutputBytes per attempt with a single truncation marker.
func (s *streamer) add(stream, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(stream, s.red.apply(data))
}

func (s *streamer) addLocked(stream, data string) {
	if s.truncated {
		return
	}
	// Measured as it will arrive: JSON carries invalid UTF-8 as U+FFFD (three
	// bytes for one), so binary output sized before that would exceed
	// MaxChunkBytes on arrival and be cut by the control plane.
	// The control plane also replaces NUL (Postgres text can't hold it).
	data = strings.ReplaceAll(strings.ToValidUTF8(data, "\uFFFD"), "\x00", "\uFFFD")
	if room := agentapi.MaxOutputBytes - s.sent; len(data) > room {
		data = truncateUTF8(data, room)
		s.truncated = true
	}
	for len(data) > 0 {
		piece := truncateUTF8(data, agentapi.MaxChunkBytes)
		if piece == "" { // binary output: no character boundary near the limit
			piece = data[:min(len(data), agentapi.MaxChunkBytes)]
		}
		data = data[len(piece):]
		s.sent += len(piece)
		// Coalesce with the last chunk if no upload has carried it yet, so a
		// step that writes a byte at a time doesn't become a row per byte.
		// (One that has may already be stored, and resends are deduped by
		// seq, so it must stay as it was.)
		if n := len(s.pending); n > 0 && s.pending[n-1].Seq > s.attempted && s.pending[n-1].Stream == stream &&
			len(s.pending[n-1].Data)+len(piece) <= agentapi.MaxChunkBytes {
			s.pending[n-1].Data += piece
			continue
		}
		s.seq++
		s.pending = append(s.pending, agentapi.OutputChunk{Seq: s.seq, Stream: stream, Data: piece})
	}
	if s.truncated {
		s.seq++
		s.pending = append(s.pending, agentapi.OutputChunk{Seq: s.seq, Stream: "log", Data: truncatedMarker})
	}
}

// truncateUTF8 returns the longest prefix of s that is at most n bytes and
// doesn't end inside a multi-byte rune.
func truncateUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	// Back off at most one character's worth; past that it isn't UTF-8
	// (binary output), so cut where asked.
	for k, m := 0, n; k < utf8.UTFMax && m > 0; k, m = k+1, m-1 {
		if utf8.RuneStart(s[m]) {
			return s[:m]
		}
	}
	return s[:n]
}

// log records an executor message (not process output).
func (s *streamer) log(msg string) { s.add("log", msg+"\n") }

type streamWriter struct {
	s      *streamer
	stream string
}

// Write redacts everything that can no longer be part of a secret and holds
// back the rest. A secret can be split across writes, contain newlines, or
// sit inside a very long line, so the only safe boundary is "fewer bytes
// remain than the longest needle" — never a newline or a fixed cut.
func (w streamWriter) Write(p []byte) (int, error) {
	s := w.s
	s.mu.Lock()
	defer s.mu.Unlock()
	emit, keep := s.red.scan(s.state(w.stream), s.tails[w.stream]+string(p), false)
	s.tails[w.stream] = keep
	if emit != "" {
		s.addLocked(w.stream, emit)
	}
	return len(p), nil
}

func (s *streamer) writer(stream string) io.Writer { return streamWriter{s, stream} }

func (s *streamer) state(stream string) *scanState {
	st := s.states[stream]
	if st == nil {
		st = &scanState{}
		s.states[stream] = st
	}
	return st
}

func (s *streamer) flush() {
	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.attempted = s.seq
	s.mu.Unlock()
	for len(batch) > 0 {
		// Batches are sized by their encoded size, not chunk count: binary
		// output JSON-escapes to up to 6 bytes a byte, and the gateway
		// refuses bodies over 4 MiB.
		n, size := 0, 0
		for n < len(batch) && n < 64 {
			b, _ := json.Marshal(batch[n])
			if n > 0 && size+len(b) > maxOutputBatchBytes {
				break
			}
			size += len(b)
			n++
		}
		err := s.a.c.post(context.Background(), "/agent/v1/attempts/"+s.attempt+"/output", agentapi.OutputBatch{Chunks: batch[:n]}, nil)
		var se *statusError
		if err != nil && errors.As(err, &se) && se.Code/100 == 4 && se.Code != 408 && se.Code != 429 {
			// Refused: sending it again can't help, so don't hold up the
			// step's result behind it.
			s.a.cfg.Log.Warn("output refused; dropping it", "attempt", s.attempt, "chunks", n, "err", err)
			batch = batch[n:]
			continue
		}
		if err != nil {
			s.a.cfg.Log.Warn("output upload failed; will retry", "attempt", s.attempt, "err", err)
			s.mu.Lock()
			s.pending = append(batch, s.pending...)
			s.mu.Unlock()
			return
		}
		batch = batch[n:]
	}
}

// maxOutputBatchBytes keeps an output request well under the gateway's
// 4 MiB body limit.
const maxOutputBatchBytes = 1 << 20

func (s *streamer) close() {
	s.mu.Lock()
	for _, stream := range []string{"stdout", "stderr"} {
		if t := s.tails[stream]; t != "" {
			if emit, _ := s.red.scan(s.state(stream), t, true); emit != "" {
				s.addLocked(stream, emit)
			}
		}
	}
	s.tails = map[string]string{}
	s.mu.Unlock()
	close(s.done)
	s.wg.Wait()
	// The final flush failed (the control plane unreachable as the step
	// ended): keep trying for a while, before the result goes, so the
	// output isn't lost (agent-protocol.md §7.1).
	backoff := 500 * time.Millisecond
	for deadline := time.Now().Add(outputRetryFor); s.hasPending() && time.Now().Before(deadline); {
		time.Sleep(jitter(backoff))
		backoff = min(backoff*2, 10*time.Second)
		s.flush()
	}
}

// outputRetryFor bounds how long a finished step's output is retried before
// its result is sent anyway (the result itself is retried much longer).
var outputRetryFor = 2 * time.Minute

func (s *streamer) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0
}
