package agent

import (
	"bytes"
	"context"
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

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/expr"
	"github.com/peacedouts/nightfix/internal/runbook"
)

// stepVars is the CEL context a step sees on the agent.
func (a *Agent) stepVars(v *verified, secrets map[string]any) expr.Vars {
	vars := expr.Vars{"params": v.env.Params, "target": a.id.Labels}
	for _, k := range []string{"alert", "incident", "run", "steps"} {
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
	out.red = newRedactor(values)

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

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status = "timed_out"
		res.Error = "step exceeded its timeout of " + v.step.StepTimeout().String()
	case errors.Is(ctx.Err(), context.Canceled):
		res.Status = "cancelled"
		res.Error = "cancelled by the control plane"
	case err != nil:
		res.Status = "failed"
		res.Error = out.red.apply(err.Error())
	default:
		res.Status = "succeeded"
	}
	if res.Status == "succeeded" && len(v.step.Outputs) > 0 {
		vars := a.stepVars(v, nil) // outputs never see secrets
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
	return res
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
	r, err := expr.Render(input, a.stepVars(v, nil))
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
	res, err := a.cfg.AWS.Call(ctx, v.step.Service, v.step.Action, input)
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
	for i := 1; ; i++ {
		res, err := a.cfg.AWS.Call(ctx, c.Service, c.Action, input)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			out.log(fmt.Sprintf("check %d: %v", i, err))
		} else {
			vars := a.stepVars(v, nil)
			vars["result"] = res
			done, err := expr.EvalBool(v.step.Until, vars)
			if err != nil {
				out.log(fmt.Sprintf("check %d: until: %v", i, err))
			} else if done {
				out.log(fmt.Sprintf("check %d: condition met", i))
				return res, nil
			} else {
				out.log(fmt.Sprintf("check %d: not yet", i))
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(v.step.WaitInterval()):
		}
	}
}

func (a *Agent) runShell(ctx context.Context, v *verified, secrets map[string]any, out *streamer) (map[string]any, *int, error) {
	vars := a.stepVars(v, secrets)
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
		"stdout":   truncateUTF8(out.red.apply(stdout.String()), agentapi.MaxOutputBytes),
		"stderr":   truncateUTF8(out.red.apply(stderr.String()), agentapi.MaxOutputBytes),
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

	mu        sync.Mutex
	seq       int
	pending   []agentapi.OutputChunk
	tails     map[string]string // per stream: raw bytes held back in case a secret continues in the next write
	sent      int               // bytes queued for upload so far (the per-attempt cap)
	truncated bool
	done      chan struct{}
	wg        sync.WaitGroup
}

// truncatedMarker is appended once when an attempt's output exceeds the cap.
const truncatedMarker = "\n[output truncated: limit reached]\n"

func newStreamer(a *Agent, attempt string) *streamer {
	s := &streamer{a: a, attempt: attempt, red: newRedactor(nil), tails: map[string]string{}, done: make(chan struct{})}
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
	if room := agentapi.MaxOutputBytes - s.sent; len(data) > room {
		data = truncateUTF8(data, room)
		s.truncated = true
	}
	for len(data) > 0 {
		piece := truncateUTF8(data, agentapi.MaxChunkBytes)
		if piece == "" { // a single rune larger than the chunk size can't happen, but never loop forever
			piece = data
		}
		data = data[len(piece):]
		s.sent += len(piece)
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
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
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
	emit, keep := s.red.split(s.tails[w.stream] + string(p))
	s.tails[w.stream] = keep
	if emit != "" {
		s.addLocked(w.stream, emit)
	}
	return len(p), nil
}

func (s *streamer) writer(stream string) io.Writer { return streamWriter{s, stream} }

func (s *streamer) flush() {
	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()
	for len(batch) > 0 {
		n := min(len(batch), 64)
		err := s.a.c.post(context.Background(), "/agent/v1/attempts/"+s.attempt+"/output", agentapi.OutputBatch{Chunks: batch[:n]}, nil)
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

func (s *streamer) close() {
	s.mu.Lock()
	tails := s.tails
	s.tails = map[string]string{}
	s.mu.Unlock()
	for _, stream := range []string{"stdout", "stderr"} {
		if t := tails[stream]; t != "" {
			s.add(stream, t)
		}
	}
	close(s.done)
	s.wg.Wait()
}
