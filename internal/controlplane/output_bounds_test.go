package controlplane

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/agentapi"
	"github.com/peacedouts/nightfix/internal/db"
)

// An agent can't grow an attempt's output without bound: empty chunks
// aren't stored, rows are capped as well as bytes, and once an attempt has
// been finished for a while its output is settled.
func TestOutputRowsAndLateOutputAreBounded(t *testing.T) {
	e := setupRunHarness(t)
	ctx := context.Background()
	defer func(n int) { maxOutputChunks = n }(maxOutputChunks)
	maxOutputChunks = 200
	e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n")
	id := e.poll()
	e.ack(id)
	count := func() (n int) {
		e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM step_output_chunks WHERE attempt_id = $1`, id).Scan(&n)
		})
		return n
	}

	empty := make([]agentapi.OutputChunk, 1000)
	for i := range empty {
		empty[i] = agentapi.OutputChunk{Seq: i + 1, Stream: "stdout"}
	}
	if err := e.s.Output(ctx, e.a, id, agentapi.OutputBatch{Chunks: empty}); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("stored %d empty chunks", n)
	}

	tiny := make([]agentapi.OutputChunk, maxOutputChunks+500)
	for i := range tiny {
		tiny[i] = agentapi.OutputChunk{Seq: 10_000 + i, Stream: "stdout", Data: "."}
	}
	if err := e.s.Output(ctx, e.a, id, agentapi.OutputBatch{Chunks: tiny}); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != maxOutputChunks {
		t.Fatalf("stored %d one-byte chunks, want the cap of %d", n, maxOutputChunks)
	}
	var last string
	e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		return tx.QueryRow(`SELECT data FROM step_output_chunks WHERE attempt_id = $1 ORDER BY seq DESC LIMIT 1`, id).Scan(&last)
	})
	if last != "\n[output truncated: too many chunks]\n" {
		t.Fatalf("last row %q, want the truncation marker", last)
	}

	// Finished: output is still taken during the grace period (a cancelled
	// step's last lines), and refused after it. (A fresh attempt: the one
	// above is at its row cap.)
	if err := e.s.Result(ctx, e.a, id, agentapi.Result{Status: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	e.startRun("    - id: s1\n      type: shell\n      run: echo hi\n")
	id = e.poll()
	e.ack(id)
	if err := e.s.Result(ctx, e.a, id, agentapi.Result{Status: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	late := agentapi.OutputBatch{Chunks: []agentapi.OutputChunk{{Seq: 1, Stream: "stdout", Data: "last line\n"}}}
	if err := e.s.Output(ctx, e.a, id, late); err != nil {
		t.Fatalf("output just after the result: %v", err)
	}
	e.s.DB.WithOrg(ctx, e.a.OrgID, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE step_attempts SET finished_at = now() - interval '1 hour' WHERE id = $1`, id)
		return err
	})
	late.Chunks[0].Seq = 2
	err := e.s.Output(ctx, e.a, id, late)
	if he, ok := err.(httpError); !ok || he.code != 409 {
		t.Fatalf("output an hour after the result: %v, want 409", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("stored %d chunks after the result, want 1", n)
	}
}

// The gateway's certificate is reissued before it expires, without a
// restart.
func TestGatewayCertificateIsReissued(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sc := &serverCert{ca: ca, hosts: []string{"gw.example.com"}}
	now := time.Now()
	if err := sc.issue(now); err != nil {
		t.Fatal(err)
	}
	first := sc.get(now)
	if sc.get(now.Add(serverCertLifetime/4)) != first {
		t.Fatal("reissued early")
	}
	later := now.Add(serverCertLifetime * 3 / 4)
	second := sc.get(later)
	if second == first {
		t.Fatal("not reissued past half its life")
	}
	leaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.After(later.Add(serverCertLifetime/2)) || leaf.VerifyHostname("gw.example.com") != nil {
		t.Fatalf("reissued certificate: until %v, hosts %v", leaf.NotAfter, leaf.DNSNames)
	}
}
