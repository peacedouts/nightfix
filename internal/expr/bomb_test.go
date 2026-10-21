package expr

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Expressions are written by runbook authors (any responder) and admins
// (routing rules), and evaluated on the shared control plane and on agents
// with variables that can be large (step output up to 1 MiB). No expression
// may run long or allocate far more than its inputs, whatever its shape.
// Each case must finish (pass or fail) within maxEvalTime plus slack, and
// stay under a memory ceiling.
func TestEvaluationIsBounded(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	items := make([]any, 200_000)
	for i := range items {
		items[i] = i
	}
	vars := Vars{"result": map[string]any{"stdout": big, "items": items}}
	cases := map[string]string{
		"repeated concat":       strings.TrimSuffix(strings.Repeat("result.stdout + ", 250), " + ") + ` == ""`,
		"concat in macro":       `result.items.map(i, result.stdout + result.stdout).size() > 0`,
		"split in macro":        `result.items.map(i, result.stdout.split("")).size() > 0`,
		"big comprehension":     `result.items.map(i, i + 1).size() > 0`,
		"nested comprehension":  `result.items.all(i, result.items.exists(j, j == -1))`,
		"filter big":            `result.items.filter(i, string(i).contains("9")).size() > 0`,
		"base64 chain":          `base64.encode(bytes(base64.encode(bytes(base64.encode(bytes(result.stdout)))))) == ""`,
		"list concat":           `(result.items + result.items + result.items + result.items + result.items + result.items + result.items + result.items).size() > 0`,
		"equality of big lists": `result.items + result.items == result.items + result.items`,
	}
	for name, src := range cases {
		if only := os.Getenv("BOMB"); only != "" && only != name {
			continue
		}
		if err := Check(src); err != nil {
			t.Logf("%-22s refused at compile time: %v", name, short(err))
			continue
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, err := Eval(src, vars)
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		alloc := (after.TotalAlloc - before.TotalAlloc) >> 20
		t.Logf("%-22s %8v alloc=%4d MiB err=%v", name, d.Round(time.Millisecond), alloc, short(err))
		if d > maxEvalTime+500*time.Millisecond+raceSlack {
			t.Errorf("%s ran %v", name, d)
		}
		if alloc > 512 {
			t.Errorf("%s allocated %d MiB", name, alloc)
		}
	}
}

func short(err error) string {
	if err == nil {
		return "<nil>"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}
