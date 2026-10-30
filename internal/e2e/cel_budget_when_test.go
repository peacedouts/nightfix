package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The per-event CEL budget (celBudgetPerEvent, 1s) covers routing rules and
// trigger matches, but an auto-run started for the event evaluates its steps'
// `when` conditions in advance(), inside the same alert-processing
// transaction, with only the 250ms per-expression limit. A runbook of 100
// note steps whose `when` takes ~130ms and is false holds the instance's
// single alert loop for ~13s per alert event (and the run then succeeds at
// once, so concurrency doesn't stop the next event).
func TestStepWhenEscapesPerEventCELBudget(t *testing.T) {
	l := "[" + strings.TrimSuffix(strings.Repeat("1,", 40), ",") + "]"
	slowFalse := fmt.Sprintf("!%s.all(a, %s.all(b, %s.all(c, a + b + c > 0)))", l, l, l)
	var steps strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&steps, "    - id: n%d\n      type: note\n      when: '%s'\n      markdown: hi\n", i, slowFalse)
	}
	rb := autoRunbook{Name: "orders-slow-when", Selector: "prod", BeforePaging: false, Cooldown: "1s", Steps: steps.String()}
	g := setupGuard(t, nil, rb)
	var pub map[string]any
	if code := g.callRaw("GET", "/v1/runbooks/orders-slow-when", nil, &pub); code != 200 {
		t.Fatalf("runbook not published: %d %v", code, pub)
	}
	start := time.Now()
	g.fire("slow-when-1", "high", ordersSvc)
	var took time.Duration
	for time.Since(start) < 60*time.Second {
		if inc := g.incident(1); inc != nil {
			took = time.Since(start)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("incident for the alert visible after %v; runs: %+v", took.Round(time.Millisecond), g.runs())
	if took == 0 || took > 3*time.Second {
		t.Errorf("one alert event held the alert loop (its processing transaction) for %v; the per-event CEL budget is %v", took.Round(time.Millisecond), time.Second)
	}
}
