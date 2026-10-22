package controlplane

import "testing"

// Severities rank critical > high > warning > info; anything else ranks below
// all of them, so it can never raise an incident. (Normalization maps unknown
// severities to high before an alert is stored.)
func TestSeverityRank(t *testing.T) {
	order := []string{"", "bogus", "info", "warning", "high", "critical"}
	for i := 1; i < len(order); i++ {
		lo, hi := order[i-1], order[i]
		if lo == "" { // "" and "bogus" are both unknown
			if severityRank(lo) != severityRank(hi) {
				t.Errorf("unknown severities %q and %q rank differently", lo, hi)
			}
			continue
		}
		if severityRank(lo) >= severityRank(hi) {
			t.Errorf("severityRank(%q)=%d should be below severityRank(%q)=%d", lo, severityRank(lo), hi, severityRank(hi))
		}
	}
	if severityRank("Critical") != severityRank("bogus") {
		t.Error("severities are lowercase; Critical is unknown")
	}
	for sev := range validSeverity {
		if severityRank(sev) == 0 {
			t.Errorf("valid severity %q ranks as unknown", sev)
		}
	}
}
