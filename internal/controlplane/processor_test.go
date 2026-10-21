package controlplane

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lib/pq"
)

func TestIsTransient(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{context.Canceled, true},
		{fmt.Errorf("wrapped: %w", driver.ErrBadConn), true},
		{&pq.Error{Code: "40P01"}, true},         // deadlock
		{&pq.Error{Code: "08006"}, true},         // connection failure
		{&pq.Error{Code: "23505"}, false},        // unique violation
		{&pq.Error{Code: "22021"}, false},        // invalid byte sequence
		{errors.New("some bug"), false},          // retrying won't help
		{processError{errors.New("bad")}, false}, // malformed payload
	}
	for _, c := range cases {
		if got := isTransient(c.err); got != c.want {
			t.Errorf("isTransient(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestSanitizeAlert(t *testing.T) {
	a := sanitizeAlert(Alert{
		Summary: "a\x00b\xffc",
		Labels:  map[string]string{"k\x00": "v\x00"},
	})
	if a.Summary != "ab�c" || a.Labels["k"] != "v" {
		t.Fatalf("got %q %v", a.Summary, a.Labels)
	}
	s := truncate(strings.Repeat("a", 299)+"é", 300)
	if !utf8.ValidString(s) || len(s) != 299 {
		t.Fatalf("truncate split a rune: %q", s)
	}
}

// Alert summaries, run errors and comments are untrusted; Slack must not
// treat them as mentions or links.
func TestSlackMessagesEscapeUntrustedText(t *testing.T) {
	evil := "disk full <!channel> <https://evil.example/login|Open runbook> <@U012ADMIN> & more"
	check := func(name, s string) {
		t.Helper()
		for _, bad := range []string{"<!channel>", "<https://evil", "<@U012ADMIN>"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: %q passed through unescaped: %s", name, bad, s)
			}
		}
		if !strings.Contains(s, "&lt;!channel&gt;") || !strings.Contains(s, "&amp; more") {
			t.Errorf("%s: not escaped as Slack expects: %s", name, s)
		}
	}
	page := slackText("page", map[string]any{"incident_number": 7, "title": evil, "service": "checkout-api", "severity": "warning", "reason": "x"})
	check("page", page)
	if !strings.Contains(page, "<!here>") {
		t.Error("the page's own <!here> was escaped")
	}
	check("update", slackText("update", map[string]any{"incident_number": 7, "service": "svc", "reason": "Run failed: " + evil}))
	check("no incident", slackText("update", map[string]any{"reason": evil}))
	msg := slackApprovalMessage(map[string]any{"incident_number": 7, "service": "svc", "reason": evil,
		"approval": map[string]any{"interactive": true, "gate": "apr_x", "runbook": "rb", "step_name": evil}})
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // see the text exactly as Slack will
	enc.Encode(msg)
	check("approval", buf.String())
}
