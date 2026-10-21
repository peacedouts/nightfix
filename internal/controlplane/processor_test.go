package controlplane

import (
	"context"
	"database/sql/driver"
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
