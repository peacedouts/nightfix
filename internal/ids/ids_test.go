package ids

import (
	"strings"
	"testing"
)

func TestParseRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		u := New()
		got, err := Parse(u.String())
		if err != nil || got != u {
			t.Fatalf("Parse(%s) = %v, %v", u, got, err)
		}
	}
	// Upper case hex is the same UUID (Postgres prints lower, accepts both).
	u := New()
	got, err := Parse(strings.ToUpper(u.String()))
	if err != nil || got != u {
		t.Fatalf("upper case: %v, %v", got, err)
	}
}

func TestParseRejects(t *testing.T) {
	valid := "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
	if _, err := Parse(valid); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, s := range []string{
		"",
		strings.ReplaceAll(valid, "-", ""),        // 32 hex, no dashes
		valid[:35],                                // short
		valid + "0",                               // long
		"{" + valid[1:35] + "}",                   // braces
		"0190a1b2_c3d4_7e5f_8a6b_7c8d9e0f1a2b",    // wrong separators
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2g",    // not hex
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2 ",    // space
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a+b",    // sign
		"0190a1b2c-3d4-7e5f-8a6b-7c8d9e0f1a2b",    // dash moved
		"--90a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b",    // two extra dashes: 30 hex digits decode cleanly
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a--",    // the same at the end
		"0190a1b2-c3d4-7e5f-8a6b--c8d9e0f1a2b",    // one extra dash: odd length
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2\x00", // NUL
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1aé",     // multi-byte
	} {
		if u, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted: %s", s, u)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	u := NewString()
	api := Encode("run", u)
	if !strings.HasPrefix(api, "run_") || len(api) != 4+32 {
		t.Fatalf("Encode = %q", api)
	}
	back, err := Decode("run", api)
	if err != nil || back != u {
		t.Fatalf("Decode(%q) = %q, %v; want %q", api, back, err, u)
	}
	for _, bad := range []string{"inc_" + api[4:], api[:len(api)-1], api + "0", "run_" + strings.Repeat("g", 32), "run", ""} {
		if _, err := Decode("run", bad); err == nil {
			t.Errorf("Decode(%q) accepted", bad)
		}
	}
}

func TestNewIsVersion7AndOrdered(t *testing.T) {
	prev := New()
	for i := 0; i < 10000; i++ {
		u := New()
		if u[6]>>4 != 7 || u[8]>>6 != 2 {
			t.Fatalf("%s: not a v7/RFC 4122 UUID", u)
		}
		if u.String() <= prev.String() {
			t.Fatalf("not monotonic: %s after %s", u, prev)
		}
		prev = u
	}
}
