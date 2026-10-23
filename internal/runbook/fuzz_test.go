package runbook

import (
	"bytes"
	"testing"
)

// FuzzParse: any input either fails to parse or yields a runbook whose
// canonical form round-trips exactly (what's signed is what the agent runs).
func FuzzParse(f *testing.F) {
	f.Add([]byte("name: x\nversion: 1\nsteps:\n  - id: a\n    shell:\n      run: echo hi\n"))
	f.Add([]byte("name: x\nversion: 1\nparams:\n  n: {type: integer, default: 3}\nsteps: []\n"))
	f.Add([]byte("a: &x 1\nb: *x\n"))
	f.Add([]byte("{\"name\": \"x\", \"version\": 1}"))
	f.Fuzz(func(t *testing.T, src []byte) {
		rb, err := Parse(src)
		if err != nil {
			return
		}
		_ = Lint(rb)
		c, d, err := Canonical(rb)
		if err != nil {
			t.Fatalf("parsed runbook has no canonical form: %v", err)
		}
		back, err := FromCanonical(c)
		if err != nil {
			t.Fatalf("canonical form doesn't decode: %v\n%s", err, c)
		}
		c2, d2, err := Canonical(back)
		if err != nil || d2 != d || !bytes.Equal(c, c2) {
			t.Fatalf("canonical round trip changed the runbook:\n%s\n%s", c, c2)
		}
	})
}

// FuzzFromCanonical: what an agent receives either decodes or is refused;
// re-canonicalizing a decoded runbook is stable.
func FuzzFromCanonical(f *testing.F) {
	f.Add([]byte(`{"name":"x","steps":[],"version":1}`))
	f.Add([]byte(`{"name":"x","unknown":1}`))
	f.Fuzz(func(t *testing.T, c []byte) {
		rb, err := FromCanonical(c)
		if err != nil {
			return
		}
		c1, _, err := Canonical(rb)
		if err != nil {
			return
		}
		rb2, err := FromCanonical(c1)
		if err != nil {
			t.Fatalf("re-canonicalized runbook doesn't decode: %v", err)
		}
		c2, _, _ := Canonical(rb2)
		if !bytes.Equal(c1, c2) {
			t.Fatalf("canonical form unstable:\n%s\n%s", c1, c2)
		}
	})
}
