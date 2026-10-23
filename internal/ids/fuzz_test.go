package ids

import (
	"strings"
	"testing"
)

// FuzzDecode: a decoded ID is a UUID that encodes back to the same API ID.
func FuzzDecode(f *testing.F) {
	f.Add("run", "run_0123456789abcdef0123456789abcdef")
	f.Add("key", "key_nonsense")
	f.Fuzz(func(t *testing.T, prefix, id string) {
		u, err := Decode(prefix, id)
		if err != nil {
			return
		}
		if Encode(prefix, u) != id {
			t.Fatalf("round trip: %q -> %q -> %q", id, u, Encode(prefix, u))
		}
		if _, err := Parse(strings.ToLower(u)); err != nil {
			t.Fatalf("decoded id %q isn't a UUID: %v", u, err)
		}
	})
}
