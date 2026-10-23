package canonical

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// FuzzTransform: output is valid JSON with the same value as the input, and
// canonicalizing it again changes nothing.
func FuzzTransform(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":[1e3,-0,0.1,"é"]}`, `"😀"`, `1E400`, `{"a":{"a":{}}}`, `[null,true,false]`, `123456789012345678901234567890`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		out, err := Transform(doc)
		if err != nil {
			return
		}
		var a, b any
		if err := json.Unmarshal(out, &b); err != nil {
			t.Fatalf("output isn't JSON: %v %q", err, out)
		}
		if json.Unmarshal(doc, &a) == nil && !reflect.DeepEqual(a, b) {
			t.Fatalf("value changed: %q -> %q", doc, out)
		}
		again, err := Transform(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %q -> %q (%v)", out, again, err)
		}
	})
}
