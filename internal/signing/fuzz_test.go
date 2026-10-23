package signing

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/peacedouts/nightfix/internal/runbook"
)

func runbookDigest(s string) string { return runbook.Digest([]byte(s)) }

// FuzzOpenEnvelope: a payload the control-plane key signed is accepted only
// for the right org and agent before expiry; a payload signed by a customer
// co-signer key is never accepted, and a tampered signature never is.
func FuzzOpenEnvelope(f *testing.F) {
	cp, _ := GenerateKey("cp")
	co, _ := GenerateKey("co")
	tc := TrustConfig{
		Keys: map[string]string{cp.ID: base64.StdEncoding.EncodeToString(cp.Public),
			co.ID: base64.StdEncoding.EncodeToString(co.Public)},
		RequiredSigners: []string{cp.ID, co.ID},
		EnvelopeSigners: []string{cp.ID},
	}
	now := time.UnixMilli(1_700_000_000_000)
	f.Add(`{"org_id":"o","agent_id":"a","expires_at_unix_ms":1700000060000}`, false, uint8(0))
	f.Add(`{"org_id":"o","agent_id":"a","expires_at_unix_ms":1700000060000,"x":1}`, true, uint8(3))
	f.Add(`{"org_id":"o","agent_id":"a","expires_at_unix_ms":1700000060000}{"org_id":"p"}`, false, uint8(0))
	f.Fuzz(func(t *testing.T, payload string, coSigned bool, flip uint8) {
		k := cp
		if coSigned {
			k = co
		}
		sig := k.Sign([]byte(payload))
		if flip != 0 {
			sig[int(flip)%len(sig)] ^= 1 << (flip % 8)
		}
		se := SignedEnvelope{Payload: payload, Signature: base64.StdEncoding.EncodeToString(sig), KeyID: k.ID}
		e, err := OpenEnvelope(se, tc, "o", "a", now)
		if err != nil {
			return
		}
		if coSigned || flip != 0 {
			t.Fatalf("accepted an envelope signed by %s (flip %d)", k.ID, flip)
		}
		if e.OrgID != "o" || e.AgentID != "a" || e.ExpiresAt < now.Add(-MaxClockSkew).UnixMilli() {
			t.Fatalf("accepted %+v", e)
		}
	})
}

// FuzzVerifyBundle: a bundle is accepted only with a valid signature from
// every required signer over a digest that matches its content.
func FuzzVerifyBundle(f *testing.F) {
	cp, _ := GenerateKey("cp")
	co, _ := GenerateKey("co")
	tc := TrustConfig{
		Keys: map[string]string{cp.ID: base64.StdEncoding.EncodeToString(cp.Public),
			co.ID: base64.StdEncoding.EncodeToString(co.Public)},
		RequiredSigners: []string{cp.ID, co.ID},
	}
	f.Add(`{"name":"x","steps":[],"version":1}`, true, true, "")
	f.Add(`{"name":"x","steps":[],"version":1}`, true, false, "")
	f.Add(`{"name":"x","bogus":1}`, true, true, "")
	f.Add(`{"name":"x","steps":[],"version":1}`, true, true, "sha256:00")
	f.Fuzz(func(t *testing.T, body string, signCP, signCo bool, digest string) {
		real := digest == ""
		if real {
			digest = runbookDigest(body)
		}
		b := Bundle{CanonicalJSON: body, Digest: digest}
		if signCP {
			b.Signatures = append(b.Signatures, SignDigest(cp, digest))
		}
		if signCo {
			b.Signatures = append(b.Signatures, SignDigest(co, digest))
		}
		_, err := VerifyBundle(b, tc, nil)
		if err == nil && (!signCP || !signCo || digest != runbookDigest(body)) {
			t.Fatalf("accepted bundle: cp=%v co=%v digest ok=%v", signCP, signCo, digest == runbookDigest(body))
		}
	})
}

// FuzzSealerOpen: arbitrary bytes never decrypt (or panic), and a sealed
// value only opens under the org it was sealed for.
func FuzzSealerOpen(f *testing.F) {
	s, _ := NewSealer(make([]byte, 32))
	f.Add([]byte("secret"), "org-a", "org-b", []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, plain []byte, aad, other string, junk []byte) {
		if _, err := s.Open(junk, aad); err == nil && len(junk) < 12+16 {
			t.Fatal("short junk opened")
		}
		c, err := s.Seal(plain, aad)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.Open(c, aad); err != nil || string(got) != string(plain) {
			t.Fatalf("round trip: %v", err)
		}
		if other != aad {
			if _, err := s.Open(c, other); err == nil {
				t.Fatal("opened under another org")
			}
		}
	})
}
