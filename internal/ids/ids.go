// Package ids generates time-ordered UUIDv7 identifiers and their prefixed
// API forms (org_…, inc_…, run_…).
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// UUID is a 16-byte RFC 9562 UUID.
type UUID [16]byte

var (
	mu      sync.Mutex
	lastMs  uint64
	lastSeq uint16
)

// New returns a UUIDv7: 48-bit Unix milliseconds, then random bits. Within a
// millisecond a 12-bit counter keeps IDs from one process monotonic.
func New() UUID {
	var u UUID
	if _, err := rand.Read(u[:]); err != nil {
		panic(fmt.Sprintf("ids: crypto/rand failed: %v", err))
	}
	ms := uint64(time.Now().UnixMilli())

	mu.Lock()
	if ms <= lastMs {
		ms = lastMs
		lastSeq++
		if lastSeq > 0x0fff { // counter exhausted: borrow the next millisecond
			ms++
			lastSeq = 0
		}
	} else {
		lastSeq = binary.BigEndian.Uint16(u[6:8]) & 0x07ff // random start, leave headroom
	}
	lastMs = ms
	seq := lastSeq
	mu.Unlock()

	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	u[6] = 0x70 | byte(seq>>8) // version 7
	u[7] = byte(seq)
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return u
}

// String returns the canonical 8-4-4-4-12 form.
func (u UUID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:], u[10:])
	return string(b[:])
}

// NewString is shorthand for New().String().
func NewString() string { return New().String() }

// Parse accepts the canonical form.
func Parse(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("invalid uuid %q", s)
	}
	h := strings.ReplaceAll(s, "-", "")
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("invalid uuid %q: %w", s, err)
	}
	return u, nil
}

// Prefixed API IDs: "<prefix>_<uuid without dashes>". Opaque to clients.

// Encode returns the API form of a UUID string, e.g. Encode("run", id).
func Encode(prefix, uuid string) string {
	return prefix + "_" + strings.ReplaceAll(uuid, "-", "")
}

// Decode turns an API ID back into a UUID string, checking the prefix.
func Decode(prefix, apiID string) (string, error) {
	rest, ok := strings.CutPrefix(apiID, prefix+"_")
	if !ok || len(rest) != 32 {
		return "", fmt.Errorf("invalid %s id %q", prefix, apiID)
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return "", fmt.Errorf("invalid %s id %q", prefix, apiID)
	}
	return rest[0:8] + "-" + rest[8:12] + "-" + rest[12:16] + "-" + rest[16:20] + "-" + rest[20:], nil
}
