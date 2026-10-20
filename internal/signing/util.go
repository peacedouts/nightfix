package signing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Sealer encrypts credentials at rest (signing private keys, Slack webhook
// URLs, PagerDuty routing keys, webhook HMAC secrets).
//
// This local AES-256-GCM sealer stands in for KMS envelope encryption: in
// production each org gets a data key wrapped by AWS KMS, and Seal/Open call
// KMS to unwrap it. The ciphertext layout (nonce || ciphertext) stays the same.
type Sealer struct{ aead cipher.AEAD }

// NewSealer takes a 32-byte master key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead}, nil
}

// Seal encrypts plaintext, binding it to aad (use the org id) so a ciphertext
// copied into another org's row won't decrypt.
func (s *Sealer) Seal(plaintext []byte, aad string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open decrypts what Seal produced.
func (s *Sealer) Open(ciphertext []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(aad))
}
