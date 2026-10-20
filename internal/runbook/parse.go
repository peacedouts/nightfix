package runbook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/goccy/go-yaml"

	"github.com/peacedouts/lightning_ir/internal/canonical"
)

// Parse decodes a YAML runbook. Unknown fields are rejected so typos don't
// silently disable a guardrail.
func Parse(src []byte) (*Runbook, error) {
	var rb Runbook
	if err := yaml.UnmarshalWithOptions(src, &rb, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse runbook: %s", yaml.FormatError(err, false, true))
	}
	// Round-trip through JSON so free-form values (aws.input, defaults) have
	// exactly the shapes the canonical form and the agent will see.
	b, err := json.Marshal(&rb)
	if err != nil {
		return nil, err
	}
	var norm Runbook
	if err := json.Unmarshal(b, &norm); err != nil {
		return nil, err
	}
	return &norm, nil
}

// Canonical returns the RFC 8785 canonical JSON of the runbook and its
// digest ("sha256:<hex>"), which is what gets signed and pinned by runs.
func Canonical(rb *Runbook) ([]byte, string, error) {
	c, err := canonical.Marshal(rb)
	if err != nil {
		return nil, "", err
	}
	return c, Digest(c), nil
}

// Digest hashes canonical bytes.
func Digest(canonicalJSON []byte) string {
	sum := sha256.Sum256(canonicalJSON)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FromCanonical decodes a canonical JSON runbook (as received by the agent).
func FromCanonical(c []byte) (*Runbook, error) {
	var rb Runbook
	dec := json.NewDecoder(bytes.NewReader(c))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rb); err != nil {
		return nil, fmt.Errorf("decode canonical runbook: %w", err)
	}
	return &rb, nil
}
