package runbook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"github.com/peacedouts/nightfix/internal/canonical"
)

// Parse decodes a YAML runbook. Unknown fields are rejected so typos don't
// silently disable a guardrail.
func Parse(src []byte) (*Runbook, error) {
	if err := checkYAMLShape(src); err != nil {
		return nil, fmt.Errorf("parse runbook: %w", err)
	}
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

// maxYAMLDepth bounds nesting; real runbooks stay well under 20.
const maxYAMLDepth = 64

// checkYAMLShape refuses anchors, aliases and merge keys, and very deep
// nesting, before anything is decoded. The decoder expands aliases in full,
// so a few hundred bytes of nested aliases ("billion laughs") decoded into
// aws.input allocated gigabytes on the shared control plane. Runbooks don't
// need YAML references: they're short, reviewed and signed as written.
func checkYAMLShape(src []byte) error {
	f, err := parser.ParseBytes(src, 0)
	if err != nil {
		return fmt.Errorf("%s", yaml.FormatError(err, false, true))
	}
	var found error
	docs := 0
	for _, doc := range f.Docs {
		if doc == nil || doc.Body == nil {
			continue
		}
		docs++
		ast.Walk(&shapeVisitor{err: &found}, doc.Body)
	}
	// Only the first document is decoded, canonicalized and signed; any
	// other would be stored and shown as the runbook's source unsigned.
	if docs > 1 && found == nil {
		found = fmt.Errorf("a runbook file holds one YAML document; remove the extra '---' sections")
	}
	return found
}

type shapeVisitor struct {
	depth int
	err   *error
}

func (v *shapeVisitor) Visit(n ast.Node) ast.Visitor {
	if *v.err != nil {
		return nil
	}
	switch n.Type() {
	case ast.AnchorType, ast.AliasType, ast.MergeKeyType:
		*v.err = fmt.Errorf("line %d: YAML anchors, aliases and merge keys (&, *, <<) aren't allowed in runbooks", n.GetToken().Position.Line)
		return nil
	}
	if v.depth >= maxYAMLDepth {
		*v.err = fmt.Errorf("line %d: nested more than %d levels deep", n.GetToken().Position.Line, maxYAMLDepth)
		return nil
	}
	return &shapeVisitor{depth: v.depth + 1, err: v.err}
}
