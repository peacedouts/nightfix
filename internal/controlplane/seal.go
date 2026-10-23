package controlplane

import "strings"

// Sealed values are bound to their org and to what they are (and, where it
// matters, to their row), so a ciphertext copied into another column, row or
// org doesn't decrypt there. Bound to the org alone, someone able to write
// the database could copy any sealed secret, the org's signing key included,
// into an idempotency record and have the API replay it in plaintext.
type sealPurpose string

const (
	sealSigningKey        sealPurpose = "signing_key"          // + key ID
	sealNotifyCredential  sealPurpose = "notify_credential"    // escalation targets and approval channels
	sealWebhookSecret     sealPurpose = "webhook_secret"       // generic webhook integrations
	sealSlackSigning      sealPurpose = "slack_signing_secret" // Slack apps
	sealIdempotentReplies sealPurpose = "idempotency"          // + principal, key, method, path
)

func sealAAD(orgID string, purpose sealPurpose, row ...string) string {
	return strings.Join(append([]string{orgID, string(purpose)}, row...), "\x00")
}

func (s *Server) seal(plain []byte, orgID string, purpose sealPurpose, row ...string) ([]byte, error) {
	return s.Sealer.Seal(plain, sealAAD(orgID, purpose, row...))
}

func (s *Server) unseal(sealed []byte, orgID string, purpose sealPurpose, row ...string) ([]byte, error) {
	return s.Sealer.Open(sealed, sealAAD(orgID, purpose, row...))
}
