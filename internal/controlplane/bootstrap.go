package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/signing"
)

// Stateless startup for deployments (ECS Fargate has no persistent disk).
// See migrations/0004_system_keys.sql.

// KMSClient is the part of a signed AWS client the control plane needs
// (agent/awscall.Client satisfies it).
type KMSClient interface {
	Call(ctx context.Context, service, action string, input map[string]any) (map[string]any, error)
}

// The encryption context binds the data key to its purpose: KMS refuses to
// decrypt it for any other context, and CloudTrail records it.
var sealingContext = map[string]any{"service": "nightfix", "purpose": "credential-sealing"}

const caKeyAAD = "system:agent-ca"

// BootstrapSealer returns the credential sealer, creating its data key with
// kms:GenerateDataKey on the very first start. Only the KMS ciphertext is
// stored; the plaintext key exists only in memory.
func BootstrapSealer(ctx context.Context, d *db.DB, kms KMSClient, keyID string) (*signing.Sealer, error) {
	load := func() (blob []byte, storedKey string, err error) {
		err = d.QueryRowContext(ctx, `SELECT secret, coalesce(kms_key_id, '') FROM system_keys WHERE name = 'sealing_dek'`).Scan(&blob, &storedKey)
		return
	}
	blob, storedKey, err := load()
	if isNoRows(err) {
		if err := createSealingKey(ctx, d, kms, keyID); err != nil {
			return nil, err
		}
		blob, storedKey, err = load()
	}
	if err != nil {
		return nil, fmt.Errorf("load sealing key: %w", err)
	}
	if storedKey != keyID {
		return nil, fmt.Errorf("the sealing key is wrapped by KMS key %q, but NIGHTFIX_KMS_KEY_ID is %q; use the original key (re-wrapping isn't supported yet)", storedKey, keyID)
	}
	out, err := kmsCall(ctx, kms, "Decrypt", map[string]any{
		"CiphertextBlob": base64.StdEncoding.EncodeToString(blob), "KeyId": keyID, "EncryptionContext": sealingContext})
	if err != nil {
		return nil, fmt.Errorf("decrypt sealing key: %w", err)
	}
	pt, err := b64Field(out, "Plaintext")
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return signing.NewSealer(pt)
}

// LoadOrCreateCAInDB returns the agent CA, creating it on the very first
// start. The private key is stored sealed.
func LoadOrCreateCAInDB(ctx context.Context, d *db.DB, sl *signing.Sealer) (*CA, error) {
	load := func() (certPEM, sealedKey []byte, err error) {
		err = d.QueryRowContext(ctx, `SELECT public_part, secret FROM system_keys WHERE name = 'agent_ca'`).Scan(&certPEM, &sealedKey)
		return
	}
	certPEM, sealedKey, err := load()
	if isNoRows(err) {
		if err := createCA(ctx, d, sl); err != nil {
			return nil, err
		}
		certPEM, sealedKey, err = load()
	}
	if err != nil {
		return nil, fmt.Errorf("load agent CA: %w", err)
	}
	keyPEM, err := sl.Open(sealedKey, caKeyAAD)
	if err != nil {
		return nil, fmt.Errorf("unseal agent CA key: %w", err)
	}
	defer clear(keyPEM)
	return parseCA(certPEM, keyPEM)
}

// createSealingKey stores a new KMS-wrapped data key unless another instance
// got there first; either way, callers read back the stored one.
func createSealingKey(ctx context.Context, d *db.DB, kms KMSClient, keyID string) error {
	out, err := kmsCall(ctx, kms, "GenerateDataKey", map[string]any{"KeyId": keyID, "KeySpec": "AES_256", "EncryptionContext": sealingContext})
	if err != nil {
		return fmt.Errorf("create sealing key: %w", err)
	}
	if pt, err := b64Field(out, "Plaintext"); err == nil {
		clear(pt) // not needed: every instance decrypts the stored ciphertext
	}
	ct, err := b64Field(out, "CiphertextBlob")
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO system_keys (name, kms_key_id, secret) VALUES ('sealing_dek', $1, $2)
		ON CONFLICT (name) DO NOTHING`, keyID, ct)
	return err
}

// createCA stores a new agent CA unless another instance got there first.
func createCA(ctx context.Context, d *db.DB, sl *signing.Sealer) error {
	certPEM, keyPEM, err := generateCA()
	if err != nil {
		return err
	}
	sealed, err := sl.Seal(keyPEM, caKeyAAD)
	clear(keyPEM)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO system_keys (name, public_part, secret) VALUES ('agent_ca', $1, $2)
		ON CONFLICT (name) DO NOTHING`, certPEM, sealed)
	return err
}

// kmsCall retries transient failures, so one network blip during a rollout
// doesn't stop a task from starting. It fails closed: no key, no start.
func kmsCall(ctx context.Context, kms KMSClient, action string, input map[string]any) (map[string]any, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var out map[string]any
		if out, err = kms.Call(ctx, "kms", action, input); err == nil {
			return out, nil
		}
		var ae *awscall.Error
		if errors.As(err, &ae) && ae.Status/100 == 4 && ae.Status != 429 {
			return nil, err // access denied, wrong key, bad ciphertext: retrying won't help
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * time.Second):
		}
	}
	return nil, err
}

func b64Field(out map[string]any, field string) ([]byte, error) {
	s, _ := out[field].(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("KMS response has no %s", field)
	}
	return b, nil
}
