-- Deployment-wide keys the control plane creates on first start, so
-- instances need no disk and no secret ever passes through Terraform state:
--
--   sealing_dek  the key that seals per-org credentials, stored only as KMS
--                ciphertext; every instance decrypts it with kms:Decrypt at start.
--   agent_ca     the agent mTLS CA: certificate in the clear, private key
--                sealed with the sealing key.
--
-- Concurrent first starts race on INSERT … ON CONFLICT DO NOTHING and all
-- read back the winner. Not tenant data, so no RLS.

SET ROLE nfx_owner;

CREATE TABLE system_keys (
  name        text PRIMARY KEY CHECK (name IN ('sealing_dek','agent_ca')),
  kms_key_id  text,
  public_part bytea,
  secret      bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON system_keys TO nfx_app;

RESET ROLE;
