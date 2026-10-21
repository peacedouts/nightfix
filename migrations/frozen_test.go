package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"testing"
)

// shipped lists every migration that has reached main, with its SHA-256.
//
// Migrate tracks migrations by file name only, so editing a shipped file does
// nothing to databases that already ran it: they silently keep the old schema
// while fresh databases get the new one. Change the schema with a new
// migration instead, and add each file here once it merges to main.
var shipped = map[string]string{
	"0001_init.sql":                    "70a8ad70a502351aff8f8f289b94d07d6f4595354da824ea3d1e3a193cb04055",
	"0002_identity.sql":                "6d674ffb9d3defaa67c429bed603abcca5c41d87b6b1cb07f9361de42eb4af19",
	"0002_z_managed_postgres.sql":      "e4e0dbda47f09410aa57fccd62d45eba611fe38b81753a52ef682c9b1073a635",
	"0003_approvals.sql":               "e8347641b54d9e1d44d1f17f63b6fb08584f0de897ba720d439729d35ccabd8c",
	"0004_system_keys.sql":             "75a9d9af38923ba90d56e01d58881eba9ee4ddc4d106704c0da12a4692e2b8ff",
	"0005_notification_order.sql":      "ed230d422b387d112964580bfbe7c86c580491894e976933216773fd25ee7b2e",
	"0006_hardening.sql":               "15662f8c5ee7b1e2c24421716afa9cceab4f475523feaa7af14bd8d69ec13d25",
	"0007_agent_cert_rollover.sql":     "d19d4ac75bdd4e8c3bceb978cdc3561ba6a42a064febede26ba7fe733b6b0ea3",
	"0008_audit_check_needs_org.sql":   "e1123cd7ecb2371895900d6a449561094c4e550861ff398b63006078dfb8ec81",
	"0009_alert_event_order.sql":       "222420fcbce3032ae63f30c24730af17cbe32c1dbfe70cac395bea8c5b19854d",
	"0010_approval_channel_fixes.sql":  "ba4c9ec53b966a6dcb75d6afc6092d4ffdcdf0a7e73ed40e8590cafae3a7ac47",
	"0011_partition_maintenance.sql":   "40475610eac52ffccec7aeb1cc40411a266848574821b6b4197faa24480aa3bd",
	"0012_public_schema.sql":           "5ca5cbf3ba2c81553471019e7c0a1ecbba5c88320b79573438da43e2365552bb",
	"0013_owner_aware_policies.sql":    "4c6438922abf8f3e97c12802d4bcedfa5b7446b29e36d27506e4e2b07d422ba6",
	"0014_sns_replay_and_ordering.sql": "de26dd559a9cb1d340f4144b045bf8b5aa16fccc969252f24f1a3264caf15dc3",
	"0015_webhook_dedup_key_scope.sql": "58bb9d226f1141b5171b9ea3040e889228d4f99a4986ccf2b2adfd4ec2451709",
	"0016_idempotency_keys.sql":        "27e187489bd52cfd86bece059e73e1b50f597aae437c116f46d2efb65217600d",
	"0017_email_verified.sql":          "788293d1bfa9016d6e170aa415f3cebf794e52ef4ab4a4e56056d0139031bc63",
}

func TestShippedMigrationsAreUnchanged(t *testing.T) {
	for name, want := range shipped {
		body, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Errorf("shipped migration %s is missing: %v", name, err)
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s has changed since it shipped (sha256 %s). Put the change in a new migration instead.", name, got)
		}
	}
}
