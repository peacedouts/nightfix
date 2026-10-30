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
	"0001_init.sql":                           "70a8ad70a502351aff8f8f289b94d07d6f4595354da824ea3d1e3a193cb04055",
	"0002_identity.sql":                       "6d674ffb9d3defaa67c429bed603abcca5c41d87b6b1cb07f9361de42eb4af19",
	"0002_z_managed_postgres.sql":             "e4e0dbda47f09410aa57fccd62d45eba611fe38b81753a52ef682c9b1073a635",
	"0003_approvals.sql":                      "e8347641b54d9e1d44d1f17f63b6fb08584f0de897ba720d439729d35ccabd8c",
	"0004_system_keys.sql":                    "75a9d9af38923ba90d56e01d58881eba9ee4ddc4d106704c0da12a4692e2b8ff",
	"0005_notification_order.sql":             "ed230d422b387d112964580bfbe7c86c580491894e976933216773fd25ee7b2e",
	"0006_hardening.sql":                      "15662f8c5ee7b1e2c24421716afa9cceab4f475523feaa7af14bd8d69ec13d25",
	"0007_agent_cert_rollover.sql":            "d19d4ac75bdd4e8c3bceb978cdc3561ba6a42a064febede26ba7fe733b6b0ea3",
	"0008_audit_check_needs_org.sql":          "e1123cd7ecb2371895900d6a449561094c4e550861ff398b63006078dfb8ec81",
	"0009_alert_event_order.sql":              "222420fcbce3032ae63f30c24730af17cbe32c1dbfe70cac395bea8c5b19854d",
	"0010_approval_channel_fixes.sql":         "ba4c9ec53b966a6dcb75d6afc6092d4ffdcdf0a7e73ed40e8590cafae3a7ac47",
	"0011_partition_maintenance.sql":          "40475610eac52ffccec7aeb1cc40411a266848574821b6b4197faa24480aa3bd",
	"0012_public_schema.sql":                  "5ca5cbf3ba2c81553471019e7c0a1ecbba5c88320b79573438da43e2365552bb",
	"0013_owner_aware_policies.sql":           "4c6438922abf8f3e97c12802d4bcedfa5b7446b29e36d27506e4e2b07d422ba6",
	"0014_sns_replay_and_ordering.sql":        "de26dd559a9cb1d340f4144b045bf8b5aa16fccc969252f24f1a3264caf15dc3",
	"0015_webhook_dedup_key_scope.sql":        "58bb9d226f1141b5171b9ea3040e889228d4f99a4986ccf2b2adfd4ec2451709",
	"0016_idempotency_keys.sql":               "27e187489bd52cfd86bece059e73e1b50f597aae437c116f46d2efb65217600d",
	"0017_email_verified.sql":                 "788293d1bfa9016d6e170aa415f3cebf794e52ef4ab4a4e56056d0139031bc63",
	"0018_worker_retry.sql":                   "680e291e469d93e307a58079db9b082f47a815e7c6ebaeea9514b06bbb4c9449",
	"0019_function_privileges.sql":            "840c76a50a4e3514dedefd62206d3d9e973b7c6b683beaa5dac2df1d3171ffbc",
	"0020_outbox.sql":                         "d411f84083a6b22301c6b411155cb1ac1af75b997fed930ac5bcafdb2616bc45",
	"0021_step_retry_backoff.sql":             "918d04528d7b9e689893bb77af8094ad0c57ce13f0cccb6bbd9b1e226a07a500",
	"0022_notification_acknowledge.sql":       "744c765d838d58dba7c7dea04b70861c2aca38aeb6dd227a8cbd8028b9e3504b",
	"0023_alert_event_ordering.sql":           "20b66e6537efd794ca4715b7a520af032e71fa0d452abc92138150a9b491f3f5",
	"0024_role_scoped_policies.sql":           "12c64696cd352e86092300ff630dfeebd45cb456d6649b0813c8f9adc2077709",
	"0025_agent_iam_identity.sql":             "87fb41228fd29b04f12d929e885c65b40825c5c7f5e1d67734fef85dd7bbe146",
	"0026_claim_releases_ingest_lock.sql":     "73c01f05dd4dbe09bb6dde41d75f2b73b628443f8cc36155c4175bb2d2466e73",
	"0027_app_role_timeouts.sql":              "ec591a95de9d3d2ed17f2cfca88bdfc85baace8489e383d4d0562bd92c7ee7e4",
	"0028_partitions_attach_and_indexes.sql":  "726a70fb533ef69dec7a3463a02883075b4aab40651003c03c84a9cf3933b0e0",
	"0029_audit_insert_via_function_only.sql": "454a54ddb9bd1e9d8eeec7a516d15a6f172456f85d3296ab9a0fbbdd3dfaf411",
	"0030_slack_links_per_app.sql":            "9b2f66a3f46c0089bb0bebeb654a64ca5403b677aa281ec6bd9ae70fca12ca11",
	"0031_one_slack_app_per_workspace.sql":    "5b0e3285ae6a370b2452789fe3accbb845731b4d75b5e9266e83ebb95f4ec66d",
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
