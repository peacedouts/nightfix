// Package migrations embeds the SQL schema migrations.
package migrations

import "embed"

// FS holds the numbered *.sql migration files, applied in name order.
//
//go:embed *.sql
var FS embed.FS
