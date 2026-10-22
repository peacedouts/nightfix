package e2e_test

// Independent review (round 5): per-event lookups that scan whole indexes.

import (
	"context"
	"regexp"
	"strconv"
	"testing"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

var buffersRe = regexp.MustCompile(`Buffers: shared hit=(\d+)(?: read=(\d+))?`)

// buffers returns the pages the root node of query's plan touched.
func (x *ingestHarness) buffers(query string, args ...any) int {
	x.t.Helper()
	var first string
	err := x.srv.DB.WithOrg(context.Background(), x.orgID, func(tx *db.Tx) error {
		rows, err := tx.Query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) `+query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l string
			rows.Scan(&l)
			if first == "" && buffersRe.MatchString(l) {
				first = l
			}
		}
		return rows.Err()
	})
	if err != nil {
		x.t.Fatal(err)
	}
	m := buffersRe.FindStringSubmatch(first)
	if m == nil {
		x.t.Fatalf("no buffer counts in the plan")
	}
	hit, _ := strconv.Atoi(m[1])
	read, _ := strconv.Atoi(m[2])
	return hit + read
}

// The event processor looks up each event by id (processor.go:106 and :54)
// and its alert by fingerprint (processor.go:145, :216, :249, :324). Under
// the tenant policy every table now has (USING org_id = nfx_org() OR
// current_user = 'nfx_owner', migration 0013), org_id can't be an index
// condition, so an index on (org_id, fingerprint) is scanned end to end
// with fingerprint as a non-leading key; alert_events has no index leading
// with id at all. The cost of processing one event therefore grows with
// every alert and every retained event in the database (all orgs), and
// events are processed one at a time per org.
func TestReviewPerEventLookupsGrowWithTableSize(t *testing.T) {
	x := setupIngest(t, nil)
	ctx := context.Background()
	var integ, svc string
	x.srv.DB.WithOrg(ctx, x.orgID, func(tx *db.Tx) error {
		tx.QueryRow(`SELECT id FROM integrations WHERE type = 'webhook'`).Scan(&integ)
		return tx.QueryRow(`SELECT id FROM services WHERE name = 'checkout-api'`).Scan(&svc)
	})
	addNoise := func(n int) {
		x.exec(`INSERT INTO alert_events (id, org_id, integration_id, raw, processed_at, received_at)
			SELECT gen_random_uuid(), $1, $2, '{}', now(), now() - (g % 24) * interval '1 hour' FROM generate_series(1, $3) g`,
			x.orgID, integ, n)
		x.exec(`INSERT INTO alerts (id, org_id, fingerprint, integration_id, service_id, status, severity, summary, source,
				first_seen_at, last_seen_at, resolved_at, state_at)
			SELECT gen_random_uuid(), $1, 'wh:' || gen_random_uuid(), $2, $3, 'resolved', 'high', 's', 'webhook', now(), now(), now(), now()
			FROM generate_series(1, $4)`, x.orgID, integ, svc, n)
	}
	event := ids.NewString()
	x.exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,'{"summary":"x"}')`, event, x.orgID, integ)
	measure := func() (int, int) {
		return x.buffers(`SELECT integration_id, raw FROM alert_events WHERE id = $1`, event),
			x.buffers(`SELECT max(state_at) FROM alerts WHERE fingerprint = $1`, "wh:not-there")
	}
	addNoise(2000)
	e1, a1 := measure()
	addNoise(38000)
	e2, a2 := measure()
	t.Logf("pages touched with 2k / 40k rows: event by id %d / %d, alert by fingerprint %d / %d", e1, e2, a1, a2)
	if e2 > 3*e1 || a2 > 3*a1 {
		t.Fatalf("one lookup touched %dx (event by id) and %dx (alert by fingerprint) more pages after the tables grew 20x: each event's processing is linear in table size",
			e2/max(e1, 1), a2/max(a1, 1))
	}
}
