package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

const maxIngestBody = 256 << 10

// IngestHandler serves https://ingest…/v1/i/{integration_id}. It runs as its
// own listener (and in production its own ECS service) so API load or a bad
// UI deploy can't block alert intake.
func (s *Server) IngestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/i/{id}", s.handleIngest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", s.readyz)
	return mux
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	integrationID, err := ids.Decode("int", r.PathValue("id"))
	if err != nil {
		http.Error(w, "unknown integration", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBody+1))
	if err != nil || len(body) > maxIngestBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var orgID string
	if err := s.DB.QueryRowContext(ctx, `SELECT org_id FROM nfx_route_integration($1)`, integrationID).Scan(&orgID); err != nil {
		http.Error(w, "unknown integration", http.StatusNotFound)
		return
	}

	status, result := http.StatusAccepted, "accepted"
	var rejectedTopic string
	err = func() error {
		// 1. The integration's settings, in a short read-only transaction.
		var typ string
		var cfg db.JSON[map[string]string]
		var cred []byte
		if err := s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
			return tx.QueryRow(`SELECT type, config, credential FROM integrations WHERE id = $1`, integrationID).
				Scan(&typ, &cfg, &cred)
		}); err != nil {
			return err
		}

		// 2. Authenticate the delivery, with no transaction open: verifying
		// an SNS signature can fetch its certificate, and confirming a
		// subscription calls SNS. A transaction held open across those would
		// hold a pool connection for seconds and, worse, commit its event
		// long after it was received, so it could be processed after a later
		// event from the same source (events are processed oldest first).
		var m snsMessage
		switch typ {
		case "webhook":
			secret, err := s.Sealer.Open(cred, orgID)
			if err != nil {
				return err
			}
			if err := verifyWebhook(string(secret), body, r.Header.Get(WebhookSignatureHeader), time.Now()); err != nil {
				return httpError{http.StatusUnauthorized, err.Error()}
			}
		case "cloudwatch":
			var err error
			if m, err = parseSNS(body); err != nil {
				return httpError{http.StatusBadRequest, err.Error()}
			}
			if err := s.verifySNS(ctx, m); err != nil {
				if errors.As(err, new(errSNSCertUnavailable)) {
					return httpError{http.StatusServiceUnavailable, "SNS signing certificate unavailable; retry"}
				}
				return httpError{http.StatusUnauthorized, "SNS signature: " + err.Error()}
			}
			// Fail closed: an integration without a pinned topic accepts nothing.
			if want := cfg.V["topic_arn"]; want == "" || m.TopicArn != want {
				rejectedTopic = m.TopicArn
				return httpError{http.StatusUnauthorized, "unexpected SNS topic"}
			}
			switch m.Type {
			case "SubscriptionConfirmation":
				if err := s.confirmSNSSubscription(ctx, m); err != nil {
					return httpError{http.StatusBadGateway, "confirm subscription: " + err.Error()}
				}
				status = http.StatusOK
				return s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
					return tx.Audit(ctx, "integration", integrationID, "integration.sns_subscribed", "integration", integrationID,
						map[string]string{"topic_arn": m.TopicArn})
				})
			case "UnsubscribeConfirmation":
				status = http.StatusOK
				return nil
			}
		}

		// 3. Store it, in a short transaction. received_at is the insert's own
		// time (not the transaction's start), so events order as they arrive.
		return s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
			// Shared with other deliveries, exclusive with the claim of this
			// org's next event (migration 0023): an event isn't processed
			// while an older one may still be committing.
			if _, err := tx.Exec(`SELECT pg_advisory_xact_lock_shared(hashtextextended('nfx_ingest:' || $1, 0))`, orgID); err != nil {
				return err
			}
			if typ == "cloudwatch" {
				fresh, err := s.freshSNSNotification(tx, integrationID, m)
				if err != nil {
					return err
				}
				if !fresh {
					// A repeat (SNS retry or replay): acknowledge it so SNS stops
					// retrying, and store nothing.
					status, result = http.StatusOK, "duplicate"
					return nil
				}
			}
			_, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw, received_at) VALUES ($1,$2,$3,$4, clock_timestamp())`,
				ids.NewString(), orgID, integrationID, string(body))
			return err
		})
	}()
	if rejectedTopic != "" {
		s.noteRejectedTopic(ctx, orgID, integrationID, rejectedTopic)
	}
	var he httpError
	switch {
	case errors.As(err, &he):
		http.Error(w, he.msg, he.code)
		return
	case err != nil:
		s.Log.Error("ingest", "integration", integrationID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"status": result})
}

// freshSNSNotification bounds replays of a verified SNS notification. Its
// signed Timestamp must be within SNSMaxMessageAge, and its MessageId must
// not have been seen on this integration before; it is recorded in the
// caller's transaction, so it only counts as seen once the event is stored.
// Returns false for a repeat.
func (s *Server) freshSNSNotification(tx *db.Tx, integrationID string, m snsMessage) (bool, error) {
	sent, err := time.Parse(time.RFC3339, m.Timestamp)
	if err != nil {
		return false, httpError{http.StatusBadRequest, "SNS Timestamp is not a valid time"}
	}
	now := time.Now()
	if age := now.Sub(sent); age > s.Cfg.SNSMaxMessageAge {
		s.Log.Warn("ingest: refused stale SNS notification", "integration", integrationID, "message_id", m.MessageID, "age", age.Round(time.Second))
		return false, httpError{http.StatusUnauthorized, fmt.Sprintf("SNS message is older than %s", s.Cfg.SNSMaxMessageAge)}
	}
	if m.MessageID == "" || len(m.MessageID) > 256 {
		return false, httpError{http.StatusBadRequest, "SNS MessageId is missing or malformed"}
	}
	// Keep the id until the message would be refused as stale anyway.
	expires := sent
	if now.After(expires) {
		expires = now
	}
	res, err := tx.Exec(`INSERT INTO ingest_message_ids (org_id, integration_id, message_id, expires_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (org_id, integration_id, message_id) DO NOTHING`,
		tx.OrgID, integrationID, m.MessageID, expires.Add(s.Cfg.SNSMaxMessageAge))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

// noteRejectedTopic records a correctly signed SNS delivery from a topic the
// integration doesn't pin, so GET /v1/integrations can show it: a
// misconfigured subscription is otherwise invisible, since SNS just retries
// and gives up. At most one write a minute per integration.
func (s *Server) noteRejectedTopic(ctx context.Context, orgID, integrationID, topic string) {
	s.Log.Warn("SNS delivery from a topic the integration doesn't pin was refused",
		"org", orgID, "integration", ids.Encode("int", integrationID), "topic_arn", topic)
	err := s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		_, err := tx.Exec(`UPDATE integrations SET config = config || jsonb_build_object('last_rejected_topic', $2::text,
			'last_rejected_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
			WHERE id = $1 AND (config->>'last_rejected_topic' IS DISTINCT FROM $2
				OR (config->>'last_rejected_at')::timestamptz < now() - interval '1 minute')`, integrationID, topic)
		return err
	})
	if err != nil {
		s.Log.Warn("could not record the refused SNS topic", "err", err)
	}
}
