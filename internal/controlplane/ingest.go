package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/peacedouts/lightning_ir/internal/db"
	"github.com/peacedouts/lightning_ir/internal/ids"
)

const maxIngestBody = 256 << 10

// IngestHandler serves https://ingest…/v1/i/{integration_id}. It runs as its
// own listener (and in production its own ECS service) so API load or a bad
// UI deploy can't block alert intake.
func (s *Server) IngestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/i/{id}", s.handleIngest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
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
	if err := s.DB.QueryRowContext(ctx, `SELECT org_id FROM lir_route_integration($1)`, integrationID).Scan(&orgID); err != nil {
		http.Error(w, "unknown integration", http.StatusNotFound)
		return
	}

	status := http.StatusAccepted
	err = s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		var typ string
		var cfg db.JSON[map[string]string]
		var cred []byte
		if err := tx.QueryRow(`SELECT type, config, credential FROM integrations WHERE id = $1`, integrationID).
			Scan(&typ, &cfg, &cred); err != nil {
			return err
		}
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
			m, err := parseSNS(body)
			if err != nil {
				return httpError{http.StatusBadRequest, err.Error()}
			}
			if err := s.verifySNS(ctx, m); err != nil {
				return httpError{http.StatusUnauthorized, "SNS signature: " + err.Error()}
			}
			if want := cfg.V["topic_arn"]; want != "" && m.TopicArn != want {
				return httpError{http.StatusUnauthorized, "unexpected SNS topic"}
			}
			switch m.Type {
			case "SubscriptionConfirmation":
				if err := s.confirmSNSSubscription(ctx, m); err != nil {
					return httpError{http.StatusBadGateway, "confirm subscription: " + err.Error()}
				}
				status = http.StatusOK
				return tx.Audit(ctx, "integration", integrationID, "integration.sns_subscribed", "integration", integrationID,
					map[string]string{"topic_arn": m.TopicArn})
			case "UnsubscribeConfirmation":
				status = http.StatusOK
				return nil
			}
		}
		// Persist first; process asynchronously.
		_, err := tx.Exec(`INSERT INTO alert_events (id, org_id, integration_id, raw) VALUES ($1,$2,$3,$4)`,
			ids.NewString(), orgID, integrationID, string(body))
		return err
	})
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
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }
