package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
)

// Idempotency-Key on API writes (data-model.md §8.1). A client that retries
// a POST or PUT with the same key gets the first response back instead of a
// second execution. Keys are scoped to the org and the principal; a request
// is identified by method, path and a SHA-256 of its body, never the body.
//
// The key is claimed in its own short transaction before the handler runs,
// so a concurrent duplicate finds it in flight and gets 409 rather than
// running too. If the handler fails with a server error the claim is
// released (the handler's transaction rolled back, so a retry may run). If
// the request never finishes at all, the claim is taken over by a retry of
// the same request after idempotencyLease.

const (
	idempotencyHeader = "Idempotency-Key"
	idempotencyTTL    = 24 * time.Hour
	idempotencyLease  = 5 * time.Minute // far longer than any API request
	maxIdempotentBody = 4 << 20
)

var idempotencyKeyRe = regexp.MustCompile(`^[\x21-\x7e]{1,255}$`)

var errClaimReleased = errors.New("idempotency claim released")

type idempotencyRecord struct {
	Method, Path string
	BodyHash     []byte
	Status       sql.NullInt64
	Response     []byte
}

// withIdempotency runs serve at most once per (org, principal, key).
func (s *Server) withIdempotency(w http.ResponseWriter, r *http.Request, p principal, key string, serve func(http.ResponseWriter)) {
	if !idempotencyKeyRe.MatchString(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key must be 1-255 printable ASCII characters"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIdempotentBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read the request body"})
		return
	}
	if len(body) > maxIdempotentBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(body)
	ctx, reqID := r.Context(), ids.NewString()

	claimed, prev, err := s.claimIdempotencyKey(ctx, p, key, r.Method, r.URL.Path, sum[:], reqID)
	for i := 0; errors.Is(err, errClaimReleased) && i < 3; i++ {
		// The holder released its claim between our two statements.
		claimed, prev, err = s.claimIdempotencyKey(ctx, p, key, r.Method, r.URL.Path, sum[:], reqID)
	}
	switch {
	case errors.Is(err, errClaimReleased):
		prev = idempotencyRecord{Method: r.Method, Path: r.URL.Path, BodyHash: sum[:]} // in flight: 409 below
	case err != nil:
		s.reply(w, nil, err)
		return
	}
	if !claimed {
		s.replayIdempotent(w, r, p, prev, sum[:])
		return
	}

	rec := &capturedResponse{header: w.Header(), code: http.StatusOK}
	serve(rec)
	s.finishIdempotencyKey(ctx, p, key, reqID, rec)
	w.WriteHeader(rec.code)
	w.Write(rec.body.Bytes())
}

// claimIdempotencyKey claims key for this request if it is new, expired, or
// held by an identical request that never finished. Otherwise it returns the
// existing record.
func (s *Server) claimIdempotencyKey(ctx context.Context, p principal, key, method, path string, bodyHash []byte, reqID string) (bool, idempotencyRecord, error) {
	var rec idempotencyRecord
	claimed := false
	err := s.DB.WithOrg(ctx, p.OrgID, func(tx *db.Tx) error {
		err := tx.QueryRow(`INSERT INTO idempotency_keys (org_id, principal, key, method, path, body_hash, request_id, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7, now() + $8::interval)
			ON CONFLICT (org_id, principal, key) DO UPDATE SET method = EXCLUDED.method, path = EXCLUDED.path,
				body_hash = EXCLUDED.body_hash, request_id = EXCLUDED.request_id, status = NULL, response = NULL,
				created_at = now(), expires_at = EXCLUDED.expires_at
			WHERE idempotency_keys.expires_at <= now()
			   OR (idempotency_keys.status IS NULL AND idempotency_keys.created_at < now() - $9::interval
			       AND idempotency_keys.method = EXCLUDED.method AND idempotency_keys.path = EXCLUDED.path
			       AND idempotency_keys.body_hash = EXCLUDED.body_hash)
			RETURNING true`,
			p.OrgID, p.actor(), key, method, path, bodyHash, reqID, pgInterval(idempotencyTTL), pgInterval(idempotencyLease)).Scan(&claimed)
		if !isNoRows(err) {
			return err
		}
		err = tx.QueryRow(`SELECT method, path, body_hash, status, response FROM idempotency_keys WHERE principal = $1 AND key = $2`,
			p.actor(), key).Scan(&rec.Method, &rec.Path, &rec.BodyHash, &rec.Status, &rec.Response)
		if isNoRows(err) {
			return errClaimReleased
		}
		return err
	})
	return claimed, rec, err
}

// replayIdempotent answers a request whose key is already taken.
func (s *Server) replayIdempotent(w http.ResponseWriter, r *http.Request, p principal, prev idempotencyRecord, bodyHash []byte) {
	switch {
	case prev.Method != r.Method || prev.Path != r.URL.Path || !bytes.Equal(prev.BodyHash, bodyHash):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"error": "this Idempotency-Key was already used for a different request (method, path or body); use a new key"})
	case !prev.Status.Valid:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a request with this Idempotency-Key is still in progress; retry shortly"})
	default:
		body, err := s.Sealer.Open(prev.Response, p.OrgID)
		if err != nil {
			s.reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(int(prev.Status.Int64))
		w.Write(body)
	}
}

// finishIdempotencyKey stores the response for replay, or releases the claim
// after a server error so a retry can run.
func (s *Server) finishIdempotencyKey(ctx context.Context, p principal, key, reqID string, rec *capturedResponse) {
	// Record it even if the client has gone away: its retry needs the answer.
	err := s.DB.WithOrg(context.WithoutCancel(ctx), p.OrgID, func(tx *db.Tx) error {
		if rec.code >= 500 {
			_, err := tx.Exec(`DELETE FROM idempotency_keys WHERE principal = $1 AND key = $2 AND request_id = $3`, p.actor(), key, reqID)
			return err
		}
		sealed, err := s.Sealer.Seal(rec.body.Bytes(), p.OrgID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE idempotency_keys SET status = $4, response = $5 WHERE principal = $1 AND key = $2 AND request_id = $3`,
			p.actor(), key, reqID, rec.code, sealed)
		return err
	})
	if err != nil {
		// The claim stays in flight until its lease ends, so a retry is turned
		// away with 409 for now rather than run a second time at once.
		s.Log.Error("idempotency: could not record the response", "principal", p.actor(), "err", err)
	}
}

// capturedResponse buffers a handler's response so it can be stored before
// it's sent.
type capturedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (c *capturedResponse) Header() http.Header         { return c.header }
func (c *capturedResponse) WriteHeader(code int)        { c.code = code }
func (c *capturedResponse) Write(b []byte) (int, error) { return c.body.Write(b) }
