// Package controlplane is the hosted side of Nightfix: alert ingest, the
// incident engine, runbook runs, agent dispatch, notifications and the REST
// API. It runs as one binary (a modular monolith) with each role on its own
// listener.
package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
)

// Config holds runtime settings.
type Config struct {
	PublicIngestURL string // base URL customers point integrations at
	// SNSCertURLPrefixes, if set, are extra allowed SigningCertURL prefixes.
	// For local development only; production accepts only sns.*.amazonaws.com.
	SNSCertURLPrefixes []string
	// STSEndpoint overrides the regional STS URL for IAM enrollment. Local
	// development and tests only.
	STSEndpoint   string
	Auth0         Auth0Config
	LeaseDuration time.Duration
	EnvelopeTTL   time.Duration
	PollWait      time.Duration
	HTTPClient    *http.Client // for notifications and SNS
}

func (c *Config) defaults() {
	if c.LeaseDuration == 0 {
		c.LeaseDuration = 30 * time.Second
	}
	if c.EnvelopeTTL == 0 {
		c.EnvelopeTTL = 2 * time.Minute
	}
	if c.PollWait == 0 {
		c.PollWait = 20 * time.Second
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// Server is the control plane.
type Server struct {
	DB     *db.DB
	Sealer *signing.Sealer
	CA     *CA
	Cfg    Config
	Log    *slog.Logger

	keyMu sync.Mutex
	keys  map[string]signing.Key // org -> active control-plane signing key

	snsCertMu sync.Mutex
	snsCerts  map[string][]byte
}

// New builds a Server.
func New(d *db.DB, sealer *signing.Sealer, ca *CA, cfg Config, log *slog.Logger) *Server {
	cfg.defaults()
	if log == nil {
		log = slog.Default()
	}
	return &Server{DB: d, Sealer: sealer, CA: ca, Cfg: cfg, Log: log,
		keys: map[string]signing.Key{}, snsCerts: map[string][]byte{}}
}

// ---------------------------------------------------------------------------
// Org bootstrap
// ---------------------------------------------------------------------------

// NewOrg is the result of creating an org.
type NewOrg struct {
	OrgID     string
	APIKey    string // shown once
	SigningID string
}

// CreateOrg creates an org with its signing key, trust config, catch-all
// service and an owner API key.
func (s *Server) CreateOrg(ctx context.Context, name, slug string) (*NewOrg, error) {
	orgID := ids.NewString()
	if _, err := s.DB.ExecContext(ctx, "SELECT nfx_create_org($1,$2,$3)", orgID, name, slug); err != nil {
		if db.IsUniqueViolation(err) {
			return nil, fmt.Errorf("an org with slug %q already exists", slug)
		}
		return nil, err
	}
	key, err := signing.GenerateKey("nfx-" + slug)
	if err != nil {
		return nil, err
	}
	apiKey, prefix, hash := newSecret("nfx")
	err = s.DB.WithOrg(ctx, orgID, func(tx *db.Tx) error {
		sealed, err := s.Sealer.Seal(key.Private, orgID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO signing_keys (key_id, org_id, owner, public_key, private_key)
			VALUES ($1,$2,'control_plane',$3,$4)`, key.ID, orgID, []byte(key.Public), sealed); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO org_trust_config (org_id, required_signers) VALUES ($1, ARRAY[$2])`, orgID, key.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO services (id, org_id, name, is_catch_all) VALUES ($1,$2,'catch-all',true)`, ids.NewString(), orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO api_keys (id, org_id, name, prefix, hash, role) VALUES ($1,$2,'bootstrap owner key',$3,$4,'owner')`,
			ids.NewString(), orgID, prefix, hash); err != nil {
			return err
		}
		return tx.Audit(ctx, "system", "bootstrap", "org.create", "org", orgID, map[string]string{"slug": slug, "signing_key": key.ID})
	})
	if err != nil {
		return nil, err
	}
	return &NewOrg{OrgID: orgID, APIKey: apiKey, SigningID: key.ID}, nil
}

// signingKey returns the org's active control-plane key, decrypted.
func (s *Server) signingKey(tx *db.Tx) (signing.Key, error) {
	s.keyMu.Lock()
	k, ok := s.keys[tx.OrgID]
	s.keyMu.Unlock()
	if ok {
		return k, nil
	}
	var id string
	var pub, sealed []byte
	err := tx.QueryRow(`SELECT key_id, public_key, private_key FROM signing_keys
		WHERE owner = 'control_plane' AND state = 'active' ORDER BY created_at DESC LIMIT 1`).Scan(&id, &pub, &sealed)
	if err != nil {
		return k, fmt.Errorf("load signing key: %w", err)
	}
	priv, err := s.Sealer.Open(sealed, tx.OrgID)
	if err != nil {
		return k, fmt.Errorf("unseal signing key: %w", err)
	}
	k = signing.Key{ID: id, Public: pub, Private: priv}
	s.keyMu.Lock()
	s.keys[tx.OrgID] = k
	s.keyMu.Unlock()
	return k, nil
}

// trustConfig returns the org's trust config as sent to agents.
func trustConfig(tx *db.Tx) (signing.TrustConfig, error) {
	tc := signing.TrustConfig{Keys: map[string]string{}}
	rows, err := tx.Query(`SELECT key_id, public_key FROM signing_keys WHERE state <> 'retired'`)
	if err != nil {
		return tc, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var pub []byte
		if err := rows.Scan(&id, &pub); err != nil {
			return tc, err
		}
		tc.Keys[id] = base64.StdEncoding.EncodeToString(pub)
	}
	if err := rows.Err(); err != nil {
		return tc, err
	}
	var signers stringArray
	if err := tx.QueryRow(`SELECT required_signers FROM org_trust_config`).Scan(&signers); err != nil {
		return tc, err
	}
	tc.RequiredSigners = signers
	return tc, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newSecret returns "<prefix>_<random>", its display prefix, and its hash.
func newSecret(prefix string) (secret, display string, hash []byte) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	secret = prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
	return secret, secret[:len(prefix)+5], hashSecret(secret)
}

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

var errNotFound = errors.New("not found")

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
