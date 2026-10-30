// Package controlplane is the server side of Nightfix: alert ingest, the
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
	"sort"
	"sync"
	"time"

	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
)

// Config holds runtime settings.
type Config struct {
	PublicIngestURL string // base URL customers point integrations at
	PublicAPIURL    string // base URL of the API, for the Slack interactivity URL
	// SlackResponseURLPrefixes, if set, are extra allowed Slack response_url
	// prefixes. For local development only; production accepts only
	// https://hooks.slack.com/.
	SlackResponseURLPrefixes []string
	// SlackMaxLoginAge is how recently a person must have signed in to
	// Nightfix for their Slack clicks to count. Team membership from IdP
	// groups is refreshed at sign-in, so this bounds how stale it can be.
	SlackMaxLoginAge time.Duration
	// SNSCertURLPrefixes, if set, are extra allowed SigningCertURL prefixes.
	// For local development only; production accepts only sns.*.amazonaws.com.
	SNSCertURLPrefixes []string
	// SNSMaxMessageAge bounds replays: an SNS notification whose signed
	// Timestamp is older than this is refused. SNS keeps retrying a failed
	// delivery for a while, so keep it generous. Default 1h.
	SNSMaxMessageAge time.Duration
	// STSEndpoint overrides the regional STS URL for IAM enrollment. Local
	// development and tests only.
	STSEndpoint string
	Auth0       Auth0Config
	// LeaseDuration is how long a dispatched attempt has to be acknowledged.
	LeaseDuration time.Duration
	// RunningLease is how long a running attempt survives without hearing
	// from its agent (heartbeats renew it). Longer than LeaseDuration, so a
	// network blip of a few minutes doesn't turn a step that's still running
	// (and whose result the agent will deliver) into "lost" and a page.
	RunningLease time.Duration
	EnvelopeTTL  time.Duration
	PollWait     time.Duration
	HTTPClient   *http.Client // for SNS, STS and Slack interaction replies (fixed hosts)
	// AllowPrivateTargets lifts the host allowlist on tenant-supplied
	// notification URLs (Slack webhooks, approval channels, PagerDuty
	// events_url) and lets the notification client connect to loopback and
	// private addresses. Local development, demos and tests only.
	AllowPrivateTargets bool
	// NotifyHTTPClient sends notifications to tenant-supplied URLs. Defaults
	// to newNotifyClient: no redirects, no proxy, a 5s timeout, and (unless
	// AllowPrivateTargets) no loopback, private or link-local addresses.
	NotifyHTTPClient *http.Client
	// Auth0SelfLink lets an org's owner link an Auth0 Organization through
	// the API (PUT /v1/org/auth0). Development and tests only: nothing proves
	// the owner controls it, so in production the operator links it.
	Auth0SelfLink bool
	// NotifyWorkers is how many notifications one instance delivers at once.
	NotifyWorkers int
}

func (c *Config) defaults() {
	if c.LeaseDuration == 0 {
		c.LeaseDuration = 30 * time.Second
	}
	if c.RunningLease == 0 {
		c.RunningLease = 5 * time.Minute
	}
	if c.EnvelopeTTL == 0 {
		c.EnvelopeTTL = 2 * time.Minute
	}
	if c.PollWait == 0 {
		c.PollWait = 20 * time.Second
	}
	if c.SNSMaxMessageAge == 0 {
		c.SNSMaxMessageAge = time.Hour
	}
	if c.SlackMaxLoginAge == 0 {
		c.SlackMaxLoginAge = 7 * 24 * time.Hour
	}
	if c.HTTPClient == nil {
		// Every host it talks to is fixed (SNS, STS, Slack), and none of
		// them redirects; following one would take the request elsewhere.
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if c.NotifyHTTPClient == nil {
		c.NotifyHTTPClient = newNotifyClient(c.AllowPrivateTargets)
	}
	if c.NotifyWorkers <= 0 {
		c.NotifyWorkers = 8
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

	snsCertMu   sync.Mutex
	snsCerts    map[string][]byte
	snsFetch    chan struct{}            // bounds uncached certificate fetches, which unauthenticated requests can cause
	snsInflight map[string]chan struct{} // certificate fetches in progress, by URL

	workers sync.WaitGroup // RunWorkers' notification workers
}

// New builds a Server.
func New(d *db.DB, sealer *signing.Sealer, ca *CA, cfg Config, log *slog.Logger) *Server {
	cfg.defaults()
	if log == nil {
		log = slog.Default()
	}
	return &Server{DB: d, Sealer: sealer, CA: ca, Cfg: cfg, Log: log,
		keys: map[string]signing.Key{}, snsCerts: map[string][]byte{}, snsFetch: make(chan struct{}, 4)}
}

// ---------------------------------------------------------------------------
// Org bootstrap
// ---------------------------------------------------------------------------

// NewOrg is the result of creating an org.
type NewOrg struct {
	OrgID     string
	APIKey    string // shown once
	SigningID string
	// SigningPin is "key_id=base64-public-key", the value customers pin in
	// agents (--required-signers) so the control plane can't swap the key.
	SigningPin string
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
		sealed, err := s.seal(key.Private, orgID, sealSigningKey, key.ID)
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
	return &NewOrg{OrgID: orgID, APIKey: apiKey, SigningID: key.ID,
		SigningPin: key.ID + "=" + base64.StdEncoding.EncodeToString(key.Public)}, nil
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
	priv, err := s.unseal(sealed, tx.OrgID, sealSigningKey, id)
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
	rows, err := tx.Query(`SELECT key_id, public_key, owner FROM signing_keys WHERE state <> 'retired'`)
	if err != nil {
		return tc, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, owner string
		var pub []byte
		if err := rows.Scan(&id, &pub, &owner); err != nil {
			return tc, err
		}
		tc.Keys[id] = base64.StdEncoding.EncodeToString(pub)
		if owner == "control_plane" {
			tc.EnvelopeSigners = append(tc.EnvelopeSigners, id)
		}
	}
	sort.Strings(tc.EnvelopeSigners)
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

// readyz reports whether this instance can serve: unlike /healthz (liveness,
// which must not fail during a database outage, or the orchestrator restarts
// every instance at once), it checks the database.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.DB.PingContext(ctx); err != nil {
		s.Log.Warn("readiness check failed", "err", err)
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok"))
}
