// Command nightfix runs the Nightfix control plane.
//
//	nightfix migrate                       apply schema migrations
//	nightfix org create --name N --slug S  create an org and print its owner API key
//	nightfix serve                         run the API, ingest, agent gateway and workers
//
// Configuration (environment):
//
//	NIGHTFIX_DATABASE_URL        app connection (as nfx_app), or build it from the parts below
//	NIGHTFIX_ADMIN_DATABASE_URL  migration connection (can create roles), or from the parts below
//	NIGHTFIX_DB_HOST / _PORT / _NAME   database location (port 5432, name nightfix by default)
//	NIGHTFIX_DB_SSLMODE          default verify-full when NIGHTFIX_DB_HOST is set
//	NIGHTFIX_DB_SSLROOTCERT      CA bundle for verify-full (the image ships the RDS bundle)
//	NIGHTFIX_DB_ADMIN_USER / NIGHTFIX_DB_ADMIN_PASSWORD   migration credentials (RDS master)
//	NIGHTFIX_APP_DB_PASSWORD     nfx_app's password: set during migrate, used to connect
//	NIGHTFIX_KMS_KEY_ID          KMS key that wraps the sealing key. When set, the sealing key and
//	                             agent CA live in Postgres (no disk needed); otherwise the state dir.
//	NIGHTFIX_STATE_DIR           CA and local master key (default ./.state); local development
//	NIGHTFIX_MASTER_KEY          base64 32-byte key for sealing credentials (overrides the state dir)
//	NIGHTFIX_PUBLIC_API_URL      base URL of the API (for Slack request URLs)
//	NIGHTFIX_ORG_KEY_SECRET_PREFIX  org create stores the owner API key in Secrets Manager as <prefix><slug>
//	NIGHTFIX_API_ADDR            default :8080
//	NIGHTFIX_INGEST_ADDR         default :8081
//	NIGHTFIX_AGENT_ADDR          default :8443 (mutual TLS)
//	NIGHTFIX_AGENT_TLS_HOSTS     names/IPs on the gateway certificate (default localhost,127.0.0.1)
//	NIGHTFIX_PUBLIC_INGEST_URL   base URL returned for integrations (default http://127.0.0.1:8081)
//	NIGHTFIX_SNS_DEV_CERT_PREFIX extra allowed SNS SigningCertURL prefix — local development only
//	NIGHTFIX_SNS_MAX_MESSAGE_AGE SNS notifications signed longer ago than this are refused (default 1h)
//	NIGHTFIX_STS_DEV_ENDPOINT    STS URL for IAM enrollment instead of sts.<region>.amazonaws.com — local development only
//	NIGHTFIX_AUTH0_DOMAIN        Auth0 tenant domain (e.g. acme.us.auth0.com); enables user login
//	NIGHTFIX_AUTH0_AUDIENCE      Auth0 API identifier (e.g. https://api.nightfix.dev)
//	NIGHTFIX_AUTH0_EMAIL_CLAIM   custom claim carrying the user's email (default https://nightfix.dev/email)
//	NIGHTFIX_AUTH0_GROUPS_CLAIM  custom claim carrying IdP groups (default https://nightfix.dev/groups)
//	NIGHTFIX_AUTH0_EMAIL_VERIFIED_CLAIM  claim saying the email is verified (default email_verified;
//	                             https://nightfix.dev/email_verified is read too). Unverified emails can't sign in.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/peacedouts/nightfix/internal/agent/awscall"
	"github.com/peacedouts/nightfix/internal/auth0"
	"github.com/peacedouts/nightfix/internal/controlplane"
	"github.com/peacedouts/nightfix/internal/db"
	"github.com/peacedouts/nightfix/internal/ids"
	"github.com/peacedouts/nightfix/internal/signing"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "migrate":
		err = db.Migrate(ctx, databaseURL(true), os.Getenv("NIGHTFIX_APP_DB_PASSWORD"))
		if err == nil {
			fmt.Println("migrations applied")
		}
	case "org":
		err = orgCmd(ctx, os.Args[2:])
	case "serve":
		err = serve(ctx)
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nightfix migrate | org create --name N --slug S | serve")
	os.Exit(2)
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", k)
		os.Exit(2)
	}
	return v
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func stateDir() string { return env("NIGHTFIX_STATE_DIR", ".state") }

// sealer loads the credential-sealing key. Production uses KMS envelope
// encryption; locally a key file in the state dir stands in for it.
func sealer() (*signing.Sealer, error) {
	if k := os.Getenv("NIGHTFIX_MASTER_KEY"); k != "" {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("NIGHTFIX_MASTER_KEY: %w", err)
		}
		return signing.NewSealer(b)
	}
	path := filepath.Join(stateDir(), "master.key")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		rand.Read(b)
		if err := os.MkdirAll(stateDir(), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(b)), 0o600); err != nil {
			return nil, err
		}
		return signing.NewSealer(b)
	}
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	return signing.NewSealer(raw)
}

// databaseURL returns the app (or admin) connection string: the full URL if
// given, otherwise built from NIGHTFIX_DB_* parts, which is how ECS injects
// RDS credentials from Secrets Manager.
func databaseURL(admin bool) string {
	full, user, passVar := "NIGHTFIX_DATABASE_URL", "nfx_app", "NIGHTFIX_APP_DB_PASSWORD"
	if admin {
		full, passVar = "NIGHTFIX_ADMIN_DATABASE_URL", "NIGHTFIX_DB_ADMIN_PASSWORD"
		user = os.Getenv("NIGHTFIX_DB_ADMIN_USER")
	}
	if v := os.Getenv(full); v != "" {
		return v
	}
	host := os.Getenv("NIGHTFIX_DB_HOST")
	if host == "" || user == "" {
		fmt.Fprintf(os.Stderr, "set %s, or NIGHTFIX_DB_HOST with credentials\n", full)
		os.Exit(2)
	}
	q := url.Values{"sslmode": {env("NIGHTFIX_DB_SSLMODE", "verify-full")}}
	if rc := env("NIGHTFIX_DB_SSLROOTCERT", "/etc/ssl/rds/global-bundle.pem"); q.Get("sslmode") == "verify-full" || q.Get("sslmode") == "verify-ca" {
		q.Set("sslrootcert", rc)
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(user, mustEnv(passVar)),
		Host: host + ":" + env("NIGHTFIX_DB_PORT", "5432"), Path: "/" + env("NIGHTFIX_DB_NAME", "nightfix"), RawQuery: q.Encode()}
	return u.String()
}

func newServer(ctx context.Context) (*controlplane.Server, error) {
	pool, err := db.Open(ctx, databaseURL(false))
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var sl *signing.Sealer
	var ca *controlplane.CA
	if keyID := os.Getenv("NIGHTFIX_KMS_KEY_ID"); keyID != "" {
		// Stateless: keys live in Postgres, the sealing key wrapped by KMS.
		aws, err := awscall.New(ctx)
		if err != nil {
			return nil, err
		}
		if sl, err = controlplane.BootstrapSealer(ctx, pool, aws, keyID); err != nil {
			return nil, err
		}
		if ca, err = controlplane.LoadOrCreateCAInDB(ctx, pool, sl); err != nil {
			return nil, err
		}
	} else {
		log.Warn("NIGHTFIX_KMS_KEY_ID is not set: keys are kept in the state directory. Local development only.", "dir", stateDir())
		if sl, err = sealer(); err != nil {
			return nil, err
		}
		if ca, err = controlplane.LoadOrCreateCA(stateDir()); err != nil {
			return nil, err
		}
	}
	cfg := controlplane.Config{
		PublicAPIURL:       os.Getenv("NIGHTFIX_PUBLIC_API_URL"),
		PublicIngestURL:    env("NIGHTFIX_PUBLIC_INGEST_URL", "http://127.0.0.1:8081"),
		SNSCertURLPrefixes: []string{os.Getenv("NIGHTFIX_SNS_DEV_CERT_PREFIX")},
		STSEndpoint:        os.Getenv("NIGHTFIX_STS_DEV_ENDPOINT"),
		// Local development and demos only: lets targets point at
		// loopback/private addresses and non-Slack/PagerDuty hosts.
		AllowPrivateTargets: os.Getenv("NIGHTFIX_DEV_ALLOW_PRIVATE_TARGETS") == "1",
	}
	if v := os.Getenv("NIGHTFIX_SNS_MAX_MESSAGE_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return nil, fmt.Errorf("NIGHTFIX_SNS_MAX_MESSAGE_AGE must be a duration of at least 1m, like 1h")
		}
		cfg.SNSMaxMessageAge = d
	}
	if d := os.Getenv("NIGHTFIX_AUTH0_DOMAIN"); d != "" {
		cfg.Auth0 = controlplane.Auth0Config{
			Verifier:           auth0.New(d, mustEnv("NIGHTFIX_AUTH0_AUDIENCE")),
			EmailClaim:         os.Getenv("NIGHTFIX_AUTH0_EMAIL_CLAIM"),
			GroupsClaim:        os.Getenv("NIGHTFIX_AUTH0_GROUPS_CLAIM"),
			EmailVerifiedClaim: os.Getenv("NIGHTFIX_AUTH0_EMAIL_VERIFIED_CLAIM"),
		}
	}
	if cfg.AllowPrivateTargets {
		log.Warn("NIGHTFIX_DEV_ALLOW_PRIVATE_TARGETS is set: notification targets may point at any host, including internal addresses. Local development only.")
	}
	if cfg.STSEndpoint != "" {
		log.Warn("NIGHTFIX_STS_DEV_ENDPOINT is set: IAM enrollment trusts a non-AWS STS. Local development only.")
	}
	return controlplane.New(pool, sl, ca, cfg, log), nil
}

func orgCmd(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		usage()
	}
	fs := flag.NewFlagSet("org create", flag.ExitOnError)
	name := fs.String("name", "", "org display name")
	slug := fs.String("slug", "", "org slug")
	fs.Parse(args[1:])
	if *name == "" || *slug == "" {
		return errors.New("--name and --slug are required")
	}
	srv, err := newServer(ctx)
	if err != nil {
		return err
	}
	// In a deployment, the owner key goes straight into Secrets Manager and is
	// never printed, so it can't end up in task logs.
	prefix := os.Getenv("NIGHTFIX_ORG_KEY_SECRET_PREFIX")
	if prefix == "" {
		o, err := srv.CreateOrg(ctx, *name, *slug)
		if err != nil {
			return err
		}
		fmt.Printf("org:         %s\nsigning key: %s\nagent pin:   --required-signers %s\napi key:     %s   (shown once)\n",
			ids.Encode("org", o.OrgID), o.SigningID, o.SigningPin, o.APIKey)
		return nil
	}
	aws, err := awscall.New(ctx)
	if err != nil {
		return err
	}
	secret := prefix + *slug
	// Create the secret first, so a missing permission fails before the org
	// exists with a key nobody has.
	if _, err := aws.Call(ctx, "secretsmanager", "CreateSecret", map[string]any{"Name": secret, "SecretString": "pending",
		"Description": "Nightfix owner API key for org " + *slug + ". Copy it to your password manager, then delete this secret."}); err != nil {
		return fmt.Errorf("create secret %s: %w", secret, err)
	}
	o, err := srv.CreateOrg(ctx, *name, *slug)
	if err != nil {
		return err
	}
	if _, err := aws.Call(ctx, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": o.APIKey}); err != nil {
		return fmt.Errorf("org %s was created but its key couldn't be stored in %s: %w", ids.Encode("org", o.OrgID), secret, err)
	}
	fmt.Printf("org:         %s\nsigning key: %s\nagent pin:   --required-signers %s\napi key:     stored in Secrets Manager as %s\n",
		ids.Encode("org", o.OrgID), o.SigningID, o.SigningPin, secret)
	return nil
}

func serve(ctx context.Context) error {
	srv, err := newServer(ctx)
	if err != nil {
		return err
	}
	tlsCfg, err := srv.CA.ServerTLS(strings.Split(env("NIGHTFIX_AGENT_TLS_HOSTS", "localhost,127.0.0.1"), ","))
	if err != nil {
		return err
	}
	// Bound every phase of a connection, so slow or idle clients can't hold
	// connections (and goroutines) open indefinitely. The agent gateway's
	// write timeout must outlast a long poll.
	server := func(addr string, h http.Handler, write time.Duration) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: write, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	}
	agentSrv := server(env("NIGHTFIX_AGENT_ADDR", ":8443"), srv.AgentHandler(), srv.Cfg.PollWait+30*time.Second)
	agentSrv.TLSConfig = tlsCfg
	servers := []*http.Server{
		server(env("NIGHTFIX_API_ADDR", ":8080"), srv.APIHandler(), 60*time.Second),
		server(env("NIGHTFIX_INGEST_ADDR", ":8081"), srv.IngestHandler(), 30*time.Second),
		agentSrv,
	}
	errc := make(chan error, len(servers))
	for i, hs := range servers {
		go func(i int, hs *http.Server) {
			var err error
			if hs.TLSConfig != nil {
				err = hs.ListenAndServeTLS("", "")
			} else {
				err = hs.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(i, hs)
	}
	srv.RunWorkers(ctx, 0)
	srv.Log.Info("nightfix control plane running", "api", servers[0].Addr, "ingest", servers[1].Addr, "agent_gateway", servers[2].Addr)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, hs := range servers {
		hs.Shutdown(shut)
	}
	// Let notifications already claimed finish and be recorded.
	srv.WaitWorkers(notifyShutdownWait)
	return nil
}

// notifyShutdownWait covers one notification request and recording it.
const notifyShutdownWait = 20 * time.Second
