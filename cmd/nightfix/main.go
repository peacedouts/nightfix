// Command nightfix runs the Nightfix control plane.
//
//	nightfix migrate                       apply schema migrations
//	nightfix org create --name N --slug S  create an org and print its owner API key
//	nightfix org link-auth0 --org O --auth0-org A  link an Auth0 Organization (operator only)
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
//	NIGHTFIX_AUTH0_CLIENT_IDS    Nightfix's application(s) in the tenant (azp); tokens issued to others are refused
//	NIGHTFIX_AUTH0_EMAIL_CLAIM   custom claim carrying the user's email (default https://nightfix.dev/email)
//	NIGHTFIX_AUTH0_GROUPS_CLAIM  custom claim carrying IdP groups (default https://nightfix.dev/groups)
//	NIGHTFIX_AUTH0_EMAIL_VERIFIED_CLAIM  claim saying the email is verified (default email_verified;
//	                             https://nightfix.dev/email_verified is read too). Unverified emails can't sign in.
//	NIGHTFIX_OIDC_ISSUER         any OpenID Connect issuer, exactly as its tokens carry it (instead of Auth0)
//	NIGHTFIX_OIDC_AUDIENCE       the audience its tokens are issued for (API identifier or client ID)
//	NIGHTFIX_OIDC_CLIENT_IDS     Nightfix's client application(s); tokens issued to others are refused
//	NIGHTFIX_OIDC_ORG            the org (org_…) every user of the issuer belongs to
//	NIGHTFIX_OIDC_ALLOWED_GROUPS / NIGHTFIX_OIDC_EMAIL_DOMAINS / NIGHTFIX_OIDC_REQUIRED_CLAIMS
//	                             who may sign in (at least one): a group, an email domain, claim=value pairs
//	NIGHTFIX_OIDC_EMAIL_CLAIM / _GROUPS_CLAIM / _EMAIL_VERIFIED_CLAIM   claim names (email, groups, email_verified)
//	NIGHTFIX_OIDC_TRUST_EMAIL    true: a token without an email-verified claim counts as verified
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
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
	fmt.Fprintln(os.Stderr, "usage: nightfix migrate | org create --name N --slug S | org link-auth0 --org org_… --auth0-org org_… | org new-owner-key --org org_… [--revoke-others] | serve")
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
	login, err := loginConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	cfg.Auth0 = login
	if cfg.AllowPrivateTargets {
		log.Warn("NIGHTFIX_DEV_ALLOW_PRIVATE_TARGETS is set: notification targets may point at any host, including internal addresses. Local development only.")
	}
	if p := os.Getenv("NIGHTFIX_SNS_DEV_CERT_PREFIX"); p != "" {
		log.Warn("NIGHTFIX_SNS_DEV_CERT_PREFIX is set: SNS signing certificates are also trusted from a non-AWS URL. Local development only.", "prefix", p)
	}
	if cfg.STSEndpoint != "" {
		log.Warn("NIGHTFIX_STS_DEV_ENDPOINT is set: IAM enrollment trusts a non-AWS STS. Local development only.")
	}
	return controlplane.New(pool, sl, ca, cfg, log), nil
}

func orgCmd(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "link-auth0" {
		return linkAuth0Cmd(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "new-owner-key" {
		return newOwnerKeyCmd(ctx, args[1:])
	}
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

// linkAuth0Cmd links a customer's Auth0 Organization to their org. It's an
// operator step, done once the customer has shown they control that Auth0
// Organization: an Auth0 org id isn't secret, so the API won't let an org's
// owner claim one.
func linkAuth0Cmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("org link-auth0", flag.ExitOnError)
	org := fs.String("org", "", "org id (org_…)")
	auth0Org := fs.String("auth0-org", "", "Auth0 Organization id (org_…)")
	fs.Parse(args)
	orgID, err := ids.Decode("org", *org)
	if err != nil || *auth0Org == "" {
		return errors.New("--org org_… and --auth0-org org_… are required")
	}
	srv, err := newServer(ctx)
	if err != nil {
		return err
	}
	if err := srv.LinkAuth0(ctx, orgID, *auth0Org, "operator", "nightfix org link-auth0"); err != nil {
		return err
	}
	fmt.Printf("linked %s to Auth0 organization %s\n", *org, *auth0Org)
	return nil
}

// newOwnerKeyCmd is the recovery path when an org has lost or leaked its
// owner key: it issues a new one and, with --revoke-others, revokes every
// other key at once. In a deployment the key goes to Secrets Manager, as
// org create does, so it never appears in task logs.
func newOwnerKeyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("org new-owner-key", flag.ExitOnError)
	org := fs.String("org", "", "org id (org_…)")
	revokeOthers := fs.Bool("revoke-others", false, "revoke every other API key of the org (use when a key leaked)")
	fs.Parse(args)
	orgID, err := ids.Decode("org", *org)
	if err != nil {
		return errors.New("--org org_… is required")
	}
	srv, err := newServer(ctx)
	if err != nil {
		return err
	}
	prefix := os.Getenv("NIGHTFIX_ORG_KEY_SECRET_PREFIX")
	const actor = "nightfix org new-owner-key"
	revoke := func(keep string) (int, error) {
		if !*revokeOthers {
			return 0, nil
		}
		return srv.RevokeOtherKeys(ctx, orgID, keep, actor)
	}
	if prefix == "" {
		key, keyID, _, err := srv.NewOwnerKey(ctx, orgID, actor)
		if err != nil {
			return err
		}
		fmt.Printf("api key:     %s   (shown once)\n", key)
		revoked, err := revoke(keyID)
		if err != nil {
			return fmt.Errorf("the new key works, but revoking the others failed (run again with --revoke-others): %w", err)
		}
		fmt.Printf("revoked:     %d other key(s)\n", revoked)
		return nil
	}
	aws, err := awscall.New(ctx)
	if err != nil {
		return err
	}
	// The secret is created before the key exists, so a missing permission
	// fails before anything is revoked.
	secret := fmt.Sprintf("%s%s-%d", prefix, ids.Encode("org", orgID), time.Now().Unix())
	if _, err := aws.Call(ctx, "secretsmanager", "CreateSecret", map[string]any{"Name": secret, "SecretString": "pending",
		"Description": "New Nightfix owner API key. Copy it to your password manager, then delete this secret."}); err != nil {
		return fmt.Errorf("create secret %s: %w", secret, err)
	}
	key, keyID, slug, err := srv.NewOwnerKey(ctx, orgID, actor)
	if err != nil {
		return err
	}
	// Only once the new key is stored are the others revoked, so a failure
	// here never leaves the org with no usable key.
	if _, err := aws.Call(ctx, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": secret, "SecretString": key}); err != nil {
		return fmt.Errorf("a new owner key for %s was created but couldn't be stored in %s (no key was revoked; run again): %w", slug, secret, err)
	}
	revoked, err := revoke(keyID)
	if err != nil {
		return fmt.Errorf("the new key is stored in %s, but revoking the others failed (run again with --revoke-others): %w", secret, err)
	}
	fmt.Printf("org:         %s (%s)\napi key:     stored in Secrets Manager as %s\nrevoked:     %d other key(s)\n", *org, slug, secret, revoked)
	return nil
}

// quietHandshakeEOF passes net/http's server log to slog, dropping the
// "TLS handshake error ... EOF" lines that load-balancer health checks cause.
type quietHandshakeEOF struct{ log *slog.Logger }

func (q quietHandshakeEOF) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "TLS handshake error") && strings.HasSuffix(line, ": EOF") {
		return len(p), nil
	}
	q.log.Warn("agent gateway", "msg", line)
	return len(p), nil
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
	// The NLB's TCP health checks open and close a connection without TLS,
	// which net/http logs as a handshake error every few seconds per zone.
	agentSrv.ErrorLog = stdlog.New(quietHandshakeEOF{srv.Log}, "", 0)
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

// loginConfig reads user sign-in settings: Auth0 Organizations
// (NIGHTFIX_AUTH0_DOMAIN), or any OpenID Connect provider mapped to one org
// (NIGHTFIX_OIDC_ISSUER), or neither (API keys only).
func loginConfig(getenv func(string) string) (controlplane.Auth0Config, error) {
	domain, issuer := getenv("NIGHTFIX_AUTH0_DOMAIN"), getenv("NIGHTFIX_OIDC_ISSUER")
	if domain == "" && issuer == "" {
		return controlplane.Auth0Config{}, nil
	}
	required, err := parseClaims(getenv("NIGHTFIX_OIDC_REQUIRED_CLAIMS"))
	if err != nil {
		return controlplane.Auth0Config{}, err
	}
	switch {
	case domain != "" && issuer != "":
		return controlplane.Auth0Config{}, errors.New("set NIGHTFIX_AUTH0_DOMAIN or NIGHTFIX_OIDC_ISSUER, not both")
	case domain != "":
		aud := getenv("NIGHTFIX_AUTH0_AUDIENCE")
		if aud == "" {
			return controlplane.Auth0Config{}, errors.New("NIGHTFIX_AUTH0_AUDIENCE is required with NIGHTFIX_AUTH0_DOMAIN")
		}
		clients := list(getenv("NIGHTFIX_AUTH0_CLIENT_IDS"))
		if len(clients) == 0 {
			return controlplane.Auth0Config{}, errors.New("NIGHTFIX_AUTH0_CLIENT_IDS is required with NIGHTFIX_AUTH0_DOMAIN: the client ID(s) of Nightfix's applications in the tenant (tokens issued to any other application are refused)")
		}
		return controlplane.Auth0Config{
			ClientIDs:          clients,
			Verifier:           auth0.New(domain, aud),
			EmailClaim:         getenv("NIGHTFIX_AUTH0_EMAIL_CLAIM"),
			GroupsClaim:        getenv("NIGHTFIX_AUTH0_GROUPS_CLAIM"),
			EmailVerifiedClaim: getenv("NIGHTFIX_AUTH0_EMAIL_VERIFIED_CLAIM"),
			RequiredClaims:     required,
		}, nil
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return controlplane.Auth0Config{}, fmt.Errorf("NIGHTFIX_OIDC_ISSUER %q must be an https URL, exactly as the provider's tokens carry it", issuer)
	}
	aud := getenv("NIGHTFIX_OIDC_AUDIENCE")
	if aud == "" {
		return controlplane.Auth0Config{}, errors.New("NIGHTFIX_OIDC_AUDIENCE is required with NIGHTFIX_OIDC_ISSUER (the API identifier or client ID tokens are issued for)")
	}
	org, err := ids.Decode("org", strings.ToLower(getenv("NIGHTFIX_OIDC_ORG")))
	if err != nil {
		return controlplane.Auth0Config{}, errors.New("NIGHTFIX_OIDC_ORG must be the org_… id every user of this identity provider belongs to")
	}
	clients := list(getenv("NIGHTFIX_OIDC_CLIENT_IDS"))
	if len(clients) == 0 {
		return controlplane.Auth0Config{}, errors.New("NIGHTFIX_OIDC_CLIENT_IDS is required: the client ID(s) of Nightfix's application in your identity provider (tokens issued to any other application are refused)")
	}
	groups, domains := list(getenv("NIGHTFIX_OIDC_ALLOWED_GROUPS")), list(getenv("NIGHTFIX_OIDC_EMAIL_DOMAINS"))
	if len(required) == 0 && len(groups) == 0 && len(domains) == 0 {
		return controlplane.Auth0Config{}, errors.New("say who may sign in: set NIGHTFIX_OIDC_ALLOWED_GROUPS, NIGHTFIX_OIDC_EMAIL_DOMAINS or NIGHTFIX_OIDC_REQUIRED_CLAIMS (otherwise anyone your identity provider lets sign up becomes a member)")
	}
	// Google issues tokens to anyone with a Google account: without the
	// Workspace domain pinned, that would be anyone at all.
	if u.Host == "accounts.google.com" && required["hd"] == "" {
		return controlplane.Auth0Config{}, errors.New("with Google as the issuer, NIGHTFIX_OIDC_REQUIRED_CLAIMS must pin your Workspace domain (hd=example.com)")
	}
	trust := getenv("NIGHTFIX_OIDC_TRUST_EMAIL")
	if trust != "" && trust != "true" && trust != "false" {
		return controlplane.Auth0Config{}, errors.New("NIGHTFIX_OIDC_TRUST_EMAIL must be true or false")
	}
	return controlplane.Auth0Config{
		Verifier:           auth0.NewOIDC(issuer, aud),
		EmailClaim:         or(getenv("NIGHTFIX_OIDC_EMAIL_CLAIM"), "email"),
		GroupsClaim:        or(getenv("NIGHTFIX_OIDC_GROUPS_CLAIM"), "groups"),
		EmailVerifiedClaim: getenv("NIGHTFIX_OIDC_EMAIL_VERIFIED_CLAIM"),
		OIDCOrgID:          org,
		RequiredClaims:     required,
		SubjectPrefix:      issuer,
		TrustEmail:         trust == "true",
		ClientIDs:          clients,
		AllowedGroups:      groups,
		EmailDomains:       domains,
	}, nil
}

// list reads a comma-separated list, dropping empty entries.
func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseClaims reads "k=v,k2=v2".
func parseClaims(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("NIGHTFIX_OIDC_REQUIRED_CLAIMS: %q isn't claim=value", kv)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
