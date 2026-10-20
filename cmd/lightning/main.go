// Command lightning runs the Lightning IR control plane.
//
//	lightning migrate                       apply schema migrations
//	lightning org create --name N --slug S  create an org and print its owner API key
//	lightning serve                         run the API, ingest, agent gateway and workers
//
// Configuration (environment):
//
//	LIR_DATABASE_URL        app connection (as lir_app)
//	LIR_ADMIN_DATABASE_URL  migration connection (can create roles)
//	LIR_APP_DB_PASSWORD     password to set for lir_app during migrate
//	LIR_STATE_DIR           CA and local master key (default ./.state)
//	LIR_MASTER_KEY          base64 32-byte key for sealing credentials (overrides the state dir)
//	LIR_API_ADDR            default :8080
//	LIR_INGEST_ADDR         default :8081
//	LIR_AGENT_ADDR          default :8443 (mutual TLS)
//	LIR_AGENT_TLS_HOSTS     names/IPs on the gateway certificate (default localhost,127.0.0.1)
//	LIR_PUBLIC_INGEST_URL   base URL returned for integrations (default http://127.0.0.1:8081)
//	LIR_SNS_DEV_CERT_PREFIX extra allowed SNS SigningCertURL prefix — local development only
//	LIR_STS_DEV_ENDPOINT    STS URL for IAM enrollment instead of sts.<region>.amazonaws.com — local development only
//	LIR_AUTH0_DOMAIN        Auth0 tenant domain (e.g. acme.us.auth0.com); enables user login
//	LIR_AUTH0_AUDIENCE      Auth0 API identifier (e.g. https://api.lightning.ir)
//	LIR_AUTH0_EMAIL_CLAIM   custom claim carrying the user's email (default https://lightning.ir/email)
//	LIR_AUTH0_GROUPS_CLAIM  custom claim carrying IdP groups (default https://lightning.ir/groups)
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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/peacedouts/lightning_ir/internal/auth0"
	"github.com/peacedouts/lightning_ir/internal/controlplane"
	"github.com/peacedouts/lightning_ir/internal/db"
	"github.com/peacedouts/lightning_ir/internal/ids"
	"github.com/peacedouts/lightning_ir/internal/signing"
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
		err = db.Migrate(ctx, mustEnv("LIR_ADMIN_DATABASE_URL"), os.Getenv("LIR_APP_DB_PASSWORD"))
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
	fmt.Fprintln(os.Stderr, "usage: lightning migrate | org create --name N --slug S | serve")
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

func stateDir() string { return env("LIR_STATE_DIR", ".state") }

// sealer loads the credential-sealing key. Production uses KMS envelope
// encryption; locally a key file in the state dir stands in for it.
func sealer() (*signing.Sealer, error) {
	if k := os.Getenv("LIR_MASTER_KEY"); k != "" {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("LIR_MASTER_KEY: %w", err)
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

func newServer(ctx context.Context) (*controlplane.Server, error) {
	pool, err := db.Open(ctx, mustEnv("LIR_DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	sl, err := sealer()
	if err != nil {
		return nil, err
	}
	ca, err := controlplane.LoadOrCreateCA(stateDir())
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := controlplane.Config{
		PublicIngestURL:    env("LIR_PUBLIC_INGEST_URL", "http://127.0.0.1:8081"),
		SNSCertURLPrefixes: []string{os.Getenv("LIR_SNS_DEV_CERT_PREFIX")},
		STSEndpoint:        os.Getenv("LIR_STS_DEV_ENDPOINT"),
	}
	if d := os.Getenv("LIR_AUTH0_DOMAIN"); d != "" {
		cfg.Auth0 = controlplane.Auth0Config{
			Verifier:    auth0.New(d, mustEnv("LIR_AUTH0_AUDIENCE")),
			EmailClaim:  os.Getenv("LIR_AUTH0_EMAIL_CLAIM"),
			GroupsClaim: os.Getenv("LIR_AUTH0_GROUPS_CLAIM"),
		}
	}
	if cfg.STSEndpoint != "" {
		log.Warn("LIR_STS_DEV_ENDPOINT is set: IAM enrollment trusts a non-AWS STS. Local development only.")
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
	o, err := srv.CreateOrg(ctx, *name, *slug)
	if err != nil {
		return err
	}
	fmt.Printf("org:         %s\nsigning key: %s\napi key:     %s   (shown once)\n", ids.Encode("org", o.OrgID), o.SigningID, o.APIKey)
	return nil
}

func serve(ctx context.Context) error {
	srv, err := newServer(ctx)
	if err != nil {
		return err
	}
	tlsCfg, err := srv.CA.ServerTLS(strings.Split(env("LIR_AGENT_TLS_HOSTS", "localhost,127.0.0.1"), ","))
	if err != nil {
		return err
	}
	servers := []*http.Server{
		{Addr: env("LIR_API_ADDR", ":8080"), Handler: srv.APIHandler(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: env("LIR_INGEST_ADDR", ":8081"), Handler: srv.IngestHandler(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: env("LIR_AGENT_ADDR", ":8443"), Handler: srv.AgentHandler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second},
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
	srv.Log.Info("lightning control plane running", "api", servers[0].Addr, "ingest", servers[1].Addr, "agent_gateway", servers[2].Addr)
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
	return nil
}
