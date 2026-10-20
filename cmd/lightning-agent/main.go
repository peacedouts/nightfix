// Command lightning-agent runs the customer-side agent.
//
// It needs outbound HTTPS to the control plane only. AWS credentials come
// from the standard chain (ECS task role, IRSA, instance profile, env).
//
//	lightning-agent --endpoint https://agent.lightning.ir:443 --enroll-token lirenroll_…
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peacedouts/lightning_ir/internal/agent"
	"github.com/peacedouts/lightning_ir/internal/agent/awscall"
)

func main() {
	endpoint := flag.String("endpoint", env("LIR_ENDPOINT", "https://127.0.0.1:8443"), "agent gateway URL")
	caFile := flag.String("ca-file", os.Getenv("LIR_CA_FILE"), "CA certificate for the gateway (PEM)")
	token := flag.String("enroll-token", os.Getenv("LIR_ENROLL_TOKEN"), "enrollment token (first start only)")
	stateDir := flag.String("state-dir", os.Getenv("LIR_AGENT_STATE_DIR"), "where to keep identity; empty re-enrolls on every start")
	signers := flag.String("required-signers", os.Getenv("LIR_REQUIRED_SIGNERS"), "comma-separated signer key ids to pin locally (overrides the control plane)")
	allowlist := flag.String("allowlist", os.Getenv("LIR_ALLOWLIST_FILE"), "allowlist file")
	allowMode := flag.String("allowlist-mode", env("LIR_ALLOWLIST_MODE", "off"), "off | warn | enforce")
	freeze := flag.Bool("freeze", os.Getenv("LIR_AGENT_FREEZE") == "true", "local kill switch: connect but run nothing")
	slots := flag.Int("slots", 4, "max concurrent steps")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var caPEM []byte
	if *caFile != "" {
		b, err := os.ReadFile(*caFile)
		if err != nil {
			fail(err)
		}
		caPEM = b
	}
	aws, err := awscall.New(ctx)
	if err != nil {
		fail(err)
	}
	var pinned []string
	for _, s := range strings.Split(*signers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			pinned = append(pinned, s)
		}
	}
	a, err := agent.New(agent.Config{
		Endpoint: *endpoint, CAPEM: caPEM, EnrollToken: *token, StateDir: *stateDir,
		RequiredSigners: pinned, AllowlistFile: *allowlist, AllowlistMode: *allowMode,
		Freeze: *freeze, Slots: *slots, AWS: aws, Log: log,
	})
	if err != nil {
		fail(err)
	}
	if *freeze {
		log.Warn("local freeze is on: this agent will not run anything")
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fail(err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
