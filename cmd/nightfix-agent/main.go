// Command nightfix-agent runs the customer-side agent.
//
// It needs outbound HTTPS to the control plane only. AWS credentials come
// from the standard chain (ECS task role, IRSA, instance profile, env).
//
//	nightfix-agent --endpoint https://agent.nightfix.dev:443 --org org_…            (IAM enrollment)
//	nightfix-agent --endpoint … --enroll-method token --enroll-token nfxenroll_…   (fallback)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/peacedouts/nightfix/internal/agent"
	"github.com/peacedouts/nightfix/internal/agent/awscall"
)

func main() {
	endpoint := flag.String("endpoint", env("NIGHTFIX_ENDPOINT", "https://127.0.0.1:8443"), "agent gateway URL")
	caFile := flag.String("ca-file", os.Getenv("NIGHTFIX_CA_FILE"), "CA certificate for the gateway (PEM)")
	method := flag.String("enroll-method", env("NIGHTFIX_ENROLL_METHOD", "iam"), "iam (prove the agent's AWS role) | token")
	orgID := flag.String("org", os.Getenv("NIGHTFIX_ORG_ID"), "org id (org_…), required for iam enrollment")
	token := flag.String("enroll-token", os.Getenv("NIGHTFIX_ENROLL_TOKEN"), "enrollment token (token method only)")
	stateDir := flag.String("state-dir", os.Getenv("NIGHTFIX_AGENT_STATE_DIR"), "where to keep identity; empty re-enrolls on every start")
	signers := flag.String("required-signers", os.Getenv("NIGHTFIX_REQUIRED_SIGNERS"), "comma-separated signers to pin locally, each key_id or key_id=base64-public-key (overrides the control plane; include the key for the full guarantee)")
	allowlist := flag.String("allowlist", os.Getenv("NIGHTFIX_ALLOWLIST_FILE"), "allowlist file")
	allowMode := flag.String("allowlist-mode", env("NIGHTFIX_ALLOWLIST_MODE", "off"), "off | warn | enforce")
	freezeDefault := false
	if v := os.Getenv("NIGHTFIX_AGENT_FREEZE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			// Fail closed: an unreadable kill switch must not mean "run".
			fail(fmt.Errorf("NIGHTFIX_AGENT_FREEZE=%q is not a boolean (use true or false)", v))
		}
		freezeDefault = b
	}
	freeze := flag.Bool("freeze", freezeDefault, "local kill switch: connect but run nothing")
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
	pinnedKeys := map[string]string{}
	for _, s := range strings.Split(*signers, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		id, pub, hasKey := strings.Cut(s, "=")
		pinned = append(pinned, id)
		if hasKey {
			pinnedKeys[id] = pub
		} else {
			log.Warn("required signer pinned without its public key; the key still comes from the control plane", "key_id", id)
		}
	}
	a, err := agent.New(agent.Config{
		Endpoint: *endpoint, CAPEM: caPEM, EnrollMethod: *method, OrgID: *orgID, IAM: aws, EnrollToken: *token, StateDir: *stateDir,
		RequiredSigners: pinned, PinnedKeys: pinnedKeys, AllowlistFile: *allowlist, AllowlistMode: *allowMode,
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
