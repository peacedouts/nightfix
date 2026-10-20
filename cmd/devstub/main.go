// Command devstub simulates ECS, SNS, Slack and PagerDuty for local demos.
// See internal/devstub. Never point production at it.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/peacedouts/lightning_ir/internal/devstub"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9100", "listen address")
	healAfter := flag.Duration("heal-after", 4*time.Second, "how long a forced ECS deployment takes to stabilize")
	flag.Parse()
	s := devstub.New(*healAfter)
	s.BaseURL = "http://" + *addr
	fmt.Printf("devstub listening on %s (ECS at %s/aws, Slack at /slack, PagerDuty at /pagerduty)\n", s.BaseURL, s.BaseURL)
	if err := http.ListenAndServe(*addr, s.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
