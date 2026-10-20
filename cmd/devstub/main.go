// Command devstub simulates ECS, SNS, Slack and PagerDuty for local demos.
// See internal/devstub. Never point production at it.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/peacedouts/nightfix/internal/devstub"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9100", "listen address")
	healAfter := flag.Duration("heal-after", 4*time.Second, "how long a forced ECS deployment takes to stabilize")
	iamKey := flag.String("iam-access-key", "AKIDEXAMPLE", "access key the fake STS recognizes")
	iamSecret := flag.String("iam-secret", "example-secret", "its secret key")
	iamAccount := flag.String("iam-account", "123456789012", "account it belongs to")
	iamRole := flag.String("iam-role", "nightfix-agent", "role it reports as assumed")
	flag.Parse()
	s := devstub.New(*healAfter)
	s.AddIAMIdentity(devstub.IAMIdentity{AccessKey: *iamKey, Secret: *iamSecret, Account: *iamAccount, Role: *iamRole})
	s.BaseURL = "http://" + *addr
	fmt.Printf("devstub listening on %s (ECS at %s/aws, STS at /sts/, Slack at /slack, PagerDuty at /pagerduty)\n", s.BaseURL, s.BaseURL)
	if err := http.ListenAndServe(*addr, s.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
