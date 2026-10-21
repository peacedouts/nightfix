package controlplane

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Tenant admins choose where notifications go, and the control plane makes
// the request from inside its own network. Unless Config.AllowPrivateTargets
// is set (local development, demos, tests), URLs must point at the real
// Slack and PagerDuty endpoints, and the notification client refuses to
// connect to internal addresses whatever a name resolves to.

const slackWebhookHost = "hooks.slack.com"

var pagerDutyEventsHosts = []string{"events.pagerduty.com", "events.eu.pagerduty.com"}

var errTargetURL = errors.New("invalid target URL")

// validateNotifyURL checks a tenant-supplied notification URL for a target
// type ("slack" covers approval channels too).
func validateNotifyURL(typ, raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return errTargetURL
	}
	if allowPrivate {
		if u.Scheme != "https" && u.Scheme != "http" {
			return errTargetURL
		}
		return nil
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return errTargetURL
	}
	host := strings.ToLower(u.Hostname())
	switch typ {
	case "slack":
		if host != slackWebhookHost {
			return errTargetURL
		}
	case "pagerduty":
		if !slices.Contains(pagerDutyEventsHosts, host) {
			return errTargetURL
		}
	default:
		return errTargetURL
	}
	return nil
}

// Address ranges the notification client never connects to (besides
// loopback, private, link-local, multicast and unspecified addresses).
var blockedNotifyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach any IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("::ffff:0:0:0/96"), // SIIT IPv4-translated
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated)
}

var errAddrNotAllowed = errors.New("destination address not allowed")

func notifyAddrAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedNotifyPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// refuseInternalAddrs is a net.Dialer Control func. It runs after name
// resolution, for each address actually dialled, so DNS rebinding can't get
// around it.
func refuseInternalAddrs(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !notifyAddrAllowed(ap.Addr()) {
		return errAddrNotAllowed
	}
	return nil
}

// notifyRequestTimeout bounds one notification request, connect to body.
const notifyRequestTimeout = 5 * time.Second

// newNotifyClient returns the client for tenant-supplied URLs: it never
// follows redirects, never uses a proxy (the address check must see the
// real destination), and refuses internal addresses unless allowPrivate.
func newNotifyClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: notifyRequestTimeout, KeepAlive: 30 * time.Second}
	if !allowPrivate {
		d.Control = refuseInternalAddrs
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   notifyRequestTimeout,
		ResponseHeaderTimeout: notifyRequestTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       notifyRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
