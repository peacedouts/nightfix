package main

import (
	"strings"
	"testing"
)

func TestLoginConfig(t *testing.T) {
	org := "org_0123456789abcdef0123456789abcdef"
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	ok := map[string]string{"NIGHTFIX_OIDC_ISSUER": "https://acme.okta.com/oauth2/default", "NIGHTFIX_OIDC_AUDIENCE": "api://nightfix", "NIGHTFIX_OIDC_ORG": org,
		"NIGHTFIX_OIDC_CLIENT_IDS": "0oa1nightfix", "NIGHTFIX_OIDC_ALLOWED_GROUPS": "nightfix-users"}

	with := func(changes map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range ok {
			m[k] = v
		}
		for k, v := range changes {
			m[k] = v
		}
		return m
	}
	c, err := loginConfig(env(ok))
	if err != nil || c.Verifier == nil || c.OIDCOrgID != "01234567-89ab-cdef-0123-456789abcdef" || c.SubjectPrefix != ok["NIGHTFIX_OIDC_ISSUER"] || c.GroupsClaim != "groups" {
		t.Fatalf("okta: %+v %v", c, err)
	}
	if c, err := loginConfig(env(nil)); err != nil || c.Verifier != nil {
		t.Fatalf("no sign-in configured: %+v %v", c, err)
	}
	// Sign-in settings are ignored, not fatal, when no provider is set.
	if _, err := loginConfig(env(map[string]string{"NIGHTFIX_OIDC_REQUIRED_CLAIMS": "garbage"})); err != nil {
		t.Fatalf("API keys only with a stray setting: %v", err)
	}
	// A mixed-case org id is the same org.
	if c, err := loginConfig(env(with(map[string]string{"NIGHTFIX_OIDC_ORG": strings.ToUpper(org[:4]) + strings.ToUpper(org[4:])}))); err != nil || c.OIDCOrgID != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("mixed-case org: %q %v", c.OIDCOrgID, err)
	}

	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"both providers":        {with(map[string]string{"NIGHTFIX_AUTH0_DOMAIN": "x.us.auth0.com"}), "not both"},
		"http issuer":           {with(map[string]string{"NIGHTFIX_OIDC_ISSUER": "http://acme.okta.com"}), "https"},
		"no audience":           {with(map[string]string{"NIGHTFIX_OIDC_AUDIENCE": ""}), "AUDIENCE"},
		"no org":                {with(map[string]string{"NIGHTFIX_OIDC_ORG": ""}), "ORG"},
		"google without domain": {with(map[string]string{"NIGHTFIX_OIDC_ISSUER": "https://accounts.google.com"}), "hd="},
		"bad claims":            {with(map[string]string{"NIGHTFIX_OIDC_REQUIRED_CLAIMS": "hd"}), "claim=value"},
		"bad trust flag":        {with(map[string]string{"NIGHTFIX_OIDC_TRUST_EMAIL": "yes"}), "true or false"},
		"auth0 no audience":     {map[string]string{"NIGHTFIX_AUTH0_DOMAIN": "x.us.auth0.com"}, "AUDIENCE"},
		"auth0 no client ids":   {map[string]string{"NIGHTFIX_AUTH0_DOMAIN": "x.us.auth0.com", "NIGHTFIX_AUTH0_AUDIENCE": "https://api"}, "CLIENT_IDS"},
		"no client ids":         {with(map[string]string{"NIGHTFIX_OIDC_CLIENT_IDS": ""}), "CLIENT_IDS"},
		"nobody may sign in":    {with(map[string]string{"NIGHTFIX_OIDC_ALLOWED_GROUPS": ""}), "who may sign in"},
	} {
		if _, err := loginConfig(env(c.env)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error about %s", name, err, c.want)
		}
	}

	g, err := loginConfig(env(with(map[string]string{"NIGHTFIX_OIDC_ISSUER": "https://accounts.google.com",
		"NIGHTFIX_OIDC_REQUIRED_CLAIMS": "hd=acme.example, azp = client", "NIGHTFIX_OIDC_TRUST_EMAIL": "false"})))
	if err != nil || g.RequiredClaims["hd"] != "acme.example" || g.RequiredClaims["azp"] != "client" || g.TrustEmail {
		t.Fatalf("google with domain: %+v %v", g, err)
	}
}
