package crawler

import (
	"net/url"
	"testing"
)

func TestSameOrSubdomain(t *testing.T) {
	tests := []struct {
		name string
		host string
		base string
		want bool
	}{
		{"identical", "ado.dtu.acme.com", "ado.dtu.acme.com", true},
		{"subdomain of base", "ado.dtu.acme.com", "acme.com", true},
		{"base is subdomain of host", "acme.com", "ado.dtu.acme.com", false},
		{"sibling host", "mail.dtu.acme.com", "ado.dtu.acme.com", false},
		{"unrelated host", "login.microsoftonline.com", "ado.dtu.acme.com", false},
		{"suffix-but-not-subdomain", "evilacme.com", "acme.com", false},
		{"empty host", "", "acme.com", false},
		{"empty base", "ado.dtu.acme.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameOrSubdomain(tt.host, tt.base); got != tt.want {
				t.Errorf("sameOrSubdomain(%q, %q) = %v, want %v", tt.host, tt.base, got, tt.want)
			}
		})
	}
}

func TestLooksLikeLoginURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"microsoft idp", "https://login.microsoftonline.com/common/oauth2/authorize?client_id=x", true},
		{"okta tenant", "https://acme.okta.com/", true},
		{"auth0 tenant", "https://acme.eu.auth0.com/authorize", true},
		{"login subdomain prefix", "https://login.example.com/", true},
		{"sso subdomain prefix", "https://sso.example.com/start", true},
		{"adfs path marker", "https://corp.example.com/adfs/ls/?wa=wsignin1.0", true},
		{"saml path marker", "https://idp.example.com/app/saml/sso", true},
		{"signin path", "https://app.example.com/account/signin", true},
		{"oauth authorize path", "https://api.example.com/oauth2/authorize?response_type=code", true},
		{"plain app root", "https://newapp.example.com/", false},
		{"dashboard path", "https://app.example.com/dashboard/home", false},
		{"login as substring of word only in host", "https://logistics.example.com/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.raw, err)
			}
			if got := looksLikeLoginURL(u); got != tt.want {
				t.Errorf("looksLikeLoginURL(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
