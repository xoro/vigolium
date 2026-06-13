package infra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func hdr(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestRailsSignals_HeaderSignals(t *testing.T) {
	t.Parallel()

	assert.NotEmpty(t, RailsSignals(hdr(map[string]string{"X-Runtime": "0.013"}), nil, ""),
		"X-Runtime is a Rails signal")
	assert.NotEmpty(t, RailsSignals(hdr(map[string]string{"Server": "Puma 6.4.0"}), nil, ""),
		"Puma Server header is a Rails signal")
	assert.NotEmpty(t, RailsSignals(hdr(map[string]string{"X-Powered-By": "Phusion Passenger 6.0"}), nil, ""),
		"Phusion Passenger is a Rails signal")
}

func TestRailsSignals_CookieAndBodySignals(t *testing.T) {
	t.Parallel()

	assert.NotEmpty(t, RailsSignals(hdr(nil), []string{"_myapp_session=abc; path=/; HttpOnly"}, ""),
		"a Rails _session cookie is a signal")
	assert.NotEmpty(t, RailsSignals(hdr(nil), nil, `<meta name="csrf-token" content="x">`),
		"a Rails CSRF meta tag is a body signal")
	assert.NotEmpty(t, RailsSignals(hdr(nil), nil, "ActionController::ParameterMissing: param is missing"),
		"a framework error string is a body signal")
}

func TestRailsSignals_NoSignals(t *testing.T) {
	t.Parallel()

	// A generic gateway / proxy response: CORS + CSP headers, an ASP.NET-ish
	// session cookie, and a plain body. None of these are Rails signals.
	got := RailsSignals(
		hdr(map[string]string{
			"Server":                       "cloudflare",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST",
			"Content-Security-Policy":      "default-src 'self'",
		}),
		[]string{"ASP.NET_SessionId=xyz; path=/"},
		"<html><body>Welcome</body></html>",
	)
	assert.Empty(t, got, "a generic non-Rails response must yield no Rails signals")
}
