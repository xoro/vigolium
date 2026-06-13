package infra

import "strings"

// railsBodySignal pairs a body substring with the human-readable label surfaced
// as evidence when it matches. These are framework markers that a generic
// reverse proxy / API gateway never emits — they only appear in genuine Ruby on
// Rails responses.
type railsBodySignal struct {
	marker string
	label  string
}

// railsBodySignals mirrors the body detection in the passive rails_fingerprint
// module so header-less Rails apps (those that strip X-Runtime / Server) are
// still recognised from their rendered content. ActiveStorage / ActionMailbox
// class names are included; callers that scan a probe response must echo-strip
// the request path first (every Active Storage / Action Mailbox probe path
// embeds those tokens, so a reflected target would otherwise match).
var railsBodySignals = []railsBodySignal{
	{`name="csrf-token"`, "Rails CSRF meta tag"},
	{`name="csrf-param"`, "Rails CSRF meta tag"},
	{"data-turbo-track", "Turbo/Turbolinks"},
	{"data-turbolinks-track", "Turbo/Turbolinks"},
	{`name="action-cable-url"`, "Action Cable meta tag"},
	{"The page you were looking for doesn't exist", "Rails default 404 page"},
	{"We're sorry, but something went wrong", "Rails default 500 page"},
	{"Action Controller: Exception caught", "Rails exception page"},
	{"param is missing or the value is empty", "ActionController::ParameterMissing"},
	{"ActionController::", "ActionController reference"},
	{"ActionDispatch::", "ActionDispatch reference"},
	{"ActiveStorage", "ActiveStorage reference"},
	{"ActionMailbox", "ActionMailbox reference"},
}

// railsServerTokens are Ruby application-server tokens that appear in the Server
// header of a Rails deployment.
var railsServerTokens = []string{"puma", "unicorn", "passenger", "thin", "webrick", "mongrel"}

// RailsSignals inspects one HTTP response's headers, Set-Cookie values, and body
// for genuine Ruby on Rails / Rack framework fingerprints and returns the list
// of matched signal descriptions (empty when the response shows no Rails
// evidence). It mirrors the passive rails_fingerprint module so the two stay
// consistent.
//
// Callers use a non-empty result to confirm a host actually runs Rails before
// trusting a framework-route heuristic (e.g. an Active Storage / Action Mailbox
// OPTIONS probe whose only signal is an `Allow: POST` header). Generic reverse
// proxies and API gateways that answer every path uniformly carry none of these
// signals, so requiring one drops the catch-all false positives.
//
// headerGet returns a response header value by name (case-insensitive as
// implemented by the caller). setCookies are the raw Set-Cookie header values.
// body is the already-decoded response body; pass "" to skip body signals, and
// echo-strip the request path out of probe-response bodies before passing them.
func RailsSignals(headerGet func(string) string, setCookies []string, body string) []string {
	var signals []string

	if rt := strings.TrimSpace(headerGet("X-Runtime")); rt != "" {
		signals = append(signals, "X-Runtime: "+rt)
	}
	server := strings.ToLower(headerGet("Server"))
	for _, token := range railsServerTokens {
		if strings.Contains(server, token) {
			signals = append(signals, "Server: "+token)
			break
		}
	}
	poweredBy := strings.ToLower(headerGet("X-Powered-By"))
	if strings.Contains(poweredBy, "passenger") || strings.Contains(poweredBy, "phusion") {
		signals = append(signals, "X-Powered-By: Phusion Passenger")
	}

	// Rails session cookies are named _<app>_session. Exclude ASP.NET, whose
	// cookie names can also contain "session".
	for _, cookie := range setCookies {
		lc := strings.ToLower(cookie)
		if strings.Contains(lc, "_session=") && !strings.Contains(lc, "asp") {
			name := cookie
			if i := strings.Index(cookie, "="); i > 0 {
				name = cookie[:i]
			}
			signals = append(signals, "Cookie: "+strings.TrimSpace(name))
			break
		}
	}

	if body != "" {
		for _, sig := range railsBodySignals {
			if strings.Contains(body, sig.marker) {
				signals = append(signals, "Body: "+sig.label)
				break
			}
		}
	}

	return signals
}
