package secret_detect

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SecretFindingSeverity computes the severity and confidence for a Kingfisher
// secret finding based on where and how it was observed.
//
// A secret that Kingfisher validated as live stays Critical/Certain no matter
// where it appears — a confirmed live credential is serious anywhere. For
// unvalidated matches the baseline is High/Firm, but matches that ride on a
// redirect (3xx) response or that appear verbatim inside a response header
// value are downgraded to Low/Tentative. Those are almost always low-value
// reflections — e.g. an OAuth client_id / state / nonce embedded in a Location
// URL that merely bounces the browser to an SSO login page — rather than a
// genuinely leaked secret served in page content.
func SecretFindingSeverity(validated, redirect, inHeader bool) (severity.Severity, severity.Confidence) {
	switch {
	case validated:
		return severity.Critical, severity.Certain
	case redirect || inHeader:
		return severity.Low, severity.Tentative
	default:
		return severity.High, severity.Firm
	}
}

// IsRedirectStatus reports whether code is an HTTP 3xx redirect status.
func IsRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// JoinHeaderValues concatenates response header values into a single
// newline-delimited blob suitable for snippet containment checks. Header names
// are omitted — only the values can carry a reflected secret (e.g. a Location
// redirect URL).
func JoinHeaderValues(headers []httpmsg.HttpHeader) string {
	if len(headers) == 0 {
		return ""
	}
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

// SnippetInHeaderValues reports whether the matched secret snippet appears
// verbatim within the response header values blob (see JoinHeaderValues), most
// commonly a Location redirect URL. Kingfisher only scans response bodies, but
// a server's default redirect body echoes the Location URL, so a header-borne
// value surfaces in the body too; matching it back to a header marks it as a
// low-value reflection rather than leaked page content. A blank snippet never
// matches.
func SnippetInHeaderValues(snippet, headerValues string) bool {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" || headerValues == "" {
		return false
	}
	return strings.Contains(headerValues, snippet)
}
