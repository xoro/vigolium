package clickjacking_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "clickjacking-detect"
	ModuleName  = "Clickjacking (UI Redress)"
	ModuleShort = "Detects framable pages with sensitive/interactive content vulnerable to clickjacking"
)

var (
	ModuleDesc = `## Description
Detects pages that can be embedded in a cross-origin iframe and carry
sensitive, state-changing, or authenticated interactive content — the
combination that makes a clickjacking (UI-redress) attack worthwhile. Unlike a
plain "missing X-Frame-Options" hygiene check, this module evaluates the
*effective* anti-framing protection the way a browser would and only reports a
page that is both framable AND worth hijacking.

## Detection
Multiple corroborating signals are required, dropping early at each gate:
- Status: only HTTP 200 application responses (WAF/CDN challenge, auth, error,
  and redirect responses are rejected).
- Content-Type: only text/html with a non-empty body.
- Header verdict (browser-accurate precedence): an enforced CSP
  'frame-ancestors' directive overrides X-Frame-Options. A page is protected
  when 'frame-ancestors' is restrictive ('none'/'self'/an allowlist) or, absent
  any 'frame-ancestors', when X-Frame-Options is DENY or SAMEORIGIN. Deprecated
  ALLOW-FROM, invalid values, duplicated/conflicting headers, wildcard or
  scheme-only 'frame-ancestors', and report-only CSP are all treated as
  ineffective.
- Interactive-content baseline: the page must contain something a hijacked click
  actually does — a credential (password) form, an authenticated session, or a
  form posting to a state-changing/sensitive endpoint. Purely static framable
  pages are deferred to security_headers_missing / csp_weakness_audit.
- SameSite modifier: when the session cookie the page sets is SameSite=Strict or
  Lax, a cross-site iframe loads unauthenticated, so an authenticated finding is
  downgraded.

## Notes
- Passive only — does not send any HTTP requests.
- Runs once per host (deduplicated).
- Complements (does not replace) security_headers_missing and csp_weakness_audit,
  which cover the lower-severity header-hygiene angle.
- Limitations: button-only SPA actions are only caught when the captured traffic
  was already authenticated; 'frame-ancestors' in a <meta> tag is correctly
  ignored (browsers honor it only as a real header); request-cookie SameSite
  attributes are not visible to a passive observer.

## References
- https://owasp.org/www-community/attacks/Clickjacking
- https://portswigger.net/web-security/clickjacking
- https://cwe.mitre.org/data/definitions/1021.html`

	ModuleConfirmation = "Confirmed when a 200 OK HTML page lacks effective frame-ancestors/X-Frame-Options protection and carries sensitive or authenticated interactive content"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"clickjacking", "ui-redress", "header-security", "misconfiguration", "light"}
)
