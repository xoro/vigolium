package internal_header_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "internal-header-probe"
	ModuleName  = "Internal Header Probe"
	ModuleShort = "Fuzzes custom/internal request headers advertised via Access-Control-Allow-Headers and reports value-dependent response changes"
)

var (
	ModuleDesc = `## Description
When a server's CORS preflight response advertises the request headers it accepts
via ` + "`Access-Control-Allow-Headers`" + ` (and, secondarily, the response headers it
exposes via ` + "`Access-Control-Expose-Headers`" + `), it is effectively enumerating a
private, often gateway-injected header protocol — identity, routing, trust, and
feature-flag headers such as ` + "`X-Netflix.user.id`" + `, ` + "`X-Netflix.oauth.token`" + `, or
` + "`X-Netflix.Request.Client.Context`" + `. These headers are normally set by an upstream
gateway; if the edge passes a client-supplied value through to the backend, an
attacker may be able to influence routing, identity, or trust decisions.

This module discovers those advertised custom headers, then re-sends the original
request with each candidate header set to a battery of probe values (a random
UUID, role/identity words like ` + "`admin`/`internal`/`root`" + `, booleans, loopback IPs,
empty/null) and reports the headers whose **response body** reproducibly changes
as a result. When OAST is configured, each candidate header is additionally sprayed
with an out-of-band callback URL to surface blind SSRF (the OAST service emits its
own finding asynchronously if the callback fires).

## Detection
- A fresh baseline is fetched several times to establish the endpoint's natural
  response variance (a noise floor). The endpoint is skipped if it is too unstable
  or if its baseline body is blank.
- A header is flagged only when a probe value, **reproducibly across two rounds**,
  both shifts the body below the noise floor by at least the divergence tolerance
  AND drives it to a **substantially larger** body than the no-header baseline
  (greater by both an absolute and a relative margin), with the injected value
  stripped before comparison so a mere reflection is never mistaken for a change.
- Comparison is body-content based (token similarity + body size), not status-code
  based. Blank bodies are ignored, and responses that are not actionable — 3xx
  redirects and 4xx statuses other than 401 — are ignored.
- WAF/CDN/challenge responses are excluded, and a per-host circuit breaker stops
  probing a host once it produces too many findings or reacts to nearly every header
  (a sign of a noisy page rather than real signal).

## Notes
- Severity is **Suspect** and confidence **Tentative**: a body change proves the
  backend processes the header, not that it is a vulnerability. Manual verification
  of the impact (privilege change, routing, information disclosure) is required.
- This module is intrusive (sends many requests) and is tagged accordingly.

## References
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- https://portswigger.net/web-security/cors
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`

	ModuleConfirmation = "Confirmed when an advertised custom header, set to a probe value, reproducibly shifts the response body beyond the endpoint's natural variance AND to a substantially larger size than the no-header baseline, on an actionable response (2xx/401/5xx, non-blank; 3xx and other 4xx ignored), value stripped to exclude reflection"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cors", "header", "recon", "ssrf", "intrusive"}
)
