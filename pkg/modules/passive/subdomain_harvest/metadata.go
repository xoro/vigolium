package subdomain_harvest

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subdomain-harvest"
	ModuleName  = "Subdomain Harvest"
	ModuleShort = "Collects in-scope subdomains referenced in HTML/JS responses for recon"
)

var (
	ModuleDesc = `**What it means:** This passive check reads HTML, JavaScript, and JSON responses and collects every hostname that shares the page's registrable domain (eTLD+1). Single-page apps and minified bundles routinely embed sibling origins, API hosts, and environment URLs in their config — additional in-scope attack surface that crawling the primary host alone would miss. Detection is informational: it records the related hostnames, sends no new traffic, and flags ones whose name suggests a non-production environment (dev, staging, test, qa).

**How it's exploited:** A list of an organization's own subdomains is high-value recon. Forgotten staging and dev hosts often run with weaker auth, verbose errors, or stale code, and admin or internal subdomains widen the surface an attacker can probe. Knowing they exist lets an attacker pivot to the weakest host instead of the hardened primary one.

**Fix:** Treat referenced hostnames as public, but make sure non-production and internal subdomains are not reachable from the internet, are not indexed, and do not ship in production bundles.`

	ModuleConfirmation = "Confirmed when one or more hostnames sharing the page's registrable domain are referenced in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"recon", "subdomain", "fingerprint", "light"}
)
