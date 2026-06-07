package rails_active_storage_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-active-storage-probe"
	ModuleName  = "Rails Active Storage Probe"
	ModuleShort = "Detects exposed Rails Active Storage direct upload and Action Mailbox ingress endpoints"
)

var (
	ModuleDesc = `## Description
Probes for Rails Active Storage direct upload endpoints that may accept unauthenticated
uploads, and Action Mailbox ingress endpoints that may accept unauthorized email submissions.
Also checks for publicly accessible Active Storage blob routes.

## Notes
- OPTIONS-based ingress probes confirm only on a 2xx Allow header advertising
  POST — never on a body substring (an nginx "405 Not Allowed" page contains
  "Allow"), and never on a 405 / 404 / auth-gate / WAF-blocked reply
- Detects blanket-OPTIONS hosts (proxies / API gateways / CORS middleware that
  answer OPTIONS uniformly) and CORS-preflight replies, and discards their
  OPTIONS evidence
- Fingerprints 404 responses and strips reflected request targets to avoid
  false positives

## References
- https://guides.rubyonrails.org/active_storage_overview.html
- https://guides.rubyonrails.org/action_mailbox_basics.html`

	ModuleConfirmation = "Confirmed when an Active Storage / Action Mailbox OPTIONS probe returns a 2xx Allow header advertising POST, or a blob route redirects to a stored object"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "misconfiguration", "file-exposure", "light"}
)
