package dashboard_fingerprint

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "dashboard-fingerprint"
	ModuleName  = "Third-Party Dashboard Detected"
	ModuleShort = "Recognises self-hosted dashboards, admin consoles and developer tools (Grafana, Airflow, GitLab, Jenkins, Ollama, ...) in observed responses"

	ModuleDesc = `**What it means:** The response carries the fingerprint of a known third-party dashboard, admin console, or self-hosted application — for example Grafana, Apache Airflow, GitLab, Jenkins, Kibana, HashiCorp Vault, an OpenAI-compatible LLM API, or a database console. This is an attack-surface inventory signal: it records which off-the-shelf product is reachable so that product-specific exposure checks and known-CVE matching can follow.

**How it's exploited:** Attackers prioritise targets by the software running on them. Knowing a host serves, say, Grafana or Ollama lets them pull the matching default-credential lists, version-specific CVEs, and unauthenticated API tricks for that exact product instead of probing blind. The companion active check (dashboard-exposure) escalates to a real finding when the product additionally leaks version, configuration, or data without authentication.

**Fix:** Treat the presence of an admin/console product on an internet-facing host as a deliberate decision: put it behind authentication, an allow-list, or a VPN, keep it patched, and remove default credentials.`

	ModuleConfirmation = "A response matched a catalogued product fingerprint (unique header, body markers, or a distinctive cookie plus a name reference)."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"dashboard", "fingerprint", "discovery", "info"}
)
