package dashboard_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "dashboard-exposure"
	ModuleName  = "Exposed Third-Party Dashboard"
	ModuleShort = "Probes for exposed third-party dashboards/consoles (Grafana, Airflow, GitLab, Jenkins, Ollama, ...) and unauthenticated version/config/data leaks"

	ModuleDesc = `**What it means:** A known third-party dashboard, admin console, or self-hosted app — Grafana, Airflow, GitLab, Jenkins, Kibana, Elasticsearch, Vault, an OpenAI-compatible LLM API, a database console, and more — is reachable on this host. The module confirms the product by probing its health, version, and config endpoints. When such an endpoint returns internal data (version, full configuration, model list, cluster status) without authentication, it is reported as a High-severity information leak; otherwise the reachable console is reported as attack surface.

**How it's exploited:** Off-the-shelf consoles are high-value targets. Attackers match the confirmed product and version against default-credential lists and known CVEs, then pivot through any unauthenticated endpoint — a leaked version pins the exact exploit, an open model list reveals an unauthenticated inference endpoint, and an exposed agent config dumps internal topology.

**Fix:** Put the console behind authentication, an allow-list, or a VPN; disable or restrict unauthenticated health/version/config/data endpoints; remove default credentials and setup tokens; and keep the product patched.`

	ModuleConfirmation = "A request to a product-specific endpoint returned a response matching that product's fingerprint; UnauthLeak endpoints additionally disclosed internal data without authentication."
)

var (
	ModuleSeverity   = severity.Medium
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"dashboard", "exposure", "discovery", "info-leak", "light"}
)
