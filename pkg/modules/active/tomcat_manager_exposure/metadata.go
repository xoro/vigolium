package tomcat_manager_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tomcat-manager-exposure"
	ModuleName  = "Tomcat Manager Exposure"
	ModuleShort = "Detects exposed Apache Tomcat Manager and Host Manager interfaces"
)

var (
	ModuleDesc = `**What it means:** An Apache Tomcat administrative or default endpoint is reachable. The scanner probes the Manager, Host Manager, status, examples, and docs apps, flagging a 200 with distinctive content or a 401 Tomcat auth challenge, and for the admin paths also tries reverse-proxy path-normalization bypasses (e.g. /..;/manager/html) that re-reach the manager when a proxy blocks the direct path. These leftover apps should not be exposed and indicate incomplete hardening and an oversized attack surface.

**How it's exploited:** The Manager and Host Manager let an authenticated user deploy WAR files and manipulate virtual hosts, so an attacker with default or weak credentials (e.g. tomcat/tomcat) can upload a malicious WAR for remote code execution and full server compromise. The status page leaks JVM, connector, and thread details; the example servlets and docs disclose the server version and may carry known vulnerabilities.

**Fix:** Remove or restrict the Manager, Host Manager, examples, and docs applications, and require strong credentials over TLS plus network access controls for any administrative interface that must remain.`

	ModuleConfirmation = "Confirmed when Tomcat Manager or Host Manager interface is accessible or prompts for authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"tomcat", "java", "misconfiguration", "authentication", "light"}
)
