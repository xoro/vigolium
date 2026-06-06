package spring_actuator_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-actuator-misconfig"
	ModuleName  = "Spring Actuator Misconfiguration"
	ModuleShort = "Detects exposed Spring Boot actuator endpoints"
)

var (
	ModuleDesc = `## Description
Detects exposed Spring Boot Actuator endpoints that leak sensitive application
information such as environment variables, health status, and configuration.

## Notes
- Checks common actuator paths (/actuator, /env, /health, /info, /mappings, etc.)
- Runs per-request to detect misconfigured access controls
- Exposed actuators can leak secrets, internal URLs, and database credentials
- Each endpoint is confirmed by its actuator-specific JSON structure (e.g.
  "status":"UP" for /health, the propertySources envelope for /env, dotted
  Micrometer metric ids for /metrics) rather than a generic word match, and a
  sibling-path probe rejects catch-all handlers that 200 every child path

## References
- https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
- https://www.veracode.com/blog/research/exploiting-spring-boot-actuators`

	ModuleConfirmation = "Confirmed when an actuator path returns JSON matching that endpoint's specific actuator structure, the response is not the host's wildcard/soft-404 shell, and a guaranteed-nonexistent sibling under the same directory does not return the same content (ruling out catch-all handlers)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
