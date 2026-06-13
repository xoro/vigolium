package baas_endpoint_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "baas-endpoint-fingerprint"
	ModuleName  = "BaaS Endpoint Fingerprint"
	ModuleShort = "Identifies third-party backend / identity / serverless providers referenced in responses"
)

var (
	ModuleDesc = `**What it means:** This passive check matches HTML, JavaScript, and JSON responses against a catalog of backend-as-a-service, identity, serverless, and managed-data providers — for example Okta, Auth0, AWS Cognito, Supabase, Convex, AWS Lambda function URLs, Google Cloud Run, Hasura, Algolia, Contentful, and Sentry. When a provider endpoint appears it records the provider, the category, and the tenant/instance identifier in the host. Detection is informational and sends no new traffic. Firebase and object-storage references are left to their dedicated modules.

**How it's exploited:** Each referenced backend is a distinct, externally hosted attack surface. The tenant identifier — an Okta org, a Supabase project ref, a Cognito user-pool region, a Convex deployment — tells an attacker which managed instance to probe for weak auth rules, public data, or misconfiguration, context a list of the primary host alone would not reveal.

**Fix:** Treat these identifiers as public, but enforce the provider's access controls (tenant rules, row-level security, signed access) so that knowing the endpoint does not grant data or account access.`

	ModuleConfirmation = "Confirmed when a known backend/identity/serverless provider endpoint is referenced in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"recon", "baas", "fingerprint", "light"}
)
