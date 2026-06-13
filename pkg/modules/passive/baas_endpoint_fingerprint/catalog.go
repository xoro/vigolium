package baas_endpoint_fingerprint

import (
	"regexp"
	"strings"
)

// provider is one entry in the backend-service catalog. re matches an absolute
// endpoint URL for the provider; capture groups feed joinSubmatches() to derive
// the tenant/instance label (the recon-valuable part). gate is a lowercase
// literal substring the re always requires, used to build the cheap catalog
// pre-filter (providerGate). category groups providers for tagging.
//
// Deliberately EXCLUDED from this catalog (owned by dedicated modules):
//   - Firebase domains: *.firebaseio.com, *.firebaseapp.com, *.appspot.com,
//     *.cloudfunctions.net  → firebase_fingerprint
//   - Object storage: *.s3*.amazonaws.com, storage.googleapis.com, Azure Blob,
//     etc.                    → cloud_storage_* modules
type provider struct {
	name     string   // stable id, used in dedup keys and metadata
	label    string   // human label for the finding name
	category string   // identity | baas | serverless | data | observability
	tags     []string // extra classification tags
	re       *regexp.Regexp
	gate     string // lowercase literal the re requires (feeds providerGate)
}

// joinSubmatches builds the instance/tenant label from a regex match by joining
// its non-empty submatches (m[1:]) — e.g. an Okta tenant or a Cognito region.
func joinSubmatches(m []string) string {
	var parts []string
	for _, g := range m[1:] {
		if g = strings.TrimSpace(g); g != "" {
			parts = append(parts, g)
		}
	}
	return strings.Join(parts, " / ")
}

// catalog is the ordered list of recognized providers.
var catalog = []provider{
	// ---- Identity / auth -------------------------------------------------
	{
		name: "okta", label: "Okta", category: "identity",
		tags: []string{"okta", "identity", "sso", "auth"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9][a-z0-9-]{1,62})\.(?:okta|oktapreview|okta-emea)\.com`),
		gate: "okta",
	},
	{
		name: "auth0", label: "Auth0", category: "identity",
		tags: []string{"auth0", "identity", "auth"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9][a-z0-9_-]{1,62})\.(?:[a-z0-9-]+\.)?auth0\.com`),
		gate: "auth0",
	},
	{
		name: "cognito-idp", label: "AWS Cognito (Identity Provider)", category: "identity",
		tags: []string{"cognito", "aws", "identity", "auth"},
		re:   regexp.MustCompile(`(?i)https?://cognito-idp\.([a-z0-9-]+)\.amazonaws\.com`),
		gate: "cognito-idp",
	},
	{
		name: "cognito-domain", label: "AWS Cognito (Hosted UI)", category: "identity",
		tags: []string{"cognito", "aws", "identity", "auth"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.auth\.([a-z0-9-]+)\.amazoncognito\.com`),
		gate: "amazoncognito",
	},
	{
		name: "entra", label: "Microsoft Entra ID", category: "identity",
		tags: []string{"entra", "azure-ad", "microsoft", "identity", "auth"},
		re:   regexp.MustCompile(`(?i)https?://login\.microsoftonline\.com/([a-z0-9][a-z0-9._-]{2,62})`),
		gate: "microsoftonline",
	},
	// ---- Backend-as-a-Service -------------------------------------------
	{
		name: "supabase", label: "Supabase", category: "baas",
		tags: []string{"supabase", "baas", "postgres", "database"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]{20})\.supabase\.(?:co|in|net)`),
		gate: "supabase",
	},
	{
		name: "convex", label: "Convex", category: "baas",
		tags: []string{"convex", "baas", "database"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.convex\.(?:cloud|site)`),
		gate: "convex",
	},
	{
		name: "appwrite", label: "Appwrite", category: "baas",
		tags: []string{"appwrite", "baas"},
		re:   regexp.MustCompile(`(?i)https?://(?:[a-z0-9-]+\.)?(?:cloud|fra|nyc|syd)\.appwrite\.io`),
		gate: "appwrite",
	},
	{
		name: "nhost", label: "Nhost", category: "baas",
		tags: []string{"nhost", "baas", "graphql"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]+)\.([a-z0-9-]+)\.nhost\.run`),
		gate: "nhost",
	},
	// ---- Serverless / functions / managed compute -----------------------
	{
		name: "lambda-url", label: "AWS Lambda Function URL", category: "serverless",
		tags: []string{"lambda", "aws", "serverless", "function"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]{16,})\.lambda-url\.([a-z0-9-]+)\.on\.aws`),
		gate: "lambda-url",
	},
	{
		name: "appsync", label: "AWS AppSync", category: "serverless",
		tags: []string{"appsync", "aws", "graphql", "serverless"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]{16,})\.appsync-api\.([a-z0-9-]+)\.amazonaws\.com`),
		gate: "appsync",
	},
	{
		name: "apigateway", label: "AWS API Gateway", category: "serverless",
		tags: []string{"api-gateway", "aws", "serverless"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]{8,})\.execute-api\.([a-z0-9-]+)\.amazonaws\.com`),
		gate: "execute-api",
	},
	{
		name: "cloud-run", label: "Google Cloud Run", category: "serverless",
		tags: []string{"cloud-run", "gcp", "serverless"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.([a-z0-9-]+)\.run\.app`),
		gate: "run.app",
	},
	{
		name: "azure-functions", label: "Azure App Service / Functions", category: "serverless",
		tags: []string{"azure-functions", "azure", "serverless"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9][a-z0-9-]{1,58})\.azurewebsites\.net`),
		gate: "azurewebsites",
	},
	{
		name: "cf-workers", label: "Cloudflare Workers", category: "serverless",
		tags: []string{"cloudflare-workers", "cloudflare", "serverless"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.([a-z0-9-]+)\.workers\.dev`),
		gate: "workers.dev",
	},
	// ---- Managed data / search / CMS ------------------------------------
	{
		name: "hasura", label: "Hasura", category: "data",
		tags: []string{"hasura", "graphql", "data"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.hasura\.app`),
		gate: "hasura",
	},
	{
		name: "algolia", label: "Algolia", category: "data",
		tags: []string{"algolia", "search", "data"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]{6,})(?:-dsn|-[0-9])?\.algolia(?:net)?\.(?:net|com)`),
		gate: "algolia",
	},
	{
		name: "contentful", label: "Contentful", category: "data",
		tags: []string{"contentful", "cms", "data"},
		re:   regexp.MustCompile(`(?i)https?://(?:cdn|preview|api)\.contentful\.com/spaces/([a-z0-9]+)`),
		gate: "contentful",
	},
	{
		name: "sanity", label: "Sanity", category: "data",
		tags: []string{"sanity", "cms", "data"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9]+)\.api(?:cdn)?\.sanity\.io`),
		gate: "sanity",
	},
	{
		name: "upstash", label: "Upstash", category: "data",
		tags: []string{"upstash", "redis", "data"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.upstash\.io`),
		gate: "upstash",
	},
	{
		name: "planetscale", label: "PlanetScale", category: "data",
		tags: []string{"planetscale", "mysql", "data"},
		re:   regexp.MustCompile(`(?i)https?://([a-z0-9-]+)\.([a-z0-9-]+)\.psdb\.cloud`),
		gate: "psdb",
	},
	// ---- Observability ---------------------------------------------------
	{
		name: "sentry", label: "Sentry", category: "observability",
		tags: []string{"sentry", "observability", "errors"},
		re:   regexp.MustCompile(`(?i)https?://[a-z0-9]+@(?:o([0-9]+)\.)?ingest\.(?:[a-z]{2}\.)?sentry\.io`),
		gate: "sentry",
	},
}

// providerGate is a cheap catalog-wide pre-filter built from every provider's
// gate token: if a body matches none of them, no provider regex can match, so
// the full 22-regex sweep is skipped. One case-insensitive pass, no allocation.
var providerGate = func() *regexp.Regexp {
	parts := make([]string, 0, len(catalog))
	for i := range catalog {
		parts = append(parts, regexp.QuoteMeta(catalog[i].gate))
	}
	return regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
}()
