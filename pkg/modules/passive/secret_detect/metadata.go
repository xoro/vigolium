package secret_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "secret-detect"
	ModuleName  = "Secret Detection"
	ModuleShort = "Detects leaked secrets and credentials in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A secret was found exposed in an HTTP response — an API key, access token, password, private key, or database connection string. This module passively scans text responses with the Kingfisher engine, so the secret is served to anyone who can reach it. Secrets Kingfisher validates as live are escalated to Critical. Matches seen only on a redirect (3xx) or in a response header are downgraded to Low, since these are usually an OAuth identifier echoed into a Location URL, not a leaked secret.

**How it's exploited:** An attacker who reads the response harvests the credential and reuses it against the matching service (cloud account, third-party API, database, signing key), gaining whatever access it grants. Leaked keys are routinely scraped from public pages, JS bundles, and config endpoints and abused for account takeover or data theft.

**Fix:** Remove the secret from the response, rotate the exposed credential immediately, and keep secrets in server-side configuration or a secrets manager, never in client-facing content.`

	ModuleConfirmation = "Confirmed when Kingfisher detects a known secret pattern in the HTTP response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
