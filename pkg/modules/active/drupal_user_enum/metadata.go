package drupal_user_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "drupal-user-enum"
	ModuleName  = "Drupal User Enumeration"
	ModuleShort = "Detects Drupal user enumeration via user profile paths and JSON:API"
)

var (
	ModuleDesc = `## Description
Tests for Drupal user enumeration through two vectors:
1. User profile paths: /user/1 through /user/5, checking for redirects to /users/<username> or a Drupal-rendered 200 profile page whose title leaks the username
2. JSON:API user listing: /jsonapi/user/user returns user objects anonymously

Enumerated usernames can be used for password brute-force attacks.

## False-positive controls
- Block gate: WAF/CDN challenge, auth-gate (401/403), rate-limit (429), and maintenance (503) responses are skipped before any extraction (an SSO wall or CloudFront error page is the edge talking, not the application leaking a profile).
- Baseline control: a UID far beyond any real account is probed first; any real /user/N yielding the same candidate is reading the site's generic unknown-user page, not a leak, and is dropped.
- Uniformity guard: genuine enumeration leaks a distinct username per UID, so 2+ UIDs collapsing to a single value are rejected.
- Title corroboration: the 200/title vector is trusted only when the response is recognisably Drupal (X-Generator/X-Drupal-* headers or Drupal body markers) and the title is not a generic error/auth/status title (e.g. "404 Not Found", "Access denied").
- Reserved routes: redirects to Drupal's own /user/<login|logout|register|password|reset|edit|cancel> are not treated as usernames.

## Notes
- Runs once per host
- Tests user IDs 1 through 5 plus a baseline control UID
- Checks JSON:API endpoint for anonymous user data access
- Non-destructive: only performs GET requests

## References
- https://www.drupal.org/docs/security-in-drupal
- https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module`

	ModuleConfirmation = "Confirmed when /user/N profile paths leak distinct usernames (via /users/<name> redirect or a Drupal-corroborated 200 profile title that differs from the unknown-user baseline) or JSON:API returns user objects"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"drupal", "php", "info-disclosure", "probe", "moderate"}
)
