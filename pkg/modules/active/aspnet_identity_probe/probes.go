package aspnet_identity_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// NOTE: the generic OIDC discovery document at /.well-known/openid-configuration
	// is intentionally NOT probed here. It is public by design (OpenID Connect
	// Discovery 1.0) and not ASP.NET-specific, and it is already reported once by
	// probeOIDCDiscovery (a single Low finding with the extracted endpoint/scope/
	// grant metadata). Listing it here too would double-report the same URL.

	// IdentityServer / Duende endpoints
	{
		path:        "/connect/token",
		name:        "Token Endpoint",
		markers:     []string{"invalid_client", "invalid_grant", "unsupported_grant_type"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "OAuth2/OIDC token endpoint accessible, may be susceptible to brute force or credential stuffing without rate limiting",
	},
	{
		path:        "/connect/authorize",
		name:        "Authorization Endpoint",
		markers:     []string{"client_id", "redirect_uri", "response_type"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "OAuth2/OIDC authorization endpoint detected, confirming IdentityServer/Duende deployment",
	},
	{
		path:        "/.well-known/openid-configuration/jwks",
		name:        "JWKS Endpoint",
		markers:     []string{"\"kty\"", "\"kid\"", "\"n\":", "\"e\":"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "JSON Web Key Set endpoint exposed, revealing public signing keys used for token validation",
	},
	// Scaffolded ASP.NET Identity UI
	{
		path:        "/Identity/Account/Register",
		name:        "Identity Register (Scaffolded)",
		markers:     []string{"__RequestVerificationToken", "ConfirmPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET Identity registration page publicly accessible, potentially allowing unauthorized account creation",
	},
	{
		path:        "/Identity/Account/Login",
		name:        "Identity Login (Scaffolded)",
		markers:     []string{"__RequestVerificationToken", "RememberMe"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity scaffolded login page detected, confirming Identity UI deployment",
	},
	{
		path:        "/Identity/Account/ForgotPassword",
		name:        "Identity Password Reset",
		markers:     []string{"__RequestVerificationToken", "ForgotPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity password reset page exposed, may enable email enumeration",
	},
	// MVC-style Identity endpoints
	{
		path:        "/Account/Register",
		name:        "MVC Register",
		markers:     []string{"__RequestVerificationToken", "ConfirmPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET MVC registration endpoint publicly accessible",
	},
	// API-based Identity (ASP.NET Core 8+ Identity API endpoints)
	{
		path:        "/register",
		name:        "Identity API Register",
		markers:     []string{"DuplicateUserName", "PasswordTooShort", "\"errors\":{", "InvalidEmail"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "ASP.NET Core Identity API registration endpoint accessible, may allow unauthorized account creation via API",
	},
	{
		path:        "/manage/info",
		name:        "Identity API Manage Info",
		markers:     []string{"email", "isEmailConfirmed"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE", "401"},
		sev:         severity.High,
		desc:        "ASP.NET Core Identity management API accessible without proper authentication",
	},
}
