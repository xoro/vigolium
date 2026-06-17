package default_credentials

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// loginEndpoint represents a detected login form with field names.
type loginEndpoint struct {
	usernameField string
	passwordField string
	isJSON        bool
}

// detectLoginEndpoint checks if the request looks like a login form submission.
// Returns the detected endpoint or nil if not a login form.
func detectLoginEndpoint(ctx *httpmsg.HttpRequestResponse) *loginEndpoint {
	if ctx.Request() == nil {
		return nil
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	isFormEncoded := strings.Contains(ct, "application/x-www-form-urlencoded")
	isJSON := strings.Contains(ct, "application/json")

	if !isFormEncoded && !isJSON {
		return nil
	}

	raw := ctx.Request().Raw()

	// Check URL path for login patterns
	pathMatch := false
	urlx, err := ctx.URL()
	if err == nil {
		pathLower := strings.ToLower(urlx.Path)
		for _, pattern := range loginPathPatterns {
			if strings.Contains(pathLower, pattern) {
				pathMatch = true
				break
			}
		}
	}

	var usernameField, passwordField string

	if isJSON {
		// Parse JSON body to find field names
		body := ctx.Request().BodyToString()
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonBody); err != nil {
			return nil
		}

		for key := range jsonBody {
			keyLower := strings.ToLower(key)
			if usernameField == "" && matchesAny(keyLower, usernameParamNames) {
				usernameField = key
			}
			if passwordField == "" && matchesAny(keyLower, passwordParamNames) {
				passwordField = key
			}
		}
	} else {
		// Parse form-encoded body parameters
		bodyParams, err := httpmsg.GetBodyParametersMap(raw)
		if err != nil {
			return nil
		}
		for key := range bodyParams {
			keyLower := strings.ToLower(key)
			if usernameField == "" && matchesAny(keyLower, usernameParamNames) {
				usernameField = key
			}
			if passwordField == "" && matchesAny(keyLower, passwordParamNames) {
				passwordField = key
			}
		}
	}

	// Must have both username and password fields
	if usernameField == "" || passwordField == "" {
		return nil
	}

	// If path doesn't match login patterns, require strong field name signals
	if !pathMatch {
		// Be more conservative: both field names must be common login field names
		if !isStrongLoginField(strings.ToLower(usernameField)) || !isStrongLoginField(strings.ToLower(passwordField)) {
			return nil
		}
	}

	return &loginEndpoint{
		usernameField: usernameField,
		passwordField: passwordField,
		isJSON:        isJSON,
	}
}

// hasCAPTCHA checks if the response body contains CAPTCHA indicators.
func hasCAPTCHA(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, indicator := range captchaIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

// isLoginSuccess determines if a candidate login response indicates successful
// authentication, judged against a failed-login baseline (an invalid-credential
// attempt). All comparisons run against the response BODY and the Location
// header — never the full response string — so a fresh session cookie, a
// per-request request-id, or the clock cannot manufacture a "difference" between
// two identical-meaning rejections.
func isLoginSuccess(candidate, baseline credentialResponse) bool {
	sc := candidate.statusCode

	// Auth-challenge / rate-limit / WAF statuses are never a success. Credential
	// stuffing probes are frequently throttled (Cloudflare 429 + cf_chl_*/__cf_bm
	// cookies); a 401/403 is the expected rejection, not a login.
	if sc == 401 || sc == 403 || sc == 429 || sc == 503 {
		return false
	}

	candidateRedirect := isRedirect(sc)

	// Redirect responses: the decisive signal is WHERE the login redirects. A
	// rejected login bounces back to the login/error page (very commonly a
	// 303 → /login carrying a flash error), often while the framework sets a fresh
	// session cookie on every POST. Neither that redirect nor that cookie is
	// authentication.
	if candidateRedirect {
		if redirectsToLoginOrError(candidate.location) {
			return false // explicitly bounced to a login/error page
		}
		if isRedirect(baseline.statusCode) {
			if sameLocation(candidate.location, baseline.location) {
				return false // lands in the same place a rejected login does
			}
			// The failed login redirects to one place; this attempt redirects to a
			// distinct, non-error location — the login landed somewhere new (a
			// dashboard/home). That is a success.
			if candidate.location != "" {
				return true
			}
		}
	}

	// Transition from an auth challenge (401) to a non-challenge response.
	if baseline.statusCode == 401 && (sc == 200 || candidateRedirect) {
		return true
	}

	// A login form that re-renders (200) on failure but redirects on this attempt
	// is the classic post/redirect/get success — the login/error bounce was
	// already excluded above.
	if baseline.statusCode == 200 && candidateRedirect {
		return true
	}

	// Body-content success, computed on the response BODY only.
	return bodyShowsAuthSuccess(candidate, baseline)
}

// bodyShowsAuthSuccess reports authentication evidence drawn from the response
// body: an authenticated marker absent from the failed-login baseline, backed by
// a real body differential. An empty body (e.g. a pure redirect) carries no body
// signal, and a body indistinguishable from the failed-login page is not auth.
func bodyShowsAuthSuccess(candidate, baseline credentialResponse) bool {
	cBody := candidate.body
	if strings.TrimSpace(cBody) == "" {
		return false
	}
	if modkit.BodiesSimilar(cBody, baseline.body) {
		return false // same page the rejected login renders → page variance, not auth
	}

	cLower := strings.ToLower(cBody)
	baselineLower := strings.ToLower(baseline.body)
	for _, indicator := range successIndicators {
		// An indicator that ALSO appears in the failed-login baseline is not
		// auth-gated — it is page chrome/branding (the classic "dashboard" in
		// dashboard.example.com), so it cannot evidence a successful login.
		if strings.Contains(baselineLower, indicator) {
			continue
		}
		if strings.Contains(cLower, indicator) {
			return true
		}
	}

	// No explicit success word, but a fresh session cookie alongside a substantial
	// (not merely token-rotated) body change is a reasonable authenticated signal.
	if candidate.hasSetCookie {
		cSig := modkit.NewResponseSignature(0, cBody, "")
		bSig := modkit.NewResponseSignature(0, baseline.body, "")
		if modkit.HasSubstantialBodyDifference(cSig, bSig) {
			return true
		}
	}

	return false
}

// isRedirect reports whether a status code is an HTTP redirect.
func isRedirect(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// normalizeLocation reduces a Location header to scheme-less host+path (query
// and fragment dropped, trailing slash trimmed, lowercased) so two redirects
// that differ only by a per-request query token compare equal.
func normalizeLocation(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	if u, err := url.Parse(loc); err == nil {
		p := strings.TrimRight(u.Path, "/")
		if u.Host != "" {
			return strings.ToLower(u.Host) + strings.ToLower(p)
		}
		return strings.ToLower(p)
	}
	return strings.ToLower(strings.TrimRight(loc, "/"))
}

// sameLocation reports whether two Location headers point at the same target.
// Two empty locations are treated as the same.
func sameLocation(a, b string) bool {
	return normalizeLocation(a) == normalizeLocation(b)
}

// redirectsToLoginOrError reports whether a redirect target points back at a
// login or error page — the hallmark of a rejected login, not a success.
func redirectsToLoginOrError(loc string) bool {
	p := normalizeLocation(loc)
	if p == "" {
		return false
	}
	for _, kw := range loginErrorRedirectMarkers {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}

// probeShowsCaptchaGate reports whether a failed-login probe response reveals a
// captcha gate — inspected against the FULL response (raw), because the gate
// frequently surfaces only as a flash error in a Set-Cookie or an error body of
// the POST response rather than in the originally-observed page.
//
// It deliberately matches only "captcha"/"turnstile" rather than the broader
// body-scoped captchaIndicators list: those two substrings already subsume every
// captcha vendor token there (recaptcha/hcaptcha/g-recaptcha/cf-turnstile), while
// the list's bare "challenge" token is too generic to match against a full raw
// response (headers/cookies) without risking spurious bails.
func probeShowsCaptchaGate(cr credentialResponse) bool {
	haystack := strings.ToLower(cr.raw)
	return strings.Contains(haystack, "captcha") || strings.Contains(haystack, "turnstile")
}

// isLockout checks if the response indicates account lockout.
func isLockout(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, indicator := range lockoutIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if s == p {
			return true
		}
	}
	return false
}

func isStrongLoginField(name string) bool {
	strong := []string{"username", "user", "email", "login", "password", "passwd", "pass", "pwd"}
	for _, s := range strong {
		if name == s {
			return true
		}
	}
	return false
}
