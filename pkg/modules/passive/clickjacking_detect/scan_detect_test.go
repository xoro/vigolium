package clickjacking_detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	loginForm  = `<html><body><form method="post" action="/login"><input type="password" name="p"><button>Login</button></form></body></html>`
	newsletter = `<html><body><form method="post" action="/subscribe"><input type="email" name="e"><button>Register</button></form></body></html>`
	staticPage = `<html><body><h1>About us</h1><p>Marketing content with a <a href="/blog">Blog</a> link.</p></body></html>`
	authPanel  = `<html><body><button onclick="del()">Delete account</button></body></html>`
)

func statusText(code int) string {
	switch code {
	case 403:
		return "Forbidden"
	case 302:
		return "Found"
	default:
		return "OK"
	}
}

// makeCtx builds a request/response pair from raw header lines and a body.
func makeCtx(status int, respHeaders []string, body string, reqHeaders []string) *httpmsg.HttpRequestResponse {
	rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n"
	for _, h := range reqHeaders {
		rawReq += h + "\r\n"
	}
	rawReq += "\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)

	rawResp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, statusText(status))
	for _, h := range respHeaders {
		rawResp += h + "\r\n"
	}
	rawResp += "\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

const ctHTML = "Content-Type: text/html"

func run(t *testing.T, ctx *httpmsg.HttpRequestResponse) []*severity.Severity {
	t.Helper()
	results, err := New().ScanPerHost(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	out := make([]*severity.Severity, 0, len(results))
	for _, r := range results {
		s := r.Info.Severity
		out = append(out, &s)
	}
	return out
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// --- Positives ---

func TestMedium_AuthenticatedCredentialForm(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML}, loginForm, []string{"Cookie: sessionid=abc123"})
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Medium, *sev[0])
}

// CSP frame-ancestors '*' overrides X-Frame-Options: DENY — the page is framable
// despite the (ignored) XFO header.
func TestMedium_FrameAncestorsOverridesXFO(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "X-Frame-Options: DENY", "Content-Security-Policy: frame-ancestors *"},
		authPanel, []string{"Cookie: JSESSIONID=xyz"})
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Medium, *sev[0])
}

// Duplicated, conflicting X-Frame-Options values are discarded by browsers.
func TestMedium_ConflictingXFO(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "X-Frame-Options: DENY", "X-Frame-Options: SAMEORIGIN"},
		loginForm, []string{"Cookie: auth_token=t"})
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Medium, *sev[0])
}

// A login (credential) page with no observed auth session is a Low finding.
func TestLow_CredentialFormNoAuth(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML}, loginForm, nil)
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Low, *sev[0])
}

// A Strict session cookie means the cross-site frame loads unauthenticated, so
// an otherwise-Medium finding is downgraded to Low.
func TestSameSiteDowngrade(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "Set-Cookie: sessionid=abc; SameSite=Strict; HttpOnly"}, loginForm, nil)
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Low, *sev[0])
}

// --- Negatives ---

func TestNeg_XFOSameOrigin(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "X-Frame-Options: SAMEORIGIN"}, loginForm, []string{"Cookie: sessionid=abc"})
	assert.Empty(t, run(t, ctx))
}

func TestNeg_FrameAncestorsSelf(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "Content-Security-Policy: frame-ancestors 'self'"}, loginForm, []string{"Cookie: sessionid=abc"})
	assert.Empty(t, run(t, ctx))
}

func TestNeg_FrameAncestorsNone(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "X-Frame-Options: DENY", "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'"}, loginForm, nil)
	assert.Empty(t, run(t, ctx))
}

// Framable but static (no interactive/sensitive content) — deferred to the
// header-hygiene siblings.
func TestNeg_FramableStaticPage(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML}, staticPage, nil)
	assert.Empty(t, run(t, ctx))
}

// A newsletter signup form (POST, no password, non-sensitive action, no auth) is
// not a meaningful clickjacking target.
func TestNeg_NewsletterForm(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML}, newsletter, nil)
	assert.Empty(t, run(t, ctx))
}

func TestNeg_Non200Status(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(403, []string{ctHTML}, loginForm, nil)
	assert.Empty(t, run(t, ctx))
}

func TestNeg_NonHTML(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{"Content-Type: application/json"}, loginForm, nil)
	assert.Empty(t, run(t, ctx))
}

func TestNeg_ChallengeInterstitial(t *testing.T) {
	t.Parallel()
	body := `<html><body><div id="cf">window._cf_chl_opt={};</div><form method="post" action="/login"><input type="password"></form></body></html>`
	ctx := makeCtx(200, []string{ctHTML}, body, nil)
	assert.Empty(t, run(t, ctx))
}

// CSP report-only does not enforce, so frame-ancestors there must not be treated
// as protection.
func TestPos_ReportOnlyCSPNotProtective(t *testing.T) {
	t.Parallel()
	ctx := makeCtx(200, []string{ctHTML, "Content-Security-Policy-Report-Only: frame-ancestors 'none'"},
		loginForm, []string{"Cookie: sessionid=abc"})
	sev := run(t, ctx)
	require.Len(t, sev, 1)
	assert.Equal(t, severity.Medium, *sev[0])
}

// CSRF token cookies must not be mistaken for a session (would over-promote a
// login page to Medium).
func TestCsrfCookieNotSession(t *testing.T) {
	t.Parallel()
	assert.False(t, isSessionName("csrf_token"))
	assert.False(t, isSessionName("XSRF-TOKEN"))
	assert.True(t, isSessionName("sessionid"))
	assert.True(t, isSessionName("JSESSIONID"))
	assert.True(t, isSessionName("access_token"))
}

func TestFrameAncestorsRestrictive(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"'none'", true},
		{"'self'", true},
		{"https://trusted.example.com", true},
		{"", true},
		{"*", false},
		{"https:", false},
		{"'self' *", false},
	} {
		assert.Equalf(t, tc.want, frameAncestorsRestrictive(tc.val), "frame-ancestors %q", tc.val)
	}
}

func TestDescriptionCarriesPoC(t *testing.T) {
	t.Parallel()
	results, err := New().ScanPerHost(makeCtx(200, []string{ctHTML}, loginForm, []string{"Cookie: sessionid=abc"}), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, strings.Contains(results[0].Info.Description, "<iframe src="), "description should embed a PoC overlay")
	assert.Equal(t, ModuleID, results[0].ModuleID)
}
