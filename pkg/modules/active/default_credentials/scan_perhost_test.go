package default_credentials

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const loginFormBody = "username=seed&password=seed&csrf_token=abc123"

// TestScanPerHost_TruePositive_DefaultCreds confirms a genuine default-credential
// success is still reported after the added stable-baseline + reproduce +
// negative-control confirmation: invalid logins return a stable 401, admin/admin
// returns a distinct authenticated page.
func TestScanPerHost_TruePositive_DefaultCreds(t *testing.T) {
	t.Parallel()
	dash := "<html>Welcome to your dashboard, admin! " + strings.Repeat("account settings ", 30) + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Set-Cookie", "session=abc")
		if r.PostFormValue("username") == "admin" && r.PostFormValue("password") == "admin" {
			_, _ = fmt.Fprint(w, dash)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, "<html>Invalid credentials</html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login", loginFormBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a genuine admin/admin default credential must still be reported")
	require.Contains(t, res[0].ExtractedResults, "Username: admin")
}

// TestScanPerHost_NoFalsePositive_VolatileLoginPage is the headline regression: a
// login surface whose failed-login page varies per request (rotating content)
// must not yield a finding. The two baseline probes disagree, so the endpoint is
// judged too volatile to trust any later "success" differential — exactly the
// dynamic-page false positive the single-baseline design was prone to.
func TestScanPerHost_NoFalsePositive_VolatileLoginPage(t *testing.T) {
	t.Parallel()
	pageA := "<html>Login failed. " + strings.Repeat("alpha bravo charlie ", 20) + "</html>"
	pageB := "<html>Sign-in error. " + strings.Repeat("zeta omega sigma ", 20) + "</html>"
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Set-Cookie", "session=abc") // cookie on every response, even failures
		if atomic.AddInt64(&n, 1)%2 == 0 {
			_, _ = fmt.Fprint(w, pageA)
			return
		}
		_, _ = fmt.Fprint(w, pageB)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login", loginFormBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a volatile login page must not be reported as default credentials")
}

// TestScanPerHost_NoFalsePositive_CaptchaGateUniformRejection is the headline
// chope.co regression: a login fronted by a captcha rejects EVERY credential
// identically — 303 → /login, empty body, a fresh per-request session cookie
// carrying a "Captcha is invalid" flash. Because the body is empty, the only
// thing that differs between two attempts is the volatile Set-Cookie / request-id
// in the headers; comparing those (the old full-response-string comparison) used
// to manufacture a phantom success for admin/admin.
func TestScanPerHost_NoFalsePositive_CaptchaGateUniformRejection(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt64(&n, 1)
		// Fresh session id + captcha flash on every POST, regardless of credentials.
		w.Header().Set("Set-Cookie", fmt.Sprintf(
			"sph_s=a%%3A2%%3A%%7Bsession_id%%3D%032x%%3Bflash%%3DCaptcha%%20is%%20invalid%%7D; path=/", i))
		w.Header().Set("X-Request-Id", fmt.Sprintf("req-%032x", i*2654435761))
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther) // 303, empty body
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login/do_login", "username=seed&password=seed&code=")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a captcha-gated login that rejects every credential identically must not be reported")
}

// TestScanPerHost_NoFalsePositive_UniformRedirectRejection covers the same
// uniform-rejection class WITHOUT any captcha text: every credential gets the
// identical 303 → /login with an empty body and a rotating session cookie. The
// Location-differential guard (same redirect target as the failed baseline, and
// the target is itself a login page) must drop it independently of captcha
// detection.
func TestScanPerHost_NoFalsePositive_UniformRedirectRejection(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt64(&n, 1)
		w.Header().Set("Set-Cookie", fmt.Sprintf("sess=%032x; path=/", i))
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login/do_login", loginFormBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a login that redirects every credential back to /login must not be reported")
}

// TestScanPerHost_TruePositive_RedirectToDashboard confirms a genuine
// redirect-based success is still reported: failed logins bounce to /login, but
// admin/admin redirects to a distinct /dashboard. The body is empty in both
// cases, so the verdict rests entirely on the Location differential.
func TestScanPerHost_TruePositive_RedirectToDashboard(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt64(&n, 1)
		_ = r.ParseForm()
		w.Header().Set("Set-Cookie", fmt.Sprintf("sess=%032x; path=/", i))
		if r.PostFormValue("username") == "admin" && r.PostFormValue("password") == "admin" {
			w.Header().Set("Location", "/dashboard")
		} else {
			w.Header().Set("Location", "/login")
		}
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login/do_login", loginFormBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a login that redirects admin/admin to a distinct dashboard must be reported")
	require.Contains(t, res[0].ExtractedResults, "Username: admin")
}

// TestScanPerHost_NoFalsePositive_EdgeBlocked confirms a login fronted by a WAF/CDN
// (403 from Cloudflare) is skipped rather than mined for a credential differential.
func TestScanPerHost_NoFalsePositive_EdgeBlocked(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "<html>error code: 1020</html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login", loginFormBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a WAF/CDN-blocked login surface must not be reported")
}
