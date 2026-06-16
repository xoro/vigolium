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
