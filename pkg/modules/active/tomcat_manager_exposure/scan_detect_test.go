package tomcat_manager_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsManager drives the real scan method against a host
// that serves an open Tomcat Web Application Manager. The module fingerprints a
// 404 first, then probes fixed Tomcat paths and matches markers on a 200.
func TestScanPerRequest_DetectsManager(t *testing.T) {
	t.Parallel()
	managerHTML := "<html><head><title>/manager</title></head><body>" +
		"<h1>Tomcat Web Application Manager</h1>" +
		"<p>Deploy directory or WAR file located on server</p>" +
		"<form><input value=\"Deploy\"><input value=\"Undeploy\"></form>" +
		"</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manager/html" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(managerHTML))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the Tomcat manager is exposed")
}

// TestScanPerRequest_DetectsAuthChallenge covers the 401 + WWW-Authenticate
// detection path: a manager that requires Basic auth still reveals Tomcat.
func TestScanPerRequest_DetectsAuthChallenge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manager/html" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a Tomcat auth challenge is returned")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "404 responses must not yield a Tomcat exposure finding")
}

// TestScanPerRequest_DetectsManagerViaPathBypass models the common production
// case: a reverse proxy blocks /manager/html directly (403), but Tomcat behind it
// collapses the `..;` path-parameter sequence so /..;/manager/html re-reaches the
// manager through the proxy's allow-list. The module must surface a finding flagged
// as a path-normalization bypass.
func TestScanPerRequest_DetectsManagerViaPathBypass(t *testing.T) {
	t.Parallel()
	managerHTML := "<html><head><title>/manager</title></head><body>" +
		"<h1>Tomcat Web Application Manager</h1>" +
		"<form><input value=\"Deploy\"><input value=\"Undeploy\"></form></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/manager/html": // proxy blocks the direct path
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 Forbidden"))
		case "/..;/manager/html", "/.;/manager/html": // Tomcat normalizes → manager
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(managerHTML))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("nope"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the manager is reachable via /..;/ bypass")

	var bypass *struct{ name, evidence string }
	for _, r := range res {
		if strings.Contains(r.Info.Name, "path-normalization bypass") {
			bypass = &struct{ name, evidence string }{r.Info.Name, strings.Join(r.ExtractedResults, ",")}
			assert.Contains(t, r.Info.Tags, "acl-bypass", "bypass finding must carry the acl-bypass tag")
			assert.Contains(t, strings.Join(r.ExtractedResults, ","), "/..;/manager/html",
				"bypass finding must record the bypass path used")
		}
	}
	require.NotNil(t, bypass, "expected a path-normalization-bypass finding")
}

// TestScanPerRequest_NoBypassDuplicateWhenDirectOpen ensures the bypass probe does
// not fire (a redundant duplicate) when the manager is already open on the direct
// path — the bypass only matters when the direct path is blocked.
func TestScanPerRequest_NoBypassDuplicateWhenDirectOpen(t *testing.T) {
	t.Parallel()
	managerHTML := "<h1>Tomcat Web Application Manager</h1><input value=\"Deploy\"><input value=\"Undeploy\">"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Tomcat is directly reachable: both the direct path AND any normalized
		// bypass form return the manager.
		if strings.Contains(r.RequestURI, "manager/html") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(managerHTML))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected the direct manager finding")
	for _, r := range res {
		assert.NotContains(t, r.Info.Name, "path-normalization bypass",
			"a directly-open manager must not also emit a redundant bypass finding")
	}
}
