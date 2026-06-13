package laravel_misconfig

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

// TestScanPerRequest_CatchAllShellNoFalsePositive reproduces the catch-all/SPA
// false positive: a Laravel app whose router 200s every path with the same shell
// (which contains the generic word "telescope" in a JS bundle name and "Laravel"
// branding) must not be flagged as an exposed Telescope/Horizon dashboard,
// because the probe body equals the originally-observed page.
func TestScanPerRequest_CatchAllShellNoFalsePositive(t *testing.T) {
	t.Parallel()
	const shell = `<!DOCTYPE html><html><head><title>Laravel App</title>` +
		`<script src="/js/telescope-widget.js"></script></head><body>` +
		`<div id="app" data-page="dashboard">Welcome. Please sign in to continue.</div>` +
		`<footer>Powered by Laravel and Livewire</footer></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-laravel-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>The requested page could not be found.</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/dashboard"), "text/html", shell)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all Laravel shell must not yield a Telescope/Horizon finding")
}

// TestScanPerRequest_DetectsExposedAppLog drives the real scan method against a
// host that exposes /storage/logs/laravel.log. The module fingerprints a 404,
// then probes the Laravel paths; the log markers must surface a finding.
func TestScanPerRequest_DetectsExposedAppLog(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/logs/laravel.log" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[2024-01-01 00:00:00] production.ERROR: Something broke " +
				"{\"exception\":\"[object] (Illuminate\\\\Database\\\\QueryException...)\"}\n" +
				"[stacktrace]\n#0 /var/www/vendor/laravel/framework/src/foo.php(42)\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a misconfig finding when the Laravel app log is exposed")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "laravel misconfiguration")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s every probe must not yield a Laravel misconfig finding")
}
