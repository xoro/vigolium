package wp_misconfig

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

// TestScanPerRequest_DetectsExposedConfig drives the real scan method against a
// host that serves wp-config.php as plaintext. The module fingerprints a 404
// first, then probes fixed WordPress paths and matches markers on a 200.
func TestScanPerRequest_DetectsExposedConfig(t *testing.T) {
	t.Parallel()
	wpConfig := "<?php\n" +
		"define('DB_NAME', 'wordpress');\n" +
		"define('DB_USER', 'wp_admin');\n" +
		"define('DB_PASSWORD', 's3cret');\n" +
		"define('AUTH_KEY', 'put-your-unique-phrase-here');\n" +
		"define('LOGGED_IN_SALT', 'another-unique-phrase');\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-config.php" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(wpConfig))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when wp-config.php is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every WordPress
// probe path yields no finding.
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
	assert.Empty(t, res, "404 responses must not yield a WordPress misconfiguration finding")
}

// TestScanPerRequest_WpCronSpecificEmpty200 fires the wp-cron finding only when
// the empty 200 is specific to wp-cron.php (a random .php path 404s).
func TestScanPerRequest_WpCronSpecificEmpty200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-cron.php" {
			w.WriteHeader(http.StatusOK) // empty body — functional wp-cron
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	names := make([]string, 0, len(res))
	for _, r := range res {
		names = append(names, r.Info.Name)
	}
	assert.Contains(t, names, "WordPress Cron Externally Triggerable")
}

// TestScanPerRequest_WpCronBlanketEmpty200 reproduces a host that returns an
// empty 200 for ANY .php path (e.g. PHP misconfigured) while serving a normal
// 404 page for other paths. The wp-cron empty-200 is not specific, so the
// control-probe gate must drop it.
func TestScanPerRequest_WpCronBlanketEmpty200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".php") {
			w.WriteHeader(http.StatusOK) // every .php path returns a blank 200
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	names := make([]string, 0, len(res))
	for _, r := range res {
		names = append(names, r.Info.Name)
	}
	assert.NotContains(t, names, "WordPress Cron Externally Triggerable",
		"a blanket empty-200 for any .php path must not fire wp-cron")
}
