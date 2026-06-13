package sensitive_file_discovery

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

// TestScanPerRequest_DotEnvConfirmed serves a genuine dotenv file with real
// KEY=VALUE assignment lines and asserts the Critical finding fires.
func TestScanPerRequest_DotEnvConfirmed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("APP_KEY=base64:abcdef0123456789\nDB_PASSWORD=s3cr3t\nMAIL_HOST=smtp.example.com\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /.env exposes real KEY=VALUE assignments")
}

// TestScanPerRequest_DotEnvUnderStaticPath verifies the static-route walk: a
// misconfigured CDN/static directory serves /assets/.env, and the observed
// request is a static asset under /assets. The module must derive the /assets
// base (a directory a known-endpoint probe would skip) and find the file there.
func TestScanPerRequest_DotEnvUnderStaticPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets/.env" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("APP_KEY=base64:abcdef0123456789\nDB_PASSWORD=s3cr3t\nMAIL_HOST=smtp.example.com\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/assets/js/app.js"), "application/javascript", "console.log(1)")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /assets/.env is exposed under a static directory")
	assert.Contains(t, res[0].URL, "/assets/.env", "the finding URL must point at the static-path mount")
}

// TestScanPerRequest_GitConfigUnderContextPath verifies the context-path walk: a
// .git/config is exposed under an app mounted at /app, and the observed request
// is to /app/dashboard. The module must derive the /app base and find it.
func TestScanPerRequest_GitConfigUnderContextPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/.git/config" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/secret.git\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/app/dashboard"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /app/.git/config is exposed under a context path")
	assert.Contains(t, res[0].URL, "/app/.git/config", "the finding URL must point at the context-path mount")
}

// TestScanPerRequest_LogCatchAllNoFalsePositive reproduces the user's exact case:
// a sub-directory handler serves the SAME log-looking body for every *.log path
// (a logging proxy / SPA fallback / object-store wildcard). /orders/error.log
// matches the error-log markers, but so does the decoy /orders/<random>.log, so
// the decoy-baseline round must drop it as a false positive.
func TestScanPerRequest_LogCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	const catchAll = "[error] stack trace\nException: boom\nFatal: nope\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every *.log under any directory returns the same body — a catch-all.
		if strings.HasSuffix(r.URL.Path, ".log") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(catchAll))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/orders/dashboard"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a *.log catch-all that serves the same body for every path (decoy included) must not yield a finding")
}

// TestScanPerRequest_DotEnvProseNoFalsePositive reproduces the "=" marker false
// positive: a non-env 200 body (JSON) that merely contains an equals sign and
// the words "SECRET"/"DB_" in prose — but no genuine KEY=VALUE line — must not
// yield a Critical finding. The old marker list included a bare "=", which
// matched any non-HTML body containing an equals sign.
func TestScanPerRequest_DotEnvProseNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "application/json")
			// Contains "=", "SECRET", and "DB_" but no KEY=VALUE assignment line.
			_, _ = w.Write([]byte(`{"note":"this SECRET DB_HOST page intentionally left blank = nope"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-env body with a stray '=' must not yield a Critical .env finding")
}
