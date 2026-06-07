package sensitive_file_discovery

import (
	"net/http"
	"net/http/httptest"
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
