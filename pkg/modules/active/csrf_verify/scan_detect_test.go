package csrf_verify

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const csrfSuccessBody = "<html><body>Item deleted successfully. Thank you.</body></html>"

// TestScanPerRequest_TokenIgnored fires when the server returns the SAME success
// page whether or not a valid CSRF token is present (token not validated).
func TestScanPerRequest_TokenIgnored(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csrfSuccessBody)) // same outcome regardless of token
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a server that returns the same success page without a valid token must be flagged")
	assert.Contains(t, res[0].Info.Name, "CSRF Token Not Validated")
}

// TestScanPerRequest_SoftReject200 ensures a server that returns a 200 but a
// DIFFERENT body (a CSRF-failure page) when the token is missing/invalid is NOT
// flagged — the body-equivalence gate distinguishes it from a real bypass.
func TestScanPerRequest_SoftReject200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Mutated requests get a clearly different CSRF-rejection page.
		_, _ = w.Write([]byte("<html><body>Security check failed: invalid CSRF token. " +
			"Your request was not processed. Please reload the form and try again.</body></html>"))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 CSRF-failure page (different body) must not be flagged as a bypass")
}

// TestScanPerRequest_HardReject ensures a 4xx rejection of mutated tokens yields
// no finding.
func TestScanPerRequest_HardReject(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 403 on mutated tokens means CSRF is enforced")
}
