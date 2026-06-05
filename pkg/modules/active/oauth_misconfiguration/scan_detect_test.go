package oauth_misconfiguration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsRedirectURIManipulation drives the real scan method
// against a vulnerable OAuth authorization endpoint that reflects whatever
// redirect_uri it is handed straight into the 302 Location header. The module
// injects an attacker-controlled host (evil.example.com) and should observe it
// echoed back, flagging an OAuth open-redirect / redirect_uri manipulation.
//
// The request carries a state parameter so the (network-free) missing-state
// check stays quiet, keeping the finding attributable to redirect_uri handling.
func TestScanPerRequest_DetectsRedirectURIManipulation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: blindly redirect to the supplied redirect_uri.
		if ru := r.URL.Query().Get("redirect_uri"); ru != "" {
			w.Header().Set("Location", ru) // unvalidated redirect_uri
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an OAuth finding when the endpoint echoes a manipulated redirect_uri")

	var sawRedirectFinding bool
	for _, r := range res {
		if r.FuzzingParameter == "redirect_uri" {
			sawRedirectFinding = true
			break
		}
	}
	assert.True(t, sawRedirectFinding, "expected a redirect_uri manipulation finding among results")
}

// TestScanPerRequest_NoFalsePositive ensures a hardened OAuth endpoint yields no
// finding: it carries the CSRF state parameter, only ever redirects to a fixed
// allow-listed callback (never echoing the attacker host), and rejects a
// response_type downgrade with an OAuth error body. None of the three checks
// (redirect_uri manipulation, missing state, response_type downgrade) should fire.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject anything other than the authorization code flow.
		if rt := r.URL.Query().Get("response_type"); rt != "code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_response_type"}`))
			return
		}
		// Always redirect to the fixed, registered callback regardless of the
		// supplied redirect_uri — a properly validating authorization server.
		w.Header().Set("Location", "https://app.example.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a hardened OAuth endpoint must not yield a misconfiguration finding")
}

// TestScanPerRequest_HardcodedLocationNoFalsePositive reproduces a coincidental
// match: the endpoint always redirects to a FIXED location that happens to
// contain "evil.example.com", regardless of redirect_uri. The fresh-canary
// confirmation must drop it (the canary never appears in Location).
func TestScanPerRequest_HardcodedLocationNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fixed redirect, ignores redirect_uri; the string is hardcoded, not reflected.
		w.Header().Set("Location", "https://evil.example.com/hardcoded-marketing-link")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "redirect_uri", r.FuzzingParameter,
			"a hardcoded Location string that does not track the fresh canary must not be reported")
	}
}

// TestScanPerRequest_ResponseTypeNotValidatedNoFalsePositive reproduces an
// endpoint that accepts ANY response_type (no validation). response_type=token
// "passes", but so does an obviously invalid value, so the control gate must drop
// the downgrade finding.
func TestScanPerRequest_ResponseTypeNotValidatedNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always 302 to the fixed registered callback, never validating response_type
		// and never echoing redirect_uri.
		w.Header().Set("Location", "https://app.example.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "response_type", r.FuzzingParameter,
			"an endpoint that accepts any response_type must not be reported as a downgrade")
	}
}
