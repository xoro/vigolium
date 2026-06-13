package spring_actuator_misconfig

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

// TestScanPerRequest_DetectsActuatorEnv drives the real scan method against a
// server that exposes a Spring Boot actuator /env endpoint: status 200, a JSON
// content type, and a body carrying the telltale "server.port" property. The
// module derives candidate paths from the seed path and probes each with the
// actuator payloads, so returning the env body for any path ending in /env
// fires detection.
func TestScanPerRequest_DetectsActuatorEnv(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/env") {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"activeProfiles":[],"propertySources":[{"name":"systemProperties","properties":{"server.port":{"value":"8080"},"local.server.port":{"value":"8080"}}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an actuator finding when /env returns server.port JSON")
}

// TestScanPerRequest_DetectsActuatorEnvViaPathBypass models a Spring Boot app
// behind a reverse proxy that blocks /actuator/* directly (403), while the
// Servlet stack still serves it once the `..;` path-parameter is normalized. The
// module must fall back to the path-normalization bypass and flag the finding.
func TestScanPerRequest_DetectsActuatorEnvViaPathBypass(t *testing.T) {
	t.Parallel()
	const envJSON = `{"activeProfiles":[],"propertySources":[{"name":"systemProperties","properties":{"server.port":{"value":"8080"},"local.server.port":{"value":"8080"}}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.RequestURI == "/actuator/env" || r.RequestURI == "/env":
			w.WriteHeader(http.StatusForbidden) // proxy blocks the direct path
		case strings.Contains(r.RequestURI, "..") && strings.HasSuffix(r.RequestURI, "/actuator/env"):
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(envJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an actuator finding via the /..;/ path-normalization bypass")
	assert.Contains(t, res[0].Info.Name, "path-normalization bypass")
	assert.Contains(t, res[0].Info.Tags, "acl-bypass")
	assert.Contains(t, strings.Join(res[0].ExtractedResults, ","), "/actuator/env",
		"the finding must record the bypass path used")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every actuator
// probe yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s all actuator paths must not yield a finding")
}

// TestScanPerRequest_KeycloakMessageBundleNoFalsePositive reproduces the reported
// false positive: a Keycloak-style i18n resource handler that serves the same
// application/json message bundle for every path. The bundle contains the bare
// words the old matchers keyed on ("status", "scope", an "...Beans" key) but
// none of the actuator-specific JSON shapes, so detection must not fire.
func TestScanPerRequest_KeycloakMessageBundleNoFalsePositive(t *testing.T) {
	t.Parallel()
	const bundle = `[{"key":"status","value":"Status"},` +
		`{"key":"scope","value":"Scope"},` +
		`{"key":"clientScope","value":"Client scope"},` +
		`{"key":"adminBeans","value":"Admin Beans"},` +
		`{"key":"loginStatus","value":"UP"},` +
		`{"key":"effectiveMessageBundlesHelp","value":"You can search for effective message bundles."}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(bundle))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/auth/resources/master/admin/health")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Keycloak i18n message bundle must not be reported as a Spring actuator endpoint")
}

// TestScanPerRequest_SubDirCatchAllSuppressed ensures the sibling-path guard
// rejects a catch-all handler scoped to a sub-directory prefix: every child of
// /auth/resources/master/admin/ returns an actuator-shaped health body, so even
// though the marker matches, a guaranteed-nonexistent sibling under the same
// directory returns the same body and the finding is dropped. The root-scoped
// soft-404 probe cannot catch this because the catch-all only fires under the
// prefix.
func TestScanPerRequest_SubDirCatchAllSuppressed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/resources/master/admin/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP","components":{"db":{"status":"UP"}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/auth/resources/master/admin/health")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a sub-directory catch-all that returns actuator JSON for every child path must be suppressed")
}

// TestScanPerRequest_RealHealthAtSinglePath confirms the sibling guard does NOT
// suppress a genuine actuator: only /health returns the status body, while a
// random sibling 404s, so the finding survives.
func TestScanPerRequest_RealHealthAtSinglePath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP","groups":["liveness","readiness"]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a real /health actuator returning a status body must still be detected")
}
