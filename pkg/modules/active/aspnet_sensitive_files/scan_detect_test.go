package aspnet_sensitive_files

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsWebConfig serves an exposed ASP.NET web.config. The
// module fingerprints a random 404 then probes the sensitive-file paths and should
// flag /web.config (200 + <configuration>/<system.web> markers, no anti-markers).
func TestScanPerRequest_DetectsWebConfig(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/web.config" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<configuration><system.web><compilation debug=\"true\"/></system.web></configuration>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a sensitive-file finding when /web.config is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures an HTML 404 (matching the
// defaultAntiMarkers) for every probe produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html><html>404 Not Found</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed sensitive files must not yield a finding")
}

// TestScanPerRequest_DetectsPermissiveCrossDomain serves a crossdomain.xml with a
// wildcard `domain="*"` allow rule. The confirmAny gate is satisfied, so the module
// flags it as Low severity with a title that does not falsely claim "ASP.NET".
func TestScanPerRequest_DetectsPermissiveCrossDomain(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crossdomain.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a finding for a wildcard cross-domain policy")
	assert.Equal(t, severity.Low, res[0].Info.Severity, "wildcard cross-domain policy is Low severity")
	assert.NotContains(t, res[0].Info.Name, "ASP.NET", "cross-domain policy finding must not claim ASP.NET")
	assert.Contains(t, strings.Join(res[0].ExtractedResults, " "), `domain="*"`, "the permissive signal is surfaced")
}

// TestScanPerRequest_ScopedCrossDomainNoFinding reproduces the Netflix false positive:
// a crossdomain.xml scoped to a specific domain (`domain="*.example.com"`) is benign and
// must NOT be flagged, since the confirmAny wildcard signals never match a scoped policy.
func TestScanPerRequest_ScopedCrossDomainNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crossdomain.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<cross-domain-policy>\n<allow-access-from domain=\"*.example.com\"/>\n</cross-domain-policy>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a domain-scoped cross-domain policy must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
