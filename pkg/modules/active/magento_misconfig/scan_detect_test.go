package magento_misconfig

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

// magentoHandler serves an exposed Magento 1.x local.xml for /app/etc/local.xml
// and a distinct 404 body for everything else (including the random 404
// fingerprint probe), so the real probe response diverges from the not-found
// fingerprint.
func magentoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/etc/local.xml" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?>
<config>
  <global>
    <resources>
      <default_setup>
        <connection>
          <dbname><![CDATA[magento]]></dbname>
        </connection>
      </default_setup>
    </resources>
    <crypt><key><![CDATA[deadbeef]]></key></crypt>
  </global>
</config>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerRequest_DetectsLocalXML drives the real scan method against a host
// that exposes Magento's local.xml and asserts the module reports a finding.
func TestScanPerRequest_DetectsLocalXML(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(magentoHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when local.xml is web-reachable")
	assert.True(t, strings.Contains(res[0].Info.Name, "Configuration"), "finding should name the config probe")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for every
// probed Magento path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed Magento files must not yield a finding")
}

// TestScanPerRequest_DeployedVersionConfirmed serves a real Magento
// deployed_version.txt (a bare timestamp token) and asserts the Info finding
// fires on the version-token shape.
func TestScanPerRequest_DeployedVersionConfirmed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/deployed_version.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("1530000000"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an Info finding when deployed_version.txt holds a version token")
	assert.True(t, strings.Contains(res[0].Info.Name, "Deployed Version"))
}

// TestScanPerRequest_DeployedVersionGenericBodyNoFalsePositive reproduces the
// "." marker false positive: a small non-version 200 text body (prose with
// spaces) on the version path must not yield a finding. The old "." marker
// matched any non-empty body; the version-token regex rejects whitespace-laden
// prose.
func TestScanPerRequest_DeployedVersionGenericBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/deployed_version.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Welcome to our store homepage"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-version text body on deployed_version.txt must not yield a finding")
}

// TestCanProcess covers the custom CanProcess gate: a request needs a response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no baseline response means not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}
