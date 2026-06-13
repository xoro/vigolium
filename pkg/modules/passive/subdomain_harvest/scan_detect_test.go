package subdomain_harvest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds a request/response pair served from the given host.
func makeHTTPCtx(host, path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(host, 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// navifyBundle mirrors the real-world minified config blob this module targets:
// in-scope *.navify.com subdomains alongside third-party hosts that must be
// excluded (different registrable domains).
const navifyBundle = `const X={production:!0,origin:"https://cds-apps-harvester-dev.hi5.platform.navify.com",` +
	`firebase:{authDomain:"harvester-dev-env.firebaseapp.com",databaseURL:"https://harvester-dev-env.firebaseio.com"},` +
	`okta:{orgUrl:"https://rocherapid-test.okta.com",customTokenUrl:"https://europe-west1-harvester-dev-env.cloudfunctions.net/okta-customToken"},` +
	`gdlApps:{NTB:{url:"https://su-appsdev.appsdev-tumorboard.hi5.platform.navify.com"},` +
	`NCH:{url:"https://su-appsdev.appsdev-nch.hi5.clinicalhub.platform.navify.com"}}}`

func TestScanPerRequest_OrgSubdomainsOnly(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("app.navify.com", "/main.js", "application/javascript", navifyBundle)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	got := results[0].ExtractedResults
	// In-scope navify.com subdomains are captured.
	assert.Contains(t, got, "cds-apps-harvester-dev.hi5.platform.navify.com")
	assert.Contains(t, got, "su-appsdev.appsdev-tumorboard.hi5.platform.navify.com")
	assert.Contains(t, got, "su-appsdev.appsdev-nch.hi5.clinicalhub.platform.navify.com")

	// Third-party hosts (different registrable domains) are NOT subdomains and
	// must be left to the BaaS/Firebase modules.
	for _, h := range got {
		assert.NotContains(t, h, "okta.com")
		assert.NotContains(t, h, "firebaseapp.com")
		assert.NotContains(t, h, "firebaseio.com")
		assert.NotContains(t, h, "cloudfunctions.net")
	}

	// The dev/staging-looking subdomains earn the non-prod tag (severity stays INFO).
	assert.Contains(t, results[0].Info.Tags, "non-prod")
	assert.Equal(t, ModuleSeverity, results[0].Info.Severity)
}

func TestScanPerRequest_ExcludesOwnHost(t *testing.T) {
	t.Parallel()
	m := New()
	body := `links={self:"https://app.navify.com/home",other:"https://api.navify.com/v1"}`
	ctx := makeHTTPCtx("app.navify.com", "/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, []string{"api.navify.com"}, results[0].ExtractedResults)
}

func TestScanPerRequest_NoSubdomains(t *testing.T) {
	t.Parallel()
	m := New()
	// Only third-party hosts, no sibling navify.com subdomains.
	body := `<html><script src="https://cdn.jsdelivr.net/x.js"></script><link href="https://fonts.googleapis.com/css"></html>`
	ctx := makeHTTPCtx("app.navify.com", "/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SkipsStaticAndIP(t *testing.T) {
	t.Parallel()
	m := New()

	// Binary/asset content type is skipped even with a host in the "body".
	imgCtx := makeHTTPCtx("app.navify.com", "/logo.png", "image/png", "https://api.navify.com/x")
	res, err := m.ScanPerRequest(imgCtx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)

	// Served from a raw IP: no resolvable registrable domain, so nothing to scope.
	ipCtx := makeHTTPCtx("10.0.0.5", "/", "text/html", `x="https://api.navify.com/v1"`)
	res, err = m.ScanPerRequest(ipCtx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
