package dashboard_fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair with extra response headers and a body.
func makeHTTPCtx(headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + headers + "\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func TestScanPerRequest_GrafanaBody(t *testing.T) {
	t.Parallel()
	body := `<html><head><title>Grafana</title></head><body>` +
		`<script>window.grafanaBootData = {user:{}}</script></body></html>`
	res, err := New().ScanPerRequest(makeHTTPCtx("", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Grafana Detected", res[0].Info.Name)
	assert.Equal(t, "grafana", res[0].Metadata["product"])
}

func TestScanPerRequest_JenkinsHeaderWithVersion(t *testing.T) {
	t.Parallel()
	res, err := New().ScanPerRequest(makeHTTPCtx("X-Jenkins: 2.426.1\r\n", "<html>jenkins login</html>"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "jenkins", res[0].Metadata["product"])
	assert.Equal(t, "2.426.1", res[0].Metadata["version"])
}

// TestScanPerRequest_PassiveOnlyProduct verifies a product that has no active
// confirmer (presence handled entirely passively, e.g. Gitea) is still detected
// from its UI markers in crawled traffic.
func TestScanPerRequest_PassiveOnlyProduct(t *testing.T) {
	t.Parallel()
	body := `<html><body><footer>Powered by Gitea Version: 1.21.3 Page: 12ms</footer></body></html>`
	res, err := New().ScanPerRequest(makeHTTPCtx("", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "gitea", res[0].Metadata["product"])
}

func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	res, err := New().ScanPerRequest(makeHTTPCtx("", "<html><body>a normal marketing landing page</body></html>"), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestScanPerRequest_MarksTech verifies the product is published to the
// TechRegistry so the active prober can pick up the hint.
func TestScanPerRequest_MarksTech(t *testing.T) {
	t.Parallel()
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	body := `<html><head><title>Grafana</title></head><body>` +
		`<script>window.grafanaBootData={}</script></body></html>`
	_, err := New().ScanPerRequest(makeHTTPCtx("", body), sc)
	require.NoError(t, err)
	assert.True(t, sc.TechStack.Has("example.com", "grafana"))
	assert.True(t, sc.TechStack.Has("example.com", "dashboard"))
}
