package swagger_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsContextPathSwagger verifies the context-path walk: a
// service mounts its Swagger UI under an API-gateway prefix at /orders/swagger-ui.html
// (NOT at the web root), and the observed request is to /orders/items. The module
// must derive the /orders base and find the UI there.
func TestScanPerRequest_DetectsContextPathSwagger(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orders/swagger-ui.html" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><head><title>Swagger UI</title></head>` +
				`<body><div id="swagger-ui"></div>` +
				`<script>const ui = SwaggerUIBundle({url: '/orders/v3/api-docs'})</script></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/orders/items")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for Swagger UI mounted under the /orders context path")
	assert.Contains(t, res[0].URL, "/orders/swagger-ui.html", "the finding URL must point at the context-path mount")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every swagger probe
// (under root and any context path) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/orders/items")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s all swagger paths must not yield a finding")
}
