package ssti_detection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerInsertionPoint_LargeHTMLSurfaceSkipped covers the differential
// surface gate: a large rendered HTML baseline is an unreliable softBase-vs-probe
// oracle (cache HIT/MISS swings and per-request dynamic content manufacture phantom
// differentials), so the scan must short-circuit before sending any probe traffic.
// The existing tests (no captured response → gate fails open) are the control
// proving the gate doesn't break normal operation.
func TestScanPerInsertionPoint_LargeHTMLSurfaceSkipped(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("x", 100) + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	bigHTML := "<html><body>" + strings.Repeat("<div>x</div>", 20000) + "</body></html>" // >100 KB

	rr := modtest.RequestMethod(t, "GET", srv.URL+"/?q=widget", "")
	rr = modtest.Response(rr, "text/html", bigHTML)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a large HTML content page is an unreliable SSTI-diff surface and must be skipped")
	assert.Zero(t, atomic.LoadInt64(&hits), "surface gate should send no probe traffic on a large HTML page")
}
