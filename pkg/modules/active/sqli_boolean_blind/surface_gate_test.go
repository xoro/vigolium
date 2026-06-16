package sqli_boolean_blind

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_LargeHTMLSurfaceSkipped covers the boolean-differential
// surface gate: a large rendered HTML baseline (the chope ~200 KB marketing-page
// class) is an unreliable true/false oracle, so the scan must short-circuit before
// sending any probe traffic. A small HTML baseline, by contrast, must proceed to
// probing — proving the gate (not an unrelated precondition) is what suppresses it.
func TestScanPerRequest_LargeHTMLSurfaceSkipped(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>ok</html>") // identical regardless of payload
	}))
	defer srv.Close()
	client := modtest.Requester(t)

	bigHTML := "<html><body>" + strings.Repeat("<div>x</div>", 20000) + "</body></html>" // >100 KB

	// Large HTML baseline → gate short-circuits before any probe.
	rrBig := modtest.RequestMethod(t, "GET", srv.URL+"/search?q=widget", "")
	rrBig = modtest.Response(rrBig, "text/html", bigHTML)
	res, err := New().ScanPerRequest(rrBig, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan (large): %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("large HTML surface must be skipped, got %d findings", len(res))
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("surface gate should send no probe traffic on a large HTML page, got %d requests", n)
	}

	// Small HTML baseline → not gated; the scan proceeds and sends probes (it finds
	// nothing here because the server ignores the payload, but it must reach the wire).
	atomic.StoreInt64(&hits, 0)
	rrSmall := modtest.RequestMethod(t, "GET", srv.URL+"/search?q=widget", "")
	rrSmall = modtest.Response(rrSmall, "text/html", "<html>ok</html>")
	if _, err := New().ScanPerRequest(rrSmall, client, &modkit.ScanContext{}); err != nil {
		t.Fatalf("scan (small): %v", err)
	}
	if atomic.LoadInt64(&hits) == 0 {
		t.Fatal("a small HTML baseline must NOT be gated — the scan should have sent probes")
	}
}
