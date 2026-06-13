package upgrade_routing_ssrf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

func hasUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// TestUpgradeSSRF_Positive: the proxy reaches the metadata host ONLY when the
// upgrade handshake is present. The module must confirm via the with/without
// differential and report exactly one finding.
func TestUpgradeSSRF_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "169.254.169.254") && hasUpgrade(r) {
			_, _ = io.WriteString(w, "ami-id: ami-0secret\ninstance-id: i-9\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 upgrade-bypass finding, got %d", len(res))
	}
	if !strings.Contains(strings.ToLower(strings.Join(res[0].ExtractedResults, " ")), "ami-id") {
		t.Errorf("finding should record the ami-id marker, got %v", res[0].ExtractedResults)
	}
	if res[0].Info.Confidence.String() != "tentative" {
		t.Errorf("in-band finding should be tentative, got %q", res[0].Info.Confidence.String())
	}
}

// TestUpgradeSSRF_HTMLPageNotMetadata: even when the upgrade differential holds, an
// HTML document (the app's own SPA page that happens to mention a marker word like
// window.location.hostname) is not a metadata response and must not be reported.
func TestUpgradeSSRF_HTMLPageNotMetadata(t *testing.T) {
	const spaIndex = `<!doctype html><html><head><title>app</title></head>` +
		`<body><script>const h = window.location.hostname;</script></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "metadata.google.internal") && hasUpgrade(r) {
			_, _ = io.WriteString(w, spaIndex) // HTML page, mentions "hostname"
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("an HTML page mentioning a marker word must not be reported, got %d: %+v", len(res), res)
	}
}

// TestUpgradeSSRF_Negative: a proxy that never reaches the metadata host. No
// finding regardless of the upgrade headers.
func TestUpgradeSSRF_Negative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><body>normal</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(res), res)
	}
}

// TestUpgradeSSRF_NoDoubleReport: a plain request-line routing SSRF — the marker
// is reachable WITH OR WITHOUT the upgrade headers. That is routing-ssrf's
// finding, not an upgrade bypass, so this module must stay silent.
func TestUpgradeSSRF_NoDoubleReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "169.254.169.254") {
			// Full marker cluster present regardless of Upgrade → plain routing SSRF.
			_, _ = io.WriteString(w, "ami-id: ami-0plain\ninstance-id: i-0plain\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("upgrade module must not double-report a plain routing SSRF, got %d: %+v", len(res), res)
	}
}
