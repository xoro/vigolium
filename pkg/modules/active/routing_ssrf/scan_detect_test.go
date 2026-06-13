package routing_ssrf

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

func absoluteForm(requestURI string) bool {
	return strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://")
}

// TestRoutingSSRF_Positive: a proxy that, when the request line names the AWS
// metadata host, fetches it and returns its content. The module must connect to
// the victim, write the absolute-form target, see the ami-id marker, confirm it,
// and report exactly one High finding.
func TestRoutingSSRF_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "169.254.169.254") {
			_, _ = io.WriteString(w, "ami-id: ami-0abc123\ninstance-id: i-0deadbeef\nlocal-hostname: ip-10-0-0-5\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	got := res[0]
	if !strings.Contains(strings.ToLower(strings.Join(got.ExtractedResults, " ")), "ami-id") {
		t.Errorf("finding should record the ami-id marker, got %v", got.ExtractedResults)
	}
	if got.Info.Severity.String() == "" || got.Info.Confidence.String() == "" {
		t.Errorf("finding missing severity/confidence: %+v", got.Info)
	}
	// The in-band oracle cannot prove the marker came from metadata (vs the app's
	// own page), so it is reported only as Tentative — the strong, Certain signal is
	// the out-of-band OAST callback.
	if got.Info.Confidence.String() != "tentative" {
		t.Errorf("in-band finding should be tentative, got %q", got.Info.Confidence.String())
	}
}

// TestRoutingSSRF_HTMLPageNotMetadata reproduces the reported false positive: a
// CloudFront/S3 SPA serves its index.html (a catch-all) for the metadata
// request-line target, and that HTML contains `window.location.hostname` — which
// substring-matches the GCP "hostname" marker. The body is an HTML document, not a
// plain metadata listing, so the module must NOT report.
func TestRoutingSSRF_HTMLPageNotMetadata(t *testing.T) {
	const spaIndex = `<!doctype html>
<html lang="en">
<head><title>message-center-webview</title></head>
<body>
  <div id="root"></div>
  <script>const isProd = window.location.hostname === 'victim.example';</script>
</body>
</html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SPA catch-all: the metadata absolute/protocol-relative target falls back to
		// the app's own index.html (which mentions window.location.hostname).
		if strings.Contains(r.RequestURI, "metadata.google.internal") {
			_, _ = io.WriteString(w, spaIndex)
			return
		}
		// Origin-form baseline (and every other target) yields no metadata token.
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/soap/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("an HTML SPA page echoing window.location.hostname must not be reported, got %d: %+v", len(res), res)
	}
}

// TestRoutingSSRF_SingleMarkerInsufficient: a plain-text response that carries only
// ONE curated token (a common word) must not confirm — a genuine metadata listing
// carries several together.
func TestRoutingSSRF_SingleMarkerInsufficient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if absoluteForm(r.RequestURI) {
			_, _ = io.WriteString(w, "the current region is ap-southeast-1\n") // only "region"
			return
		}
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a single generic token must not confirm, got %d: %+v", len(res), res)
	}
}

// TestRoutingSSRF_Negative: a plain proxy that ignores the absolute-form target
// and always serves the same page. No marker ever appears → no finding.
func TestRoutingSSRF_Negative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no findings for a non-routing proxy, got %d: %+v", len(res), res)
	}
}

// TestRoutingSSRF_DecoyGate: a catch-all that returns the metadata marker for ANY
// absolute-form target (but not for the origin-form baseline). The marker looks
// "fresh" vs the baseline, so the decoy-negative control is what must suppress it:
// the benign TEST-NET decoy also yields the marker, proving a canned page rather
// than a reached endpoint. The module must NOT report.
func TestRoutingSSRF_DecoyGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if absoluteForm(r.RequestURI) {
			// Canned plain-text page returned for ANY absolute target, carrying the
			// full marker cluster — looks "fresh" vs the baseline, so only the
			// decoy-negative control can unmask it as a catch-all.
			_, _ = io.WriteString(w, "ami-id: canned\ninstance-id: canned\nlocal-hostname: canned\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("decoy-negative gate must suppress a catch-all marker, got %d findings: %+v", len(res), res)
	}
}
