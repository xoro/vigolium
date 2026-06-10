package internal_header_probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// withACAH attaches a synthetic 200 response advertising acah via
// Access-Control-Allow-Headers so the module's CanProcess gate fires.
func withACAH(rr *httpmsg.HttpRequestResponse, acah string) *httpmsg.HttpRequestResponse {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
		"Access-Control-Allow-Headers: " + acah + "\r\nContent-Length: 0\r\n\r\n"
	return rr.WithResponse(httpmsg.NewHttpResponse([]byte(raw)))
}

const (
	homePage  = "<html><body><h1>Home</h1><p>Welcome guest, please sign in to continue.</p></body></html>"
	adminPage = "<html><body><h1>Administrative Dashboard</h1>" +
		"<p>Welcome back, operator. You have full access to the control plane.</p>" +
		"<ul><li>User management</li><li>Billing and invoices</li><li>Audit logs</li>" +
		"<li>Feature flags</li><li>Secret control panel</li><li>Service routing</li>" +
		"<li>Tenant administration</li></ul>" +
		"<footer>Internal build &mdash; do not distribute.</footer></body></html>"
)

// --- positive: a header whose value changes the response body ---

func TestScanPerRequest_ValueDependentHeader_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			_, _ = fmt.Fprint(w, adminPage)
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role, Content-Type, Authorization")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	f := res[0]
	if f.Info.Severity != severity.Suspect {
		t.Errorf("severity = %v, want Suspect", f.Info.Severity)
	}
	if f.Info.Confidence != severity.Tentative {
		t.Errorf("confidence = %v, want Tentative", f.Info.Confidence)
	}
	if got := f.Metadata["header"]; got != "X-Test-Role" {
		t.Errorf("metadata header = %v, want X-Test-Role", got)
	}
	if len(f.AdditionalEvidence) == 0 {
		t.Errorf("expected evidence pairs attached")
	}
}

// --- negative: the header is ignored, body never changes ---

func TestScanPerRequest_InertHeader_NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role, X-Tenant-Id")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings on inert header, got %d", len(res))
	}
}

// --- negative: the value is only reflected, body is otherwise identical ---

func TestScanPerRequest_ReflectionOnly_NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the value verbatim but keep the surrounding page identical. The
		// module strips the injected value before comparing, so this must not flag.
		_, _ = fmt.Fprintf(w, "<html><body><h1>Home</h1><p>Welcome guest.</p><!-- ctx:%s --></body></html>",
			r.Header.Get("X-Ctx"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Ctx")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings on reflection-only header, got %d", len(res))
	}
}

// --- negative: a different-but-not-much-larger body fails the size gate ---

func TestScanPerRequest_SameSizeChange_NotFlagged(t *testing.T) {
	const base = "<html><body><p>welcome to the public home page for our guests</p></body></html>"
	const alt = "<html><body><p>members private dashboard with internal content</p></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			_, _ = fmt.Fprint(w, alt) // different tokens, near-identical size
			return
		}
		_, _ = fmt.Fprint(w, base)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a same-size content change must not flag (size gate), got %d", len(res))
	}
}

// --- negative: a 4xx (other than 401) is ignored even with a large body ---

func TestScanPerRequest_ForbiddenLargeBody_NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, adminPage)
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a 403 response must be ignored, got %d", len(res))
	}
}

// --- positive: 401 is the one 4xx carve-out, flagged when much larger ---

func TestScanPerRequest_UnauthorizedLargeBody_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, adminPage)
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("a 401 with a substantially larger body should flag, got %d", len(res))
	}
}

// --- negative: a blank probe body is ignored ---

func TestScanPerRequest_BlankProbeBody_NotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			w.WriteHeader(http.StatusOK) // empty body
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a blank probe body must not flag, got %d", len(res))
	}
}

// --- negative: a non-deterministic endpoint is too noisy to judge ---

func TestScanPerRequest_NoisyEndpoint_NotFlagged(t *testing.T) {
	var seq atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := seq.Add(1)
		_, _ = w.Write([]byte("<html><body>"))
		for i := 0; i < 40; i++ {
			_, _ = fmt.Fprintf(w, "<span>token-%d-%d</span>", n, i)
		}
		_, _ = w.Write([]byte("</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings on noisy endpoint, got %d", len(res))
	}
}

// --- breaker: per-host finding budget stops probing after too many findings ---

func TestScanPerRequest_HostCircuitBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Role") != "" {
			_, _ = fmt.Fprint(w, adminPage)
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	mgr := dedup.NewManager()
	defer mgr.Close()
	scanCtx := &modkit.ScanContext{DedupManager: mgr}
	mod := New()

	total := 0
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f"} {
		rr := withACAH(modtest.Request(t, srv.URL+p), "X-Test-Role")
		res, err := mod.ScanPerRequest(rr, client, scanCtx)
		if err != nil {
			t.Fatalf("ScanPerRequest(%s): %v", p, err)
		}
		total += len(res)
	}
	if total != maxFindingsPerHost {
		t.Fatalf("breaker should cap findings at %d per host, got %d", maxFindingsPerHost, total)
	}
}

// --- gate: no CORS allow/expose headers → module does not process ---

func TestCanProcess_RequiresAdvertisedHeaders(t *testing.T) {
	rr := modtest.Response(modtest.Request(t, "http://example.com/"), "text/html", homePage)
	if New().CanProcess(rr) {
		t.Errorf("CanProcess should be false without Allow/Expose-Headers")
	}
	rr2 := withACAH(modtest.Request(t, "http://example.com/"), "X-Test-Role")
	if !New().CanProcess(rr2) {
		t.Errorf("CanProcess should be true when Access-Control-Allow-Headers is present")
	}
}

func TestSelectCandidates(t *testing.T) {
	acah := "Authorization,Content-Type,Accept,X-Netflix.user.id,X-Netflix.oauth.token," +
		"X-Netflix.Request.Client.Context,Origin,X-Requested-With,B3"
	got := selectCandidates(acah, "")

	want := map[string]bool{
		"X-Netflix.user.id":                true,
		"X-Netflix.oauth.token":            true,
		"X-Netflix.Request.Client.Context": true,
	}
	if len(got) != len(want) {
		t.Fatalf("selectCandidates = %v, want %d custom headers", got, len(want))
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected candidate %q (standard/boring header should be dropped)", name)
		}
	}
}

func TestSelectCandidates_CapAndDedup(t *testing.T) {
	// Build more than the cap of distinct X- headers plus a duplicate.
	var acah string
	for i := 0; i < maxCandidateHeaders+5; i++ {
		acah += fmt.Sprintf("X-Custom-%d,", i)
	}
	acah += "X-Custom-0" // duplicate
	got := selectCandidates(acah, "")
	if len(got) != maxCandidateHeaders {
		t.Fatalf("selectCandidates returned %d, want cap %d", len(got), maxCandidateHeaders)
	}
}
