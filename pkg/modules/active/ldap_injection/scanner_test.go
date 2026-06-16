package ldap_injection

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// divergentLDAPServer returns a big body only for the bare wildcard ("*") value and
// a small body for everything else (the no-match control + error-based payloads),
// with no LDAP error tokens. That makes the boolean-based wildcard-vs-control /
// wildcard-vs-baseline deltas large enough to fire — so the only thing that can
// suppress a finding on a large-HTML baseline is the surface gate.
func divergentLDAPServer(t *testing.T) *httptest.Server {
	t.Helper()
	big := strings.Repeat("a", 5000)
	small := strings.Repeat("b", 400)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Query().Get("username") == "*" {
			_, _ = io.WriteString(w, big)
			return
		}
		_, _ = io.WriteString(w, small)
	}))
}

// TestScanPerInsertionPoint_BooleanGatedOnLargeHTML proves the boolean-based pass is
// suppressed on a large rendered HTML baseline (unreliable differential surface),
// while the SAME endpoint with a small baseline still reports the boolean finding —
// so the surface gate, not an unrelated precondition, is what suppresses it.
func TestScanPerInsertionPoint_BooleanGatedOnLargeHTML(t *testing.T) {
	srv := divergentLDAPServer(t)
	defer srv.Close()
	client := modtest.Requester(t)

	bigHTML := "<html><body>" + strings.Repeat("<div>x</div>", 20000) + "</body></html>" // >100 KB

	// Small baseline → boolean pass runs and fires on the wildcard/control divergence.
	rrSmall := modtest.RequestMethod(t, "GET", srv.URL+"/login?username=bob", "")
	rrSmall = modtest.Response(rrSmall, "text/html", strings.Repeat("b", 400))
	ipSmall := modtest.InsertionPoint(t, rrSmall, "username")
	res, err := New().ScanPerInsertionPoint(rrSmall, ipSmall, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan (small): %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected a boolean-based LDAP finding on a small baseline (sanity check for the gate test)")
	}

	// Large HTML baseline → surface gate suppresses the boolean pass entirely.
	rrBig := modtest.RequestMethod(t, "GET", srv.URL+"/login?username=bob", "")
	rrBig = modtest.Response(rrBig, "text/html", bigHTML)
	ipBig := modtest.InsertionPoint(t, rrBig, "username")
	res, err = New().ScanPerInsertionPoint(rrBig, ipBig, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan (large): %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("boolean-based LDAP detection must be skipped on a large HTML surface, got %d findings", len(res))
	}
}
