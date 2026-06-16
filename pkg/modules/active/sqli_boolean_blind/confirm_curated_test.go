package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_NoFalsePositive_LiteralTautologySignature is the core
// regression for the Accept-Language `'/**/OR/**/1=1--` false-positive class. The
// sink is NOT a boolean oracle: it returns a short page for any value containing
// the literal `1=1` (mimicking a WAF/CDN that signatures the tautology) and the
// long page otherwise. The literal `1=1`/`1=2` differential therefore detects, but
// re-deriving the comparison with random operands (5731=5731 / 5731=6824) makes
// both branches render the long page, so confirmRandomized must reject it.
func TestScanPerRequest_NoFalsePositive_LiteralTautologySignature(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Contains(v, "1=1") {
			_, _ = fmt.Fprint(w, falsePage) // "blocked"-like short page, no SQL logic
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a differential bound to the literal 1=1 token (WAF signature) must not be reported")
}

// TestScanPerRequest_NoFalsePositive_ChallengeOnTautology proves the block gate
// catches a WAF challenge served with a 200 status (so the status gate alone would
// pass it): the TRUE branch (`1=1`) returns a Cloudflare challenge body, which
// infra.IsBlockedResponse recognizes by marker, so the differential is dropped.
func TestScanPerRequest_NoFalsePositive_ChallengeOnTautology(t *testing.T) {
	t.Parallel()
	challenge := "<html><head><script>window._cf_chl_opt={};</script></head><body>" +
		strings.Repeat("checking your browser ", 8) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Contains(v, "1=1") {
			w.WriteHeader(http.StatusOK) // 200 challenge — status gate would pass it
			_, _ = fmt.Fprint(w, challenge)
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a 200-status WAF challenge on the TRUE branch must be block-gated, not reported")
}

// fakeIP is a minimal InsertionPoint for unit-testing the header exclusion.
type fakeIP struct {
	name string
	typ  httpmsg.InsertionPointType
}

func (f fakeIP) Name() string                     { return f.name }
func (f fakeIP) BaseValue() string                { return "" }
func (f fakeIP) Type() httpmsg.InsertionPointType { return f.typ }
func (f fakeIP) BuildRequest(p []byte) []byte     { return p }
func (f fakeIP) PayloadOffsets(p []byte) []int    { return []int{-1, -1} }

func TestIsExcludedHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		typ  httpmsg.InsertionPointType
		want bool
	}{
		{"Accept-Language", httpmsg.INS_HEADER, true},
		{"accept-encoding", httpmsg.INS_HEADER, true},
		{"Accept-Charset", httpmsg.INS_HEADER, true},
		{"Accept", httpmsg.INS_HEADER, true},
		{"User-Agent", httpmsg.INS_HEADER, false},         // legit logging/SQL vector — kept
		{"Referer", httpmsg.INS_HEADER, false},            // kept
		{"X-Forwarded-For", httpmsg.INS_HEADER, false},    // kept
		{"Accept-Language", httpmsg.INS_PARAM_URL, false}, // a param that happens to be so named is not a header
	}
	for _, c := range cases {
		if got := isExcludedHeader(fakeIP{c.name, c.typ}); got != c.want {
			t.Errorf("isExcludedHeader(%q, type=%v) = %v, want %v", c.name, c.typ, got, c.want)
		}
	}
}
