package ws_cswsh

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// The CSWSH module confirms WS support by the upgrade HANDSHAKE — 101 plus
// `Upgrade: websocket` and a `Sec-WebSocket-Accept` header — not a bare 101, so
// the test handler completes a realistic handshake via writeWSHandshake.

// writeWSHandshake emits a complete RFC 6455 upgrade response (the accept value
// is the canonical hash for the module's fixed Sec-WebSocket-Key).
func writeWSHandshake(w http.ResponseWriter) {
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	w.WriteHeader(http.StatusSwitchingProtocols)
}

// TestScanPerRequest_DetectsCSWSH drives the real scan method against a server
// that upgrades any WebSocket handshake regardless of Origin. After confirming
// WS support with the legitimate origin, every malicious origin scenario (evil,
// null, subdomain, missing) should be flagged.
func TestScanPerRequest_DetectsCSWSH(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			writeWSHandshake(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected CSWSH findings when any origin is accepted")
	// All four malicious-origin scenarios should fire against a permissive server.
	assert.Len(t, res, len(originTests))
	for _, r := range res {
		assert.True(t, r.MatcherStatus)
	}
}

// TestScanPerRequest_NoFalsePositive ensures an endpoint that never upgrades
// (no WebSocket support) yields no finding — the module bails after the initial
// matching-origin probe fails.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint with no WS support must not yield a finding")
}

// TestScanPerRequest_NoFalsePositive_Bare101 covers a reverse proxy / catch-all
// that returns 101 for every upgrade request WITHOUT completing the WebSocket
// handshake (no Sec-WebSocket-Accept). The status-only Step-1 support check used
// to treat this as a WebSocket endpoint and then flag every origin; the
// handshake gate must now bail before any finding fires.
func TestScanPerRequest_NoFalsePositive_Bare101(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols) // bare 101, no handshake headers
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a bare 101 without a WebSocket handshake must not be flagged")
}
