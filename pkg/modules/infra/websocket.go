package infra

import (
	"net/http"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"
)

// IsWebSocketHandshake reports whether resp is a genuine WebSocket upgrade
// (RFC 6455) rather than a bare 101 status. A module that confirms WebSocket
// support purely on `StatusCode == 101` can be fooled by a misconfigured
// reverse proxy or catch-all that returns 101 without actually speaking the
// WebSocket protocol — every downstream origin/CSWSH probe then "succeeds"
// against a non-WebSocket endpoint, producing a false positive.
//
// A compliant server completes the handshake with both `Upgrade: websocket`
// and a `Sec-WebSocket-Accept` header (the base64 SHA-1 of the client key plus
// the RFC magic GUID). Requiring all three — 101 + Upgrade + Accept — is the
// minimal proof that the server processed the handshake as WebSocket, and a
// conformant server always emits them, so it introduces no false negative.
func IsWebSocketHandshake(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	r := resp.Response()
	if r.StatusCode != http.StatusSwitchingProtocols { // 101
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	return strings.TrimSpace(r.Header.Get("Sec-WebSocket-Accept")) != ""
}
