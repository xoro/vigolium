package modkit

import (
	"strconv"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func diffSurfaceResp(contentType, body string, extraHeaders ...string) *httpmsg.HttpResponse {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Type: " + contentType + "\r\n")
	for _, h := range extraHeaders {
		sb.WriteString(h + "\r\n")
	}
	sb.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")
	sb.WriteString(body)
	return httpmsg.NewHttpResponse([]byte(sb.String()))
}

func TestDifferentialSurfaceUnreliable(t *testing.T) {
	bigHTML := strings.Repeat("x", LargeDynamicHTMLBytes+1)
	smallHTML := "<html>ok</html>"

	if !DifferentialSurfaceUnreliable(diffSurfaceResp("text/html", bigHTML)) {
		t.Error("large text/html should be an unreliable differential surface")
	}
	if DifferentialSurfaceUnreliable(diffSurfaceResp("text/html; charset=utf-8", smallHTML)) {
		t.Error("small text/html should be a reliable surface")
	}
	// The size gate is text/html-scoped: a large JSON API response (the real
	// injection-oracle surface) must NOT be gated.
	if DifferentialSurfaceUnreliable(diffSurfaceResp("application/json", bigHTML)) {
		t.Error("large JSON must not be gated — the size gate is text/html-scoped")
	}
	// A cache/CDN layer makes even a small body unreliable.
	if !DifferentialSurfaceUnreliable(diffSurfaceResp("text/html", smallHTML, "X-Cache: HIT")) {
		t.Error("a cache-hit response should be flagged unreliable")
	}
	if !DifferentialSurfaceUnreliable(diffSurfaceResp("application/json", "{}", "Age: 42")) {
		t.Error("a non-zero Age (cache layer) should be flagged unreliable regardless of content-type")
	}
	if DifferentialSurfaceUnreliable(nil) {
		t.Error("nil response must not be flagged (fail open)")
	}
}
