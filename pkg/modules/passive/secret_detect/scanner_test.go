package secret_detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeResponse, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func makeHTTPCtx(contentType string, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestCanProcess_NilResponse(t *testing.T) {
	m := New()

	assert.False(t, m.CanProcess(nil))

	req := httpmsg.NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	assert.False(t, m.CanProcess(ctx))
}

func TestCanProcess_EmptyBody(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("text/html", "")
	assert.False(t, m.CanProcess(ctx))
}

func TestCanProcess_MediaContentType(t *testing.T) {
	m := New()

	for _, ct := range []string{"image/png", "video/mp4", "audio/mpeg", "font/woff2"} {
		ctx := makeHTTPCtx(ct, "some body content")
		assert.False(t, m.CanProcess(ctx), "should reject media type %s", ct)
	}
}

func TestCanProcess_TextContent(t *testing.T) {
	m := New()

	for _, ct := range []string{"text/html", "application/json", "application/javascript", "text/xml"} {
		ctx := makeHTTPCtx(ct, "some body content")
		assert.True(t, m.CanProcess(ctx), "should accept text type %s", ct)
	}
}

func TestCanProcess_OversizedBody(t *testing.T) {
	m := New()
	bigBody := strings.Repeat("a", maxBodySize+1)
	ctx := makeHTTPCtx("text/html", bigBody)
	assert.False(t, m.CanProcess(ctx))
}

func TestIsTextBasedMIME(t *testing.T) {
	textTypes := []string{
		"text/html",
		"text/plain",
		"application/json",
		"application/javascript",
		"application/xml",
		"application/x-yaml",
		"application/vnd.api+json",
		"application/atom+xml",
		"",
	}
	for _, mt := range textTypes {
		assert.True(t, isTextBasedMIME(mt), "expected true for %q", mt)
	}

	binaryTypes := []string{
		"image/png",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"video/mp4",
	}
	for _, mt := range binaryTypes {
		assert.False(t, isTextBasedMIME(mt), "expected false for %q", mt)
	}
}
