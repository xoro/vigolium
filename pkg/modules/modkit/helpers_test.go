package modkit

import "testing"

func TestIsStaticAssetContentType(t *testing.T) {
	t.Parallel()
	static := []string{
		"text/javascript",
		"application/javascript; charset=utf-8",
		"application/x-javascript",
		"text/css",
		"image/png",
		"image/svg+xml",
		"font/woff2",
		"application/font-woff",
		"video/mp4",
		"audio/mpeg",
		"application/wasm",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
	}
	for _, ct := range static {
		if !IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = false, want true", ct)
		}
	}

	notStatic := []string{
		"",
		"application/json",
		"application/json; charset=utf-8",
		"text/html",
		"text/plain",
		"application/xml",
		"text/event-stream",
		"application/vnd.api+json",
	}
	for _, ct := range notStatic {
		if IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = true, want false", ct)
		}
	}
}
