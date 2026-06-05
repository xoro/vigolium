package mcp

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// DetectionFlags captures which MCP-shaped indicators were found in an HTTP
// transaction. A non-empty flags set is enough to flag the endpoint as MCP.
type DetectionFlags struct {
	HasSessionHeader bool
	HasJSONRPC       bool
	HasSSEStream     bool
	MatchedMethods   []string
	HasServerInfo    bool
	HasMCPPath       bool
	SessionID        string
}

// Any reports whether the flags carry at least one strong indicator.
func (f DetectionFlags) Any() bool {
	return f.HasSessionHeader || f.HasJSONRPC || f.HasSSEStream || len(f.MatchedMethods) > 0 ||
		f.HasServerInfo || f.HasMCPPath
}

// Strong reports whether at least one high-confidence indicator was found.
// "Strong" means we're confident this is an MCP endpoint, not just some
// endpoint (or static asset) that happens to echo a method name or "jsonrpc".
func (f DetectionFlags) Strong() bool {
	if f.HasSessionHeader {
		return true
	}
	// A matched method name is only convincing when it rides alongside another
	// MCP-shaped signal (the JSON-RPC envelope, an MCP path, an SSE stream, or
	// serverInfo). A lone method substring in an arbitrary body — e.g. "ping"
	// inside a minified JS bundle — is not enough on its own.
	if len(f.MatchedMethods) > 0 && (f.HasJSONRPC || f.HasMCPPath || f.HasSSEStream || f.HasServerInfo) {
		return true
	}
	return f.HasJSONRPC && (f.HasMCPPath || f.HasSSEStream || f.HasServerInfo)
}

// Detect inspects a request/response pair for MCP indicators. The request and
// response may be nil; missing pieces simply produce fewer flags.
func Detect(ctx *httpmsg.HttpRequestResponse) DetectionFlags {
	flags := DetectionFlags{}
	if ctx == nil {
		return flags
	}

	// Path heuristic
	if urlx, err := ctx.URL(); err == nil {
		p := strings.ToLower(urlx.Path)
		for _, mp := range CommonPaths {
			if p == mp || strings.HasPrefix(p, mp+"/") {
				flags.HasMCPPath = true
				break
			}
		}
	}

	// Headers
	if req := ctx.Request(); req != nil {
		if v := req.Header("Mcp-Session-Id"); v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
	}

	resp := ctx.Response()
	if resp == nil {
		return flags
	}

	var contentType string
	for _, h := range resp.Headers() {
		name := strings.ToLower(h.Name)
		if name == "mcp-session-id" && h.Value != "" {
			flags.HasSessionHeader = true
			flags.SessionID = h.Value
		}
		if name == "content-type" {
			contentType = h.Value
			if strings.Contains(strings.ToLower(h.Value), "text/event-stream") {
				flags.HasSSEStream = true
			}
		}
	}

	// Static assets (JS/CSS/HTML/images/fonts/...) routinely embed words like
	// "ping" or the literal "jsonrpc"; an MCP (JSON-RPC) server never serves
	// them, so don't body-match those content types — that was the source of
	// false positives such as a minified SSO login bundle flagged via "ping".
	if nonAPIContentType(contentType) {
		return flags
	}

	body := resp.BodyToString()
	if body == "" {
		return flags
	}

	flags = inspectBody(body, flags)
	return flags
}

// DetectFromParts is the same as Detect but works directly on raw pieces, used
// by the jsext API where the caller may not have a full HttpRequestResponse.
func DetectFromParts(reqHeaders map[string]string, urlPath string, respHeaders map[string]string, respBody string) DetectionFlags {
	flags := DetectionFlags{}
	pl := strings.ToLower(urlPath)
	for _, mp := range CommonPaths {
		if pl == mp || strings.HasPrefix(pl, mp+"/") {
			flags.HasMCPPath = true
			break
		}
	}
	for k, v := range reqHeaders {
		if strings.EqualFold(k, "mcp-session-id") && v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
	}
	var contentType string
	for k, v := range respHeaders {
		lk := strings.ToLower(k)
		if lk == "mcp-session-id" && v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
		if lk == "content-type" {
			contentType = v
			if strings.Contains(strings.ToLower(v), "text/event-stream") {
				flags.HasSSEStream = true
			}
		}
	}
	if nonAPIContentType(contentType) {
		return flags
	}
	flags = inspectBody(respBody, flags)
	return flags
}

// ambiguousMethods are MCP method names that are also common English words or
// generic identifiers. They appear all over non-MCP content (a bare "ping" or
// "initialize" token shows up in almost any minified JS bundle), so they only
// count as an MCP signal when accompanied by a JSON-RPC envelope. Namespaced
// methods ("tools/list", "resources/read", ...) are specific enough to stand
// on their own.
var ambiguousMethods = map[string]bool{
	"ping":       true,
	"initialize": true,
}

func inspectBody(body string, flags DetectionFlags) DetectionFlags {
	if body == "" {
		return flags
	}
	hasEnvelope := strings.Contains(body, `"jsonrpc"`) && strings.Contains(body, `"2.0"`)
	if hasEnvelope {
		flags.HasJSONRPC = true
	}
	for _, m := range KnownMethods {
		needle := `"` + m + `"`
		if !strings.Contains(body, needle) {
			continue
		}
		if ambiguousMethods[m] && !hasEnvelope {
			continue
		}
		flags.MatchedMethods = append(flags.MatchedMethods, m)
	}
	if strings.Contains(body, `"serverInfo"`) {
		flags.HasServerInfo = true
	}
	return flags
}

// nonAPIContentTypes are response content types served by static assets and
// binary payloads — never by an MCP (JSON-RPC over HTTP/SSE) server. Bodies
// with these types are skipped before any JSON-RPC / method-name matching.
var nonAPIContentTypes = []string{
	"javascript", // text/javascript, application/javascript, application/x-javascript
	"ecmascript",
	"css",  // text/css
	"html", // text/html, application/xhtml+xml — MCP answers with JSON, not HTML
	"xml",  // text/xml, application/xml — MCP is JSON-RPC, not XML-RPC/SOAP
	"image/",
	"audio/",
	"video/",
	"font/",
	"application/font",
	"application/wasm",
	"application/octet-stream",
	"application/pdf",
	"application/zip",
	"text/csv",
}

// nonAPIContentType reports whether the given Content-Type header value belongs
// to a static asset / binary payload that an MCP server would never serve. An
// empty/unknown content type returns false so the body heuristics still run.
func nonAPIContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 { // drop "; charset=utf-8" etc.
		ct = strings.TrimSpace(ct[:i])
	}
	for _, bad := range nonAPIContentTypes {
		if strings.Contains(ct, bad) {
			return true
		}
	}
	return false
}
