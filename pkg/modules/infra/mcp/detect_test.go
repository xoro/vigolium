package mcp

import "testing"

func TestDetectFromParts(t *testing.T) {
	cases := []struct {
		name      string
		reqHdr    map[string]string
		urlPath   string
		respHdr   map[string]string
		body      string
		wantStrng bool
		wantAny   bool
	}{
		{
			name:      "session header",
			respHdr:   map[string]string{"Mcp-Session-Id": "abc"},
			body:      "{}",
			wantStrng: true,
			wantAny:   true,
		},
		{
			name:      "json-rpc with method",
			body:      `{"jsonrpc":"2.0","id":1,"result":{"tools":[]},"method":"tools/list"}`,
			urlPath:   "/mcp",
			wantStrng: true,
			wantAny:   true,
		},
		{
			name:    "raw json-rpc only",
			body:    `{"jsonrpc":"2.0","id":1,"result":{}}`,
			wantAny: true,
		},
		{
			name:    "noise",
			body:    `<html>nothing here</html>`,
			wantAny: false,
		},
		{
			// Regression: a minified SSO/login JS bundle containing a bare
			// "ping" token must NOT be flagged as MCP (was firing Medium).
			name:    "static js asset with ping word",
			respHdr: map[string]string{"Content-Type": "text/javascript"},
			body:    `function NN(e,t){return e.ping("2.0")}var x="ping";`,
			wantAny: false,
		},
		{
			// Even a JS bundle that embeds a literal jsonrpc envelope string is
			// a static asset, not an MCP server — content-type gate wins.
			name:    "js asset embedding jsonrpc literal",
			respHdr: map[string]string{"Content-Type": "application/javascript; charset=utf-8"},
			body:    `const tpl='{"jsonrpc":"2.0","method":"initialize"}';export{tpl};`,
			wantAny: false,
		},
		{
			// A plain JSON body with a bare "ping" but no JSON-RPC envelope is
			// too weak to count as a method match.
			name:    "json with bare ping no envelope",
			respHdr: map[string]string{"Content-Type": "application/json"},
			body:    `{"status":"ok","ping":true}`,
			wantAny: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := DetectFromParts(c.reqHdr, c.urlPath, c.respHdr, c.body)
			if f.Any() != c.wantAny {
				t.Fatalf("Any() got %v want %v: flags=%#v", f.Any(), c.wantAny, f)
			}
			if f.Strong() != c.wantStrng {
				t.Fatalf("Strong() got %v want %v: flags=%#v", f.Strong(), c.wantStrng, f)
			}
		})
	}
}
