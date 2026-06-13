package authzutil

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// credentialHeaders are headers (besides Authorization/Cookie) that carry a
// user-identifying credential or API token. Their presence marks the request as
// belonging to a specific principal.
var credentialHeaders = []string{
	"X-Api-Key", "X-Api-Token", "Api-Key",
	"X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

// credentialQueryKeys are query-string keys that carry a credential for APIs
// that authenticate via the URL instead of a header.
var credentialQueryKeys = []string{
	"access_token", "auth_token", "api_key", "apikey",
	"session_id", "sessionid", "jwt",
}

// RequestCarriesCredential reports whether an HTTP request presents a
// user-identifying credential — an Authorization header, a Cookie, a well-known
// API-token header, or a credential query parameter.
//
// IDOR / BOLA is by definition an *authorization* flaw: one principal reaching
// another principal's object. When the original request carries no credential
// there is no per-user authorization boundary to cross, so a neighbor id that
// returns "different but valid" content is most often just public, navigable
// content — a blog, a docs site, a product catalog — where distinct ids are
// *expected* to serve distinct pages (e.g. GET /blog/3/ vs /blog/4/). Modules
// use this to gate severity: without a credential the differential is a weak
// lead, not a High/Firm authorization bypass.
func RequestCarriesCredential(req *httpmsg.HttpRequest) bool {
	if req == nil {
		return false
	}
	if strings.TrimSpace(req.Header("Authorization")) != "" {
		return true
	}
	if strings.TrimSpace(req.Header("Cookie")) != "" {
		return true
	}
	for _, h := range credentialHeaders {
		if strings.TrimSpace(req.Header(h)) != "" {
			return true
		}
	}
	return queryCarriesCredential(req.Path())
}

// queryCarriesCredential reports whether a request target's query string carries
// a well-known credential parameter.
func queryCarriesCredential(target string) bool {
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return false
	}
	q := strings.ToLower(target[i+1:])
	for _, k := range credentialQueryKeys {
		if strings.Contains(q, k+"=") {
			return true
		}
	}
	return false
}

// BaselineLinksNeighbor reports whether the baseline response body already links
// to the neighbor request target — the page itself offers the neighbor as
// navigation (a "Next"/"Prev" pagination link, a sibling href, a catalog
// entry). A document never links to another user's *private* object as
// navigation, so a neighbor reachable straight from the page is intended public
// browsing, not a broken-authorization bypass.
//
// This is the dominant IDOR false positive on blogs, documentation and product
// catalogs — e.g. GET /blog/3/ whose body contains href="/blog/4/" and
// href="/blog/2/", so probing the 2/4 neighbors merely re-fetches pages the
// site links to anyway.
//
// neighborTarget is the neighbor request's path including any query string. It
// is only treated as a link signal when specific enough that an incidental
// short numeric substring cannot match: it must carry a query or a non-numeric
// path segment, so a bare "/4" does not match arbitrary digits in the body.
func BaselineLinksNeighbor(baselineBody, neighborTarget string) bool {
	target := strings.TrimSpace(neighborTarget)
	if len(baselineBody) == 0 || len(target) < 3 {
		return false
	}
	if !neighborTargetIsSpecific(target) {
		return false
	}
	return strings.Contains(baselineBody, target)
}

// neighborTargetIsSpecific reports whether a neighbor path/target is distinctive
// enough that finding it verbatim in a body is a deliberate link rather than an
// incidental substring. A target qualifies when it carries a query string or has
// a path segment containing a non-digit character (e.g. "/blog/4/" → the "blog"
// segment), which rules out bare numeric paths like "/4".
func neighborTargetIsSpecific(target string) bool {
	if strings.ContainsRune(target, '?') {
		return true
	}
	for _, seg := range strings.Split(target, "/") {
		if seg == "" {
			continue
		}
		for _, r := range seg {
			if r < '0' || r > '9' {
				return true
			}
		}
	}
	return false
}
