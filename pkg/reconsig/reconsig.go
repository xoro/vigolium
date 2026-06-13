// Package reconsig provides generic recon-extraction primitives shared by the
// passive recon modules (subdomain_harvest, baas_endpoint_fingerprint): pulling
// hostnames out of response bodies and resolving their registrable domain
// (eTLD+1) so discovered subdomains can be scoped to the target organization.
//
// The extraction is deliberately permissive — callers filter the results
// (by registrable domain for subdomains, or an explicit provider catalog for
// backend services), so incidental matches inside minified bundles are
// discarded downstream rather than being suppressed here.
package reconsig

import (
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// hostRe matches FQDN-shaped tokens in text: one or more dot-terminated labels
// followed by an all-letter TLD of 2–24 characters. A scheme/userinfo prefix is
// not captured — only the hostname — so both absolute URLs ("https://a.b.com/x")
// and bare host references ("a.b.com") are picked up. Numeric version strings
// (1.2.3) never match because the final segment must be letters.
var hostRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}`)

// ExtractHosts returns the deduped, normalized FQDNs referenced in body, capped
// at max unique hosts. Each host is lowercased with any port and trailing dot
// stripped. Order follows first appearance in the body.
func ExtractHosts(body string, max int) []string {
	if body == "" || max <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range hostRe.FindAllString(body, -1) {
		h := NormalizeHost(raw)
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
		if len(out) >= max {
			break
		}
	}
	return out
}

// NormalizeHost lowercases a host, strips a :port suffix, a trailing dot, and
// any stray leading/trailing separators. Input may be a bare host or host:port.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.Trim(h, ".")
	return h
}

// stripToHost reduces a possible URL ("https://user@host:443/path?q") down to
// its host[:port] component. A plain host is returned unchanged.
func stripToHost(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// HostOf reduces a possible URL ("https://key@host:443/path") to its
// normalized host component (lowercased, no port). A bare host is returned
// normalized. Returns "" when no host can be derived.
func HostOf(s string) string {
	return NormalizeHost(stripToHost(s))
}

// RegistrableDomain returns the eTLD+1 (registrable domain) for a host, or ""
// when it cannot be resolved. The argument may be a full URL, host:port, or
// bare host — only the hostname is considered. Public-suffix data is the
// ICANN+private list bundled in golang.org/x/net/publicsuffix, so platform
// apexes like "*.vercel.app" resolve to the per-app registrable domain.
func RegistrableDomain(host string) string {
	h := NormalizeHost(stripToHost(host))
	if h == "" || !strings.Contains(h, ".") {
		return ""
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return reg
}

// IsScannableContentType reports whether a response Content-Type is a text
// body worth mining for recon references. Unlike modkit.IsStaticAssetContentType
// (which treats JavaScript as a static asset to suppress), this allowlist
// deliberately INCLUDES JS/TS, because minified bundles are the richest source
// of embedded config (origins, Firebase blocks, BaaS endpoints).
func IsScannableContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "text/html"),
		strings.Contains(ct, "javascript"),
		strings.Contains(ct, "ecmascript"),
		strings.Contains(ct, "json"),
		strings.Contains(ct, "text/plain"),
		strings.Contains(ct, "xml"):
		return true
	default:
		return false
	}
}
