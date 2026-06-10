package internal_header_probe

import (
	"sort"
	"strings"
)

// maxCandidateHeaders caps how many advertised headers a single endpoint is
// fuzzed with, after sensitivity ordering. ACAH lists can carry 50+ entries; the
// cap keeps request volume bounded while keeping the most interesting headers.
const maxCandidateHeaders = 15

// standardHeaders are well-known request headers that are uninteresting to fuzz:
// they have defined semantics, are routinely sent by browsers, and are unlikely
// to expose a private backend protocol. They are excluded from candidate
// selection so the module focuses on custom / vendor / internal headers.
var standardHeaders = map[string]bool{
	"accept": true, "accept-charset": true, "accept-datetime": true,
	"accept-encoding": true, "accept-language": true, "accept-ranges": true,
	"access-control-request-headers": true, "access-control-request-method": true,
	"authorization": true, "b3": true, "baggage": true, "cache-control": true,
	"connection": true, "content-encoding": true, "content-language": true,
	"content-length": true, "content-type": true, "cookie": true, "date": true,
	"dnt": true, "expect": true, "from": true, "host": true, "if-match": true,
	"if-modified-since": true, "if-none-match": true, "if-range": true,
	"if-unmodified-since": true, "keep-alive": true, "max-forwards": true,
	"origin": true, "pragma": true, "range": true, "referer": true, "te": true,
	"traceparent": true, "tracestate": true, "upgrade": true,
	"upgrade-insecure-requests": true, "user-agent": true, "via": true,
	"warning": true, "x-requested-with": true,
}

// sensitivityKeywords are name fragments that mark a header as more interesting
// to fuzz (identity, routing, trust, environment). A header containing more of
// them sorts earlier so the most promising candidates survive the cap. Presence
// of any one also lets a non-X-/non-dotted custom header qualify.
var sensitivityKeywords = []string{
	"user", "uuid", "token", "oauth", "auth", "key", "secret", "role", "admin",
	"internal", "priv", "sudo", "super", "owner", "group", "scope", "claim",
	"identity", "principal", "impersonat", "on-behalf", "act-as", "request",
	"context", "rout", "forward", "real-ip", "client", "trace", "session",
	"tenant", "account", "debug", "env", "region", "gateway", "backend",
	"origin", "src", "host", "ip", "id",
}

// selectCandidates parses the advertised header lists and returns the custom
// header names worth fuzzing, deduplicated, sensitivity-ordered, and capped.
// acah (Access-Control-Allow-Headers) is the primary source; aceh
// (Access-Control-Expose-Headers) is folded in as a secondary signal that the
// host speaks a custom header protocol.
func selectCandidates(acah, aceh string) []string {
	seen := make(map[string]bool)
	var cands []string

	for _, name := range append(splitHeaderList(acah), splitHeaderList(aceh)...) {
		low := strings.ToLower(name)
		if low == "" || low == "*" || seen[low] {
			continue
		}
		seen[low] = true
		if standardHeaders[low] {
			continue
		}
		if !isInterestingHeader(low) {
			continue
		}
		cands = append(cands, name)
	}

	// Score each candidate once, then sort on the cached scores — the comparator
	// would otherwise recompute (and re-lowercase) sensitivityScore O(n log n) times.
	scores := make(map[string]int, len(cands))
	for _, c := range cands {
		scores[c] = sensitivityScore(c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return scores[cands[i]] > scores[cands[j]]
	})
	if len(cands) > maxCandidateHeaders {
		cands = cands[:maxCandidateHeaders]
	}
	return cands
}

// splitHeaderList splits a comma-separated header value into trimmed names.
func splitHeaderList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if name := strings.TrimSpace(p); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// isInterestingHeader reports whether a (lowercased) header name looks like a
// custom / vendor / internal header worth fuzzing: an X- prefix, a vendor-dotted
// name (e.g. "x-netflix.user.id"), or a name carrying a sensitivity keyword.
func isInterestingHeader(low string) bool {
	if strings.HasPrefix(low, "x-") || strings.Contains(low, ".") {
		return true
	}
	return sensitivityScore(low) > 0
}

// sensitivityScore counts how many sensitivity keywords appear in the header
// name; used purely to order candidates so the juiciest survive the cap.
func sensitivityScore(name string) int {
	low := strings.ToLower(name)
	score := 0
	for _, kw := range sensitivityKeywords {
		if strings.Contains(low, kw) {
			score++
		}
	}
	return score
}
