package infra

import "bytes"

// ByteSetMatcher scans a body once for any of a fixed set of byte needles,
// dispatching on the first byte so each position only checks needles that could
// start there. Built once from a static marker set, it replaces N independent
// bytes.Contains full passes (one per needle) with a single pass whose cost is
// independent of the needle count — the shape the edge-block / challenge-page
// marker scans need, since they run on essentially every clean response a
// content/value detector inspects.
type ByteSetMatcher struct {
	byFirst [256][][]byte
	has     bool
}

// NewByteSetMatcher builds a matcher for the given needles. Empty needles are
// ignored. Intended to be called once at package init, not per request.
func NewByteSetMatcher(markers [][]byte) *ByteSetMatcher {
	m := &ByteSetMatcher{}
	for _, mk := range markers {
		if len(mk) == 0 {
			continue
		}
		m.byFirst[mk[0]] = append(m.byFirst[mk[0]], mk)
		m.has = true
	}
	return m
}

// MatchAny reports whether body contains any of the matcher's needles. nil-safe
// and false for an empty needle set.
func (m *ByteSetMatcher) MatchAny(body []byte) bool {
	if m == nil || !m.has {
		return false
	}
	for i := 0; i < len(body); i++ {
		for _, mk := range m.byFirst[body[i]] {
			if i+len(mk) <= len(body) && bytes.Equal(body[i:i+len(mk)], mk) {
				return true
			}
		}
	}
	return false
}
