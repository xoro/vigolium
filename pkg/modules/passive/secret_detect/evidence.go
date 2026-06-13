package secret_detect

import (
	"bytes"
	"fmt"
	"strings"
)

// Evidence-rendering tunables. A small response body is shown in full; a large
// one (typically a minified JS bundle) is reduced to a window around the matched
// secret so the finding carries useful context without storing a multi-megabyte
// asset.
const (
	// evidenceFullThreshold is the body size (bytes) at or below which the whole
	// body is shown verbatim. Above it, only a window around the match is kept.
	evidenceFullThreshold = 8 * 1024

	// evidenceContextLines is how many lines of context to show on each side of
	// the matched line in a windowed body.
	evidenceContextLines = 5

	// evidenceContextChars caps the window to this many bytes on each side of the
	// match. This bounds the minified single-line case, where evidenceContextLines
	// would otherwise span the entire bundle.
	evidenceContextChars = 512
)

// BuildEvidenceResponse renders the raw HTTP response head (status line plus
// headers, no body) followed by a body view. Small bodies are shown in full;
// large bodies are reduced to a window around the matched secret (see
// snippetWindow). matchLine is Kingfisher's 1-indexed line number, used as a
// fallback anchor when the snippet can't be located verbatim in the body.
func BuildEvidenceResponse(head string, body []byte, snippet string, matchLine int) string {
	if len(body) <= evidenceFullThreshold {
		return head + string(body)
	}
	return head + snippetWindow(body, snippet, matchLine, evidenceContextLines, evidenceContextChars)
}

// snippetWindow returns a slice of body centered on the matched secret: up to
// ctxLines lines on each side, additionally clamped to ctxChars bytes on each
// side so a single very long line (minified bundle) doesn't defeat the line
// window. Truncated edges are marked with a "... [N bytes truncated] ..." note.
func snippetWindow(body []byte, snippet string, matchLine, ctxLines, ctxChars int) string {
	matchStart, matchEnd := locateMatch(body, snippet, matchLine)

	// Line window: ctxLines full lines on each side of the match line.
	lineStart := lineWindowStart(body, matchStart, ctxLines)
	lineEnd := lineWindowEnd(body, matchEnd, ctxLines)

	// Char window: a hard byte cap on each side of the match.
	charStart := matchStart - ctxChars
	if charStart < 0 {
		charStart = 0
	}
	charEnd := matchEnd + ctxChars
	if charEnd > len(body) {
		charEnd = len(body)
	}

	// Take the tighter of the two windows on each side: show ctxLines of context,
	// but never more than ctxChars worth.
	start := max(lineStart, charStart)
	end := min(lineEnd, charEnd)

	var b strings.Builder
	if start > 0 {
		fmt.Fprintf(&b, "... [%d bytes truncated] ...\n", start)
	}
	b.Write(body[start:end])
	if end < len(body) {
		fmt.Fprintf(&b, "\n... [%d bytes truncated] ...", len(body)-end)
	}
	return b.String()
}

// locateMatch returns the [start, end) byte range of the matched secret within
// body. It searches for the snippet verbatim first; failing that (Kingfisher may
// normalize the snippet), it falls back to the start of the reported 1-indexed
// line, and finally to the start of the body.
func locateMatch(body []byte, snippet string, matchLine int) (start, end int) {
	if s := strings.TrimSpace(snippet); s != "" {
		if idx := bytes.Index(body, []byte(s)); idx >= 0 {
			return idx, idx + len(s)
		}
	}
	if matchLine > 1 {
		off := 0
		for n := 1; n < matchLine && off < len(body); n++ {
			nl := bytes.IndexByte(body[off:], '\n')
			if nl < 0 {
				break
			}
			off += nl + 1
		}
		return off, off
	}
	return 0, 0
}

// lineWindowStart returns the byte offset of the start of the line that is ctx
// lines before the line containing pos.
func lineWindowStart(body []byte, pos, ctx int) int {
	if pos > len(body) {
		pos = len(body)
	}
	home := bytes.LastIndexByte(body[:pos], '\n') + 1 // start of pos's line (0 if none)
	for i := 0; i < ctx && home > 0; i++ {
		home = bytes.LastIndexByte(body[:home-1], '\n') + 1
	}
	return home
}

// lineWindowEnd returns the byte offset of the end of the line that is ctx lines
// after the line containing pos (the offset of the terminating newline, or
// len(body) if the window runs to the end).
func lineWindowEnd(body []byte, pos, ctx int) int {
	if pos >= len(body) {
		return len(body)
	}
	nl := bytes.IndexByte(body[pos:], '\n')
	if nl < 0 {
		return len(body)
	}
	end := pos + nl // newline ending pos's line
	for i := 0; i < ctx; i++ {
		next := bytes.IndexByte(body[end+1:], '\n')
		if next < 0 {
			return len(body)
		}
		end += 1 + next
	}
	return end
}
