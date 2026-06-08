package lfi_generic

import (
	"regexp"
	"strings"
)

// injectionMarker is the unique sentinel embedded (base64-encoded) in the
// data:// wrapper payload — it decodes to `<?php echo "vigolium-test"; ?>`.
// A genuine data:// include echoes the marker back as *plaintext*; just as
// importantly, it lets corroboration steps recognise — and discard — our own
// payload when a target merely *reflects* the request body (e.g. Salesforce
// Aura endpoints echo aura.context). Without this guard the reflected base64
// decodes straight back to the PHP snippet above and masquerades as a real
// php://filter source read.
const injectionMarker = "vigolium-test"

type rule struct {
	payloads []string
	regex    []*regexp.Regexp
	words    []string
	// confirm is an optional, payload-specific corroboration step run in
	// addition to words/regex. It receives the fuzzed response body, the
	// original (baseline) body, and the payload that was injected, and returns
	// true only when the body carries strong, module-specific evidence of a
	// successful include (e.g. a base64 blob that decodes to actual PHP source,
	// or two distinct .env assignments). It exists to replace loose signature
	// regexes/words that fire on incidental base64 (data-URI images, fonts) or
	// the payload simply being reflected back in the response.
	confirm func(data, baseline, payload string) bool
}

func newRule(payloads []string, regex []*regexp.Regexp, words []string) *rule {
	return &rule{
		payloads: payloads,
		regex:    regex,
		words:    words,
	}
}

// withConfirm attaches a payload-specific corroboration step to the rule.
func (r *rule) withConfirm(fn func(data, baseline, payload string) bool) *rule {
	r.confirm = fn
	return r
}

// MatchWithBaseline checks if data matches the rule but the match is NOT already
// present in the baseline. payload is the value that was injected into the
// insertion point; confirm steps use it to discard pure payload reflections.
func (r *rule) MatchWithBaseline(data, baseline, payload string) bool {
	if len(r.words) > 0 {
		allWordsFound := true
		allWordsInBaseline := true
		for _, word := range r.words {
			if !strings.Contains(data, word) {
				allWordsFound = false
				break
			}
			if !strings.Contains(baseline, word) {
				allWordsInBaseline = false
			}
		}
		if allWordsFound && !allWordsInBaseline {
			return true
		}
	}
	if len(r.regex) > 0 {
		for _, regex := range r.regex {
			if regex.MatchString(data) {
				if baseline != "" && regex.MatchString(baseline) {
					continue
				}
				return true
			}
		}
	}
	if r.confirm != nil && r.confirm(data, baseline, payload) {
		return true
	}
	return false
}

func (r *rule) Match(data string) bool {
	if len(r.words) > 0 {
		allWordsFound := true
		for _, word := range r.words {
			if !strings.Contains(data, word) {
				allWordsFound = false
				break
			}
		}
		if allWordsFound {
			return true
		}
	}
	if len(r.regex) > 0 {
		for _, regex := range r.regex {
			if regex.MatchString(data) {
				return true
			}
		}
	}
	return false
}

func (r *rule) Payloads() []string {
	return r.payloads
}
