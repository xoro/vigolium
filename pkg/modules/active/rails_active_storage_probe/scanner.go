package rails_active_storage_probe

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// railsBodyMarkers are genuine Rails framework references. They corroborate an
// OPTIONS finding (they never gate it) and confirm the GET blob-route finding.
// Matched against the echo-stripped body so a reflected request path can't forge
// them — the probe paths themselves contain "active_storage"/"action_mailbox".
var railsBodyMarkers = []string{
	"ActiveStorage",
	"Active Storage",
	"ActionMailbox",
	"Action Mailbox",
	"ActionDispatch",
	"ActionController",
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Rails Active Storage Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Rails Active Storage Probe module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("rails_active_storage_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed Active Storage and Action Mailbox endpoints.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Detect blanket OPTIONS handlers before probing. If a guaranteed-nonexistent
	// path answers OPTIONS with 200/204 + Allow:POST (or a generic CORS preflight),
	// the host responds to OPTIONS uniformly on every path and OPTIONS-based
	// evidence is meaningless here.
	if m.detectBlanketOptions(ctx, httpClient) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// detectBlanketOptions sends OPTIONS to a random non-Rails path. A host whose
// reverse proxy / API gateway / CORS middleware answers OPTIONS uniformly (Allow
// with POST, or an Access-Control-Allow-* preflight) would yield a finding on
// every probe path, so OPTIONS evidence is discarded for the whole host.
func (m *Module) detectBlanketOptions(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) bool {
	randomPath := "/vigolium-not-rails-" + utils.RandomString(12)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "OPTIONS")
	if err != nil {
		return false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return false
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return false
	}
	defer resp.Close()

	if resp.Response() == nil {
		return false
	}

	if resp.Response().StatusCode == 200 || resp.Response().StatusCode == 204 {
		allow := resp.Response().Header.Get("Allow")
		if allow != "" && strings.Contains(strings.ToUpper(allow), "POST") {
			return true
		}
		if isCORSPreflightResponse(resp) {
			return true
		}
	}

	return false
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-rails-storage-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), p.method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	// Reject responses that never reached — or were rejected by — the Rails route:
	//   404            route absent
	//   405            method not allowed; OPTIONS isn't handled here. This is the
	//                  production false-positive status: an nginx "405 Not Allowed"
	//                  page literally contains "Allow" inside "Not Allowed".
	//   401/403        generic auth / WAF gates
	//   5xx            upstream / CDN errors (incl. Cloudflare 520-526)
	//   blocked        rate-limit / vendor challenge pages (429/408/425/451, …)
	// None of these confirm the endpoint exists.
	if status == 404 || status == 405 || status == 401 || status == 403 ||
		status >= 500 || isBlockedOrThrottled(resp) {
		return nil
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	// Strip any echo of the request target before scanning the body for markers.
	// Error / 404 / throttle pages routinely reflect the requested URL, and every
	// probe path contains "active_storage"/"action_mailbox" — a reflected target
	// must not be mistaken for genuine framework content.
	scanBody := stripEcho(body, p.path, targetURL)

	for _, anti := range p.antiMarkers {
		if strings.Contains(scanBody, anti) {
			return nil
		}
	}

	var evidence []string

	switch p.method {
	case "OPTIONS":
		// Direct-upload and mail-ingress endpoints are POST-only API routes with
		// no rendered body. A generic CORS preflight (Access-Control-Allow-* with
		// no Allow header) is the API-gateway / proxy reply to OPTIONS on *any*
		// path — it proves a CORS responder exists, not that the Rails route is
		// mounted.
		if isCORSPreflightResponse(resp) {
			return nil
		}
		// Only a 2xx OPTIONS advertising POST via the standard Allow *header*
		// confirms a live Rails route. We never match "POST"/"Allow" as body
		// substrings: that is the exact bug that flagged nginx "405 Not Allowed"
		// pages (which contain "Allow" inside "Not Allowed").
		if status != 200 && status != 204 {
			return nil
		}
		allowHeader := resp.Response().Header.Get("Allow")
		if allowHeader == "" || !strings.Contains(strings.ToUpper(allowHeader), "POST") {
			return nil
		}
		evidence = append(evidence, "Allow: "+allowHeader)
		// Surface any genuine Rails reference in the body as corroboration
		// (does not gate the finding).
		for _, marker := range railsBodyMarkers {
			if strings.Contains(scanBody, marker) {
				evidence = append(evidence, "Body: "+marker)
				break
			}
		}
	case "GET":
		// Blob routes: confirm on a real redirect to a stored object (the genuine
		// Active Storage behavior) or on actual framework body content — never on a
		// bare 200, which SPA/landing pages return for every path.
		if status == 301 || status == 302 {
			loc := resp.Response().Header.Get("Location")
			if loc != "" && !strings.Contains(loc, p.path) {
				evidence = append(evidence, "Redirect: "+loc)
			}
		}
		for _, marker := range p.markers {
			if strings.Contains(scanBody, marker) {
				evidence = append(evidence, "Body: "+marker)
			}
		}
		if len(evidence) == 0 {
			return nil
		}
	default:
		return nil
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails Endpoint Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"rails", "ruby", "active-storage", "action-mailbox"},
			Reference:   []string{"https://guides.rubyonrails.org/active_storage_overview.html", "https://guides.rubyonrails.org/action_mailbox_basics.html"},
		},
	}
}

// isBlockedOrThrottled reports whether a probe response came from a rate
// limiter, WAF/CDN edge, or server error rather than the Rails application.
// Such responses never exercised the route, so their bodies (often error pages
// that reflect the requested path) cannot confirm exposure.
func isBlockedOrThrottled(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	// Vendor-aware detector (Cloudflare, Akamai, CloudFront, Incapsula, AWS ELB)
	// plus the generic rate-limit cases.
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 408, // request timeout
		425, // too early
		429, // too many requests
		451: // unavailable for legal reasons (edge block)
		return true
	}
	return false
}

// isCORSPreflightResponse reports whether resp is a generic CORS preflight reply
// rather than a real Rails route. API gateways and reverse proxies (AWS API
// Gateway, Cloudflare, nginx) answer OPTIONS for every path with an empty 204/200
// carrying Access-Control-Allow-* headers and no standard Allow header. A real
// Rails route answering OPTIONS sets the Allow header, so its presence rules out
// a preflight.
func isCORSPreflightResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	h := resp.Response().Header
	if h.Get("Access-Control-Allow-Origin") == "" && h.Get("Access-Control-Allow-Methods") == "" {
		return false
	}
	return h.Get("Allow") == ""
}

// stripEcho removes occurrences of the requested path and full URL from the body.
// Reflected request targets are common on WAF, rate-limit, and 404 pages; because
// every probe path contains "active_storage"/"action_mailbox", an echoed target
// would masquerade as genuine framework content.
func stripEcho(body, path, fullURL string) string {
	out := body
	for _, echo := range []string{fullURL, path} {
		if echo != "" {
			out = strings.ReplaceAll(out, echo, "")
		}
	}
	return out
}
