package spring_gateway_exposure

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path        string
	name        string
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	bypass      bool // if true, also probe reverse-proxy path-normalization bypasses
}

var probes = []probe{
	{
		path:        "/actuator/gateway/routes",
		name:        "Gateway Routes",
		markers:     [][]string{{`"route_id"`, `"route_definition"`}, {`"uri"`, `"predicate"`, `"filters"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Spring Cloud Gateway routes exposed, revealing internal service URLs, routing predicates, and backend topology",
		bypass:      true,
	},
	{
		path:        "/actuator/gateway/globalfilters",
		name:        "Gateway Global Filters",
		markers:     [][]string{{"cloud.gateway", "GatewayFilter", "WebFilter"}, {`"order"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Cloud Gateway global filters exposed, revealing security filter chain and processing pipeline",
		bypass:      true,
	},
	{
		path:        "/actuator/gateway/routefilters",
		name:        "Gateway Route Filters",
		markers:     [][]string{{"AddRequestHeader", "RewritePath", "StripPrefix", "GatewayFilterFactory", "cloud.gateway"}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Cloud Gateway route filter definitions exposed, revealing available filter configurations",
		bypass:      true,
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Spring Cloud Gateway Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Spring Cloud Gateway Exposure module.
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
		ds: dedup.LazyDiskSet("spring_gateway_exposure"),
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

// ScanPerRequest probes the host for exposed Spring Cloud Gateway actuator endpoints.
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so an
	// endpoint mounted under server.servlet.context-path (e.g. /api/<endpoint>)
	// is reached, not just the root path. Claim each (host, base) pair up front
	// so a fully-deduped request issues no traffic — including the soft-404
	// fingerprint below.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	// Walk the bases and, once per host, fall back to the reverse-proxy path-
	// normalization bypass for any bypass-eligible endpoint the direct root probe
	// found blocked. The shared driver owns the status/hit bookkeeping and the
	// once-per-host + blocked-status gating.
	results := modkit.DriveProbesWithBypass(bases, probes, urlx.Path,
		func(p probe) string { return p.name },
		func(p probe) string { return p.path },
		func(p probe) bool { return p.bypass },
		func(p probe, probePath string) (*output.ResultEvent, int) {
			return m.probeEndpoint(ctx, httpClient, p, probePath, fp)
		})

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-gateway-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetPath produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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
	probePath string,
	fp *notFoundFingerprint,
) (*output.ResultEvent, int) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, 0
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil, 0
	}

	// SetPath produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, 0
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, 0
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil, status
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil, status
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil, status
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil, status
			}
		}
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil, status
		}
	}

	if status != 200 {
		return nil, status
	}

	// Confirm the marker groups, then drop the finding if a sub-directory
	// catch-all serves the same markers for a nonexistent sibling (a handler that
	// 200s every child path). Root-level probes are covered by the random-path 404
	// fingerprint above, so the sibling probe is a no-op for them.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, body, p.markers)
	if !ok {
		return nil, status
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Spring Gateway Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"spring", "java", "gateway", "misconfiguration"},
			Reference:   []string{"https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/"},
		},
	}, status
}
