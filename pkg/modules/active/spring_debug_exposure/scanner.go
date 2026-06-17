package spring_debug_exposure

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
		path:        "/error",
		name:        "Whitelabel Error Page",
		markers:     [][]string{{"Whitelabel Error Page", "There was an unexpected error"}},
		antiMarkers: []string{"404", "nginx", "Apache"},
		sev:         severity.Low,
		desc:        "Spring Boot Whitelabel Error Page is enabled, confirming Spring Boot is running and may reveal version information",
	},
	{
		path:        "/error?trace=true",
		name:        "Whitelabel Error with Stack Trace",
		markers:     [][]string{{".java:", "Caused by:", "Exception"}, {"at java.", "at org.", "at com.", "org.springframework"}},
		antiMarkers: []string{},
		sev:         severity.Medium,
		desc:        "Spring Boot Whitelabel Error Page returns full stack traces when trace parameter is provided, revealing internal packages, libraries, and code paths",
	},
	{
		path:        "/error?message=true&trace=true",
		name:        "Whitelabel Error with Message and Trace",
		markers:     [][]string{{"Caused by:", "Exception"}, {"org.springframework", ".java:", "at java."}},
		antiMarkers: []string{},
		sev:         severity.Medium,
		desc:        "Spring Boot error page returns detailed error messages and stack traces",
	},
	{
		path:        "/.~~spring-boot!~/restart",
		name:        "Spring DevTools Remote Restart",
		markers:     [][]string{{"restart"}, {"spring"}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Spring Boot DevTools remote restart endpoint is accessible, potentially allowing remote application restart and configuration manipulation",
		bypass:      true,
	},
	{
		path:        "/actuator/startup",
		name:        "Actuator Startup Events",
		markers:     [][]string{{`"startupStep"`, `"timeline"`}, {`"startupStep"`, `"spring.boot"`, `"spring.beans"`, `"duration"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Boot startup events endpoint exposed, revealing application initialization details, bean creation order, and timing data",
		bypass:      true,
	},
	{
		path:        "/actuator/conditions",
		name:        "Actuator Auto-Configuration Report",
		markers:     [][]string{{`"positiveMatches"`, `"negativeMatches"`, `"unconditionalClasses"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Boot auto-configuration conditions endpoint exposed, revealing which configurations are active and why",
		bypass:      true,
	},
	{
		path:        "/actuator/scheduledtasks",
		name:        "Actuator Scheduled Tasks",
		markers:     [][]string{{`"cron"`, `"fixedDelay"`, `"fixedRate"`}, {`"target"`, `"runnable"`, `"expression"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Spring Boot scheduled tasks endpoint exposed, revealing internal task scheduling and method names",
		bypass:      true,
	},
	{
		path:        "/actuator/caches",
		name:        "Actuator Caches",
		markers:     [][]string{{`"cacheManagers"`}, {`"caches"`, `"cacheManager"`, `"target"`}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Spring Boot caches endpoint exposed, revealing cache manager configuration and cache names",
		bypass:      true,
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Spring Debug Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Spring Debug Exposure module.
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
		ds: dedup.LazyDiskSet("spring_debug_exposure"),
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

// ScanPerRequest probes the host for exposed Spring Boot debug endpoints.
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
	randomPath := "/vigolium-spring-debug-404-" + utils.RandomString(8)

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

	// Catch-all / shell guard: a body textually equivalent to the originally
	// observed page means the app routed this sub-path back to its standard shell
	// rather than serving a distinct debug surface — "the same body with or without
	// the probe".
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil, status
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil, status
		}
	}

	if status != 200 {
		return nil, status
	}

	// Strip the reflected probe path before matching: the DevTools restart probe's
	// markers ("restart", "spring") are both segments of /.~~spring-boot!~/restart,
	// so a page echoing the requested path would otherwise satisfy both groups.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	// Confirm the marker groups, then drop the finding if a sub-directory
	// catch-all serves the same markers for a nonexistent sibling (a handler that
	// 200s every child path). Root-level probes are covered by the random-path 404
	// fingerprint above, so the sibling probe is a no-op for them.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, matchBody, p.markers)
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
			Name:        fmt.Sprintf("Spring Debug: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"spring", "java", "debug", "information-disclosure"},
			Reference:   []string{"https://docs.spring.io/spring-boot/docs/current/reference/html/web.html#web.servlet.spring-mvc.error-handling"},
		},
	}, status
}
