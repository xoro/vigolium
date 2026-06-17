package magento_misconfig

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// deployedVersionPattern matches the bare version token Magento writes to
// /static/deployed_version.txt — a Unix timestamp or build hash, a single
// whitespace-free token. Prose/HTML/JSON (which contain spaces) won't match.
var deployedVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type probe struct {
	path string
	name string
	// markers is an AND-of-OR matcher: the body must contain at least one
	// substring from EVERY group. A single weak word ("setup", "downloader",
	// "admin") is never sufficient on its own — a probe fires only when a
	// Magento-identity anchor co-occurs with a page-specific token, so a themed
	// catch-all / SPA shell that merely happens to contain one of those words
	// does not match. An empty markers slice means the probe is validated
	// structurally in probeFile (see deployed_version.txt).
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	conf        severity.Confidence
	desc        string
}

var probes = []probe{
	// Setup wizard (Magento 2) — page-presence, Tentative
	{
		path:        "/setup/",
		name:        "Magento Setup Wizard",
		markers:     [][]string{{"Magento"}, {"Setup Wizard", "Web Setup Wizard", "setup/index.php", "Component Manager", "ng-app"}},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		conf:        severity.Tentative,
		desc:        "Magento setup wizard accessible in production, potentially allowing reconfiguration",
	},
	// Downloader (Magento 1.x) — page-presence, Tentative
	{
		path:        "/downloader/",
		name:        "Magento Downloader (Connect Manager)",
		markers:     [][]string{{"Magento"}, {"Connect Manager", "Magento Connect", "downloader/index.php", "Web Setup"}},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		conf:        severity.Tentative,
		desc:        "Magento Connect Manager (downloader) exposed, allowing extension installation",
	},
	// Version disclosure — page-presence, Tentative
	{
		path:        "/magento_version",
		name:        "Magento Version File",
		markers:     [][]string{{"Magento/"}, {"Community", "Enterprise", "Commerce"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		conf:        severity.Tentative,
		desc:        "Magento version file exposed, revealing exact platform version",
	},
	{
		path:        "/RELEASE_NOTES.txt",
		name:        "Magento Release Notes",
		markers:     [][]string{{"Magento"}, {"Release Notes"}, {"Bug Fixes", "Highlights", "Fixed"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		conf:        severity.Tentative,
		desc:        "Magento release notes file exposed, revealing platform version details",
	},
	// Exposed configuration
	{
		path:        "/app/etc/local.xml",
		name:        "Magento 1.x Configuration",
		markers:     [][]string{{"<config"}, {"<connection", "<dbname", "<crypt", "<key>", "<resources"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		conf:        severity.Firm,
		desc:        "Magento 1.x local.xml configuration exposed, containing database credentials and encryption key",
	},
	{
		path:        "/app/etc/env.php",
		name:        "Magento 2.x Environment Config",
		markers:     [][]string{{"<?php"}, {"'db'", "'crypt'", "'key'", "'connection'", "'dbname'", "'backend'"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		conf:        severity.Firm,
		desc:        "Magento 2.x env.php configuration exposed, containing database credentials and encryption key",
	},
	{
		path:        "/app/etc/config.php",
		name:        "Magento 2.x Module Config",
		markers:     [][]string{{"<?php"}, {"'modules'", "Magento_"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		conf:        severity.Firm,
		desc:        "Magento 2.x config.php exposed, revealing installed modules and their status",
	},
	// Admin paths — page-presence, Tentative
	{
		path: "/admin/",
		name: "Magento Admin (default)",
		markers: [][]string{
			{"Magento"},
			{"Dashboard", "Username", "Sign in to Admin", "adminhtml", "login-form", "Welcome, please sign in"},
		},
		sev:  severity.Medium,
		conf: severity.Tentative,
		desc: "Magento admin panel accessible at default path /admin/, should be moved to a custom URL",
	},
	// Error log
	{
		path:        "/var/log/exception.log",
		name:        "Magento Exception Log",
		markers:     [][]string{{"main.CRITICAL", "main.ERROR", "report.CRITICAL", "Exception"}, {"Magento\\", "Stack trace", "#0 ", "vendor/magento"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		conf:        severity.Firm,
		desc:        "Magento exception log exposed, revealing stack traces and internal application details",
	},
	{
		path:        "/var/log/system.log",
		name:        "Magento System Log",
		markers:     [][]string{{"main.INFO", "main.ERROR", "main.WARNING", "main.CRITICAL"}, {"Magento", "report.", "] [] []", "cron"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		conf:        severity.Firm,
		desc:        "Magento system log exposed, revealing application errors and operational details",
	},
	{
		path:        "/var/log/debug.log",
		name:        "Magento Debug Log",
		markers:     [][]string{{"main.DEBUG", "DEBUG:"}, {"Magento\\", "] [] []", "cache", "vendor/magento"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		conf:        severity.Firm,
		desc:        "Magento debug log exposed, revealing detailed application debugging information",
	},
	// Static version endpoint
	{
		path: "/static/deployed_version.txt",
		name: "Magento Deployed Version",
		// No substring marker: the file holds a bare version token (a Unix
		// timestamp or build hash), validated structurally in probeFile. The
		// previous "." marker matched every non-empty body.
		markers:     nil,
		antiMarkers: []string{"<html", "<!DOCTYPE", "404 Not Found"},
		sev:         severity.Info,
		conf:        severity.Tentative,
		desc:        "Magento deployed version file accessible, confirming Magento installation",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// Module implements the Magento Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Magento Misconfiguration module.
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
		ds: dedup.LazyDiskSet("magento_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to bypass default URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for Magento-specific misconfiguration files.
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

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// sub-directory Magento install (e.g. /store/<file>) is reached, not just the
	// root. Claim each (host, base) pair up front so a fully-deduped request issues
	// no traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeFile(ctx, httpClient, p, base+p.path, fp); result != nil {
				results = append(results, result)
			}
		}
	}
	return results, nil
}

// fingerprint404 fetches a non-existent path to learn what a 404 looks like.
func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-magento-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))

	status := 0
	contentType := ""
	if resp.Response() != nil {
		status = resp.Response().StatusCode
		contentType = strings.ToLower(resp.Response().Header.Get("Content-Type"))
	}

	return &notFoundFingerprint{
		status:      status,
		bodyHash:    hash,
		bodyLen:     len(body),
		contentType: contentType,
	}
}

// probeFile sends a GET request for a Magento file and validates the response.
func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	probePath string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode

	// Skip error responses
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	// Skip redirects to login
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	// Check against 404 fingerprint
	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil // same content as 404 page
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil // body length within 5% of 404 page
			}
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	// Check anti-markers
	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	// Require status 200 before any content match.
	if status != 200 {
		return nil
	}

	// Markerless probes need structural validation, not substring matching.
	if len(p.markers) == 0 {
		matchedMarkers := m.matchMarkerless(p, body)
		if matchedMarkers == nil {
			return nil
		}
		return m.buildResult(ctx, p, probePath, string(modifiedRaw), resp.FullResponseString(), matchedMarkers)
	}

	// Require the full co-occurrence marker set (AND across groups).
	// MatchAndConfirmSibling also drops the finding when a guaranteed-nonexistent
	// sibling under the same parent returns the same markers — a sub-directory
	// catch-all the root soft-404 fingerprint cannot see.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, body, p.markers)
	if !ok {
		return nil
	}
	return m.buildResult(ctx, p, probePath, string(modifiedRaw), resp.FullResponseString(), matchedMarkers)
}

// matchMarkerless validates a markerless probe structurally, returning the
// evidence to attach or nil when the body does not fit the expected shape.
func (m *Module) matchMarkerless(p probe, body string) []string {
	switch p.path {
	case "/static/deployed_version.txt":
		trimmed := strings.TrimSpace(body)
		if len(trimmed) == 0 || len(trimmed) > 64 || !deployedVersionPattern.MatchString(trimmed) {
			return nil
		}
		return []string{"deployed version: " + trimmed}
	default:
		return nil
	}
}

// buildResult assembles the finding for a confirmed probe hit.
func (m *Module) buildResult(
	ctx *httpmsg.HttpRequestResponse,
	p probe,
	probePath, requestRaw, responseRaw string,
	matchedMarkers []string,
) *output.ResultEvent {
	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          requestRaw,
		Response:         responseRaw,
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Magento Misconfiguration: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  p.conf,
			Tags:        []string{"php", "magento", "misconfiguration"},
			Reference:   []string{"https://experienceleague.adobe.com/docs/commerce-operations/configuration-guide/overview.html"},
		},
	}
}
