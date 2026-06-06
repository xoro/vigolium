package spring_actuator_misconfig

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// testCase pairs a set of actuator paths to probe with a confirm predicate that
// must recognize the *structure* of that endpoint's actuator response — not a
// single generic word. A bare substring like "status", "scope" or "beans"
// appears in countless unrelated JSON payloads (e.g. Keycloak's
// /auth/resources/<realm>/<theme>/<anything> i18n message bundles, which are
// application/json and contain those words), so each confirm requires the
// telltale key:value pairing or co-occurring keys that only a real Spring Boot
// Actuator endpoint emits.
type testCase struct {
	Payloads []string
	confirm  func(body string) bool
}

func (c *testCase) Matches(content string) bool {
	return c.confirm != nil && c.confirm(content)
}

type Module struct {
	modkit.BaseActiveModule
	contentTypeRegex *regexp.Regexp
	ds               dedup.Lazy[dedup.DiskSet]
	testCases        []*testCase
}

// https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/springboot/springboot-env.yaml
func New() *Module {
	contentTypeRegex := regexp.MustCompile(`(?mi)(application/vnd\.spring-boot\.actuator\.v[0-9]\+json|application/json|application/vnd\.spring-boot.actuator)`)
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
		contentTypeRegex: contentTypeRegex,
		ds:               dedup.LazyDiskSet("spring_actuator_misconfig"),
		testCases:        initTestCases(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans the request for Spring Actuator misconfigurations.
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

	paths := utils.SplitPathRecursive(urlx.Path)
	if len(paths) == 0 {
		return results, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	for _, path := range paths {
		if path == "/" || path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		path = strings.TrimSuffix(path, "/")

		checksum := getChecksum(urlx, path)
		if diskSet != nil && diskSet.IsSeen(checksum) {
			continue
		}

		for _, testCase := range m.testCases {
			for _, payload := range testCase.Payloads {
				// Build the new path with payload (the actuator endpoint under this
				// directory) and probe it.
				newPath := path + "/" + payload

				rawReq, body, ok := m.fetchPathBody(ctx, httpClient, newPath)
				if !ok || !testCase.Matches(body) {
					continue
				}

				// Soft-404 guard: reject when the matched actuator response is just
				// the host's wildcard shell (a server that 200s every path). Compares
				// against a cached host-wide random-path fingerprint; fails open on
				// probe error so a real actuator is never suppressed by a flaky probe.
				if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), "") {
					continue
				}

				// Sub-directory catch-all guard: probe a guaranteed-nonexistent sibling
				// under the SAME parent directory and drop the finding if it yields the
				// same actuator marker. This reproduces the /health-vs-/aaaa comparison
				// directly and catches catch-all static handlers (e.g. Keycloak's
				// /auth/resources/.../<path>) that the root-scoped wildcard probe above
				// cannot — the catch-all only fires under a specific path prefix.
				if m.siblingIsCatchAll(testCase, path, ctx, httpClient) {
					continue
				}

				results = append(results, &output.ResultEvent{
					URL:              urlx.Scheme + "://" + urlx.Host + newPath,
					Request:          rawReq,
					Response:         body,
					FuzzingParameter: path,
				})
			}
		}
	}

	return results, nil
}

func getChecksum(urlx *urlutil.URL, path string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(urlx.Scheme+"|"+urlx.Host+"|"+path)))
}

// fetchPathBody issues a GET to newPath, carrying the original request's headers
// and service, and returns the raw request and response body only when the
// response is a 200 with an actuator-compatible content type. ok is false on any
// build/transport error or a non-matching status/content type.
func (m *Module) fetchPathBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	newPath string,
) (rawReq, body string, ok bool) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return "", "", false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, newPath)
	if err != nil {
		return "", "", false
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return "", "", false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return "", "", false
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return "", "", false
	}
	if !m.contentTypeRegex.MatchString(resp.Response().Header.Get("Content-Type")) {
		return "", "", false
	}

	return string(modifiedRaw), resp.Body().String(), true
}

// siblingIsCatchAll probes a random, guaranteed-nonexistent sibling path under
// the same parent directory and reports whether it returns the SAME actuator
// marker match. A genuine actuator endpoint only emits its report at its own
// path; a catch-all handler (Keycloak i18n resources, SPA fallbacks, static file
// servers that 200 every child path) returns the same blob for the sibling too.
// Returns false on any probe/parse error so a flaky probe never suppresses a
// real finding.
func (m *Module) siblingIsCatchAll(
	tc *testCase,
	parentPath string,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) bool {
	siblingPath := parentPath + "/" + modkit.FreshCanary()
	_, body, ok := m.fetchPathBody(ctx, httpClient, siblingPath)
	if !ok {
		return false
	}
	return tc.Matches(body)
}

// containsAny reports whether body contains at least one of subs.
func containsAny(body string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

var (
	// healthStatusRe matches the actuator /health status field paired with one of
	// the Spring Boot Health status enum values (UP/DOWN/OUT_OF_SERVICE/UNKNOWN),
	// in compact or pretty-printed JSON. {"status":"UP"} is the minimal health
	// body, so the key:value pairing — not the bare word "status" — is the anchor.
	healthStatusRe = regexp.MustCompile(`"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`)

	// metricNameRe matches a dotted Micrometer/JVM metric id as emitted in the
	// /metrics names array (jvm.memory.used, process.cpu.usage, system.cpu.count,
	// http.server.requests, tomcat.sessions.active, hikaricp.connections, ...).
	// These dotted ids are specific to the actuator metrics registry.
	metricNameRe = regexp.MustCompile(`"(jvm\.[a-z.]+|process\.[a-z.]+|system\.[a-z.]+|http\.server\.requests|tomcat\.[a-z.]+|logback\.events|hikaricp\.[a-z.]+|spring\.[a-z.]+)"`)
)

func initTestCases() []*testCase {
	return []*testCase{
		{
			// /env — Environment property dump. Always wrapped in the
			// propertySources/activeProfiles envelope; require it plus a corroborating
			// inner key so a config blob that merely mentions "server.port" is rejected.
			Payloads: []string{"env", "..;/env", "..;xxx/env", "actuator/env", "..;/actuator/env", "..;xxx/actuator/env"},
			confirm: func(b string) bool {
				return strings.Contains(b, `"propertySources"`) &&
					containsAny(b,
						`"activeProfiles"`,
						`"name":"systemProperties"`,
						`"name":"systemEnvironment"`,
						`"local.server.port"`,
						`"server.ports"`,
					)
			},
		},
		{
			// /info — build & git metadata. Require the build or git block paired with
			// one of its inner fields so a bare "build"/"git" word doesn't match.
			Payloads: []string{"info", "..;/info", "..;xxx/info", "actuator/info", "..;/actuator/info", "..;xxx/actuator/info"},
			confirm: func(b string) bool {
				return (strings.Contains(b, `"build"`) && containsAny(b, `"artifact"`, `"version"`, `"group"`)) ||
					(strings.Contains(b, `"git"`) && containsAny(b, `"commit"`, `"branch"`))
			},
		},
		{
			// /health — status enum. The {"status":"UP"} key:value pair is the anchor.
			Payloads: []string{"health", "..;/health", "actuator/health", "..;/actuator/health"},
			confirm:  func(b string) bool { return healthStatusRe.MatchString(b) },
		},
		{
			// /metrics — names list or a single metric's measurements. Require a real
			// dotted Micrometer metric id, or the measurements/availableTags envelope
			// of a /metrics/{name} response.
			Payloads: []string{"metrics", "..;/metrics", "actuator/metrics", "..;/actuator/metrics"},
			confirm: func(b string) bool {
				return metricNameRe.MatchString(b) ||
					(strings.Contains(b, `"measurements"`) && containsAny(b, `"availableTags"`, `"statistic"`, `"baseUnit"`))
			},
		},
		{
			// /loggers — configured/effective levels. configuredLevel/effectiveLevel
			// are essentially unique to the actuator loggers report; otherwise require
			// the levels-enum array alongside the loggers map.
			Payloads: []string{"loggers", "..;/loggers", "actuator/loggers", "..;/actuator/loggers"},
			confirm: func(b string) bool {
				return containsAny(b, `"configuredLevel"`, `"effectiveLevel"`) ||
					(strings.Contains(b, `"levels"`) && strings.Contains(b, `"loggers"`))
			},
		},
		{
			// /beans — bean catalog. Each bean entry carries scope/type/dependencies/
			// aliases under a contexts→beans tree. Require that structural co-occurrence
			// so a page that merely contains the word "scope" (e.g. OAuth client scopes)
			// is not mistaken for a bean dump.
			Payloads: []string{"beans", "..;/beans", "actuator/beans", "..;/actuator/beans"},
			confirm: func(b string) bool {
				return strings.Contains(b, `"beans"`) &&
					containsAny(b, `"dependencies"`, `"aliases"`) &&
					containsAny(b, `"scope"`, `"contexts"`, `"type"`)
			},
		},
		{
			// /mappings — request mappings. dispatcherServlets / requestMappingConditions
			// / requestMappingHandlerMapping are unique to the actuator mappings report.
			Payloads: []string{"mappings", "..;/mappings", "actuator/mappings", "..;/actuator/mappings"},
			confirm: func(b string) bool {
				return containsAny(b, `"dispatcherServlets"`, `"requestMappingConditions"`, `"requestMappingHandlerMapping"`) ||
					(strings.Contains(b, `"contexts"`) && strings.Contains(b, `"mappings"`))
			},
		},
	}
}
