package firebase_rtdb_exposure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Extract RTDB URLs from response body
	rtdbURLRe = regexp.MustCompile(`https://([a-z0-9][a-z0-9-]*[a-z0-9])\.firebaseio\.com`)

	// Secret patterns in exposed data
	secretPatterns = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
		{"Google API Key", regexp.MustCompile(`AIza[a-zA-Z0-9_-]{35}`)},
		{"Stripe Secret Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`)},
		{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`)},
		{"Slack Token", regexp.MustCompile(`xox[bprs]-[a-zA-Z0-9-]+`)},
	}
)

// Common RTDB subpaths that often contain sensitive data
var rtdbSubpaths = []string{
	"users",
	"user",
	"profiles",
	"config",
	"settings",
	"admin",
	"roles",
	"tokens",
	"accounts",
	"messages",
	"orders",
	"private",
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
		ds: dedup.LazyDiskSet("firebase_rtdb_exposure"),
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

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Extract RTDB URLs from response
	matches := rtdbURLRe.FindAllStringSubmatch(body, 10)
	if len(matches) == 0 {
		return nil, nil
	}

	// Deduplicate database names
	seen := make(map[string]struct{})
	var dbNames []string
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				dbNames = append(dbNames, name)
			}
		}
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for _, dbName := range dbNames {
		dedupKey := dbName + ".firebaseio.com"
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		dbURL := fmt.Sprintf("https://%s.firebaseio.com", dbName)

		// Probe root with shallow=true
		if result := m.probeRTDB(ctx, httpClient, dbURL, "", true); result != nil {
			results = append(results, result)

			// If root is readable, check for secrets in the data
			if secretResults := m.checkSecrets(ctx, httpClient, dbURL, result.Response); len(secretResults) > 0 {
				results = append(results, secretResults...)
			}
			continue
		}

		// Root denied — probe common subpaths. Each readable subpath proves the SAME
		// signal (this database has world-readable paths), so collapse them into ONE
		// finding per database instead of writing an http_record per subpath; the
		// extra readable paths ride along as inline evidence.
		var subResults []*output.ResultEvent
		for _, subpath := range rtdbSubpaths {
			if result := m.probeRTDB(ctx, httpClient, dbURL, subpath, false); result != nil {
				subResults = append(subResults, result)
			}
		}
		results = append(results, modkit.CollapseFindings(subResults, modkit.CollapseSpec{
			Key: func(*output.ResultEvent) string { return dbURL },
		})...)
	}

	return results, nil
}

// looksLikeRTDBData reports whether a 200 body is genuine Firebase Realtime
// Database content: it must parse as JSON and be a non-empty object or array
// (the shape of an exposed data tree). It rejects invalid JSON (HTML/error
// interstitials returned with a 200), empty/null trees, a lone {"error": ...}
// Firebase error envelope, and bare scalars — all of which are not evidence of a
// world-readable database.
func looksLikeRTDBData(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed == "null" || trimmed == "{}" || trimmed == "[]" {
		return false
	}
	var v interface{}
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return false
	}
	switch t := v.(type) {
	case map[string]interface{}:
		if len(t) == 0 {
			return false
		}
		if _, hasErr := t["error"]; hasErr && len(t) == 1 {
			return false // lone {"error": ...} Firebase envelope, not data
		}
		return true
	case []interface{}:
		return len(t) > 0
	default:
		return false // bare scalar node — too weak to confirm exposure
	}
}

func (m *Module) probeRTDB(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	dbURL string,
	subpath string,
	shallow bool,
) *output.ResultEvent {
	targetPath := "/.json"
	if subpath != "" {
		targetPath = "/" + subpath + ".json"
	}
	targetURL := dbURL + targetPath
	if shallow {
		targetURL += "?shallow=true"
	}

	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n",
		targetURL, strings.TrimPrefix(strings.TrimPrefix(dbURL, "https://"), "http://"))

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status != 200 {
		return nil
	}

	respBody := resp.Body().String()

	// Skip permission denied responses
	if strings.Contains(respBody, "Permission denied") {
		return nil
	}

	// Strict drop-on-fail: a 200 is only an exposure when the body is genuine,
	// non-trivial RTDB data — a non-empty JSON object/array. This drops 200s that
	// are not valid JSON (interstitials / error pages on a coincidentally-matched
	// host), empty/null trees, Firebase error envelopes, and bare scalars.
	if !looksLikeRTDBData(respBody) {
		return nil
	}

	name := "Firebase RTDB World-Readable (Root)"
	desc := fmt.Sprintf("Firebase Realtime Database at %s is publicly readable at root — full data exposure", dbURL)
	sev := severity.Critical
	if subpath != "" {
		name = fmt.Sprintf("Firebase RTDB Partial Exposure (/%s)", subpath)
		desc = fmt.Sprintf("Firebase Realtime Database at %s has publicly readable path /%s", dbURL, subpath)
		sev = severity.High
	}

	// Truncate response for storage
	responseStr := resp.FullResponseString()
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Matched:  targetURL,
		Request:  rawReq,
		Response: responseStr,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "rtdb", "data-exposure"},
		},
		Metadata: map[string]any{
			"database": dbURL,
			"subpath":  subpath,
			"shallow":  shallow,
		},
	}
}

func (m *Module) checkSecrets(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	dbURL string,
	responseBody string,
) []*output.ResultEvent {
	var results []*output.ResultEvent
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(responseBody) {
			results = append(results, &output.ResultEvent{
				URL:     dbURL + "/.json",
				Matched: sp.name + " found in RTDB data",
				Info: output.Info{
					Name:        fmt.Sprintf("Secret Leaked in Firebase RTDB (%s)", sp.name),
					Description: fmt.Sprintf("Publicly readable Firebase RTDB at %s contains embedded %s", dbURL, sp.name),
					Severity:    severity.Critical,
					Confidence:  severity.Firm,
					Tags:        []string{"firebase", "rtdb", "secret-leak"},
				},
				Metadata: map[string]any{
					"database":   dbURL,
					"secretType": sp.name,
				},
			})
		}
	}
	return results
}
