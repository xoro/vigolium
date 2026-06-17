package api_key_url_exposure

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// authHeaders defines auth-like headers and their corresponding URL parameter names.
var authHeaders = []struct {
	header    string
	urlParams []string
}{
	{"Authorization", []string{"authorization", "access_token", "token"}},
	{"X-API-Key", []string{"api_key", "apikey"}},
	{"X-Api-Key", []string{"api_key", "apikey"}},
	{"Api-Key", []string{"api_key", "apikey"}},
	{"Apikey", []string{"api_key", "apikey"}},
	{"X-Auth-Token", []string{"auth_token", "token"}},
	{"X-Access-Token", []string{"access_token", "token"}},
}

// Module implements the API Key in URL active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new API Key in URL module.
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
		ds: dedup.LazyDiskSet("api_key_url_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests if API keys work when moved from headers to URL parameters.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Check if the original response is successful (2xx)
	if ctx.Response() == nil || ctx.Response().StatusCode() < 200 || ctx.Response().StatusCode() >= 300 {
		return nil, nil
	}

	originalStatus := ctx.Response().StatusCode()

	// Find the first matching auth header
	for _, ah := range authHeaders {
		headerValue, err := httpmsg.GetHeaderValue(ctx.Request().Raw(), ah.header)
		if err != nil || headerValue == "" {
			continue
		}

		// Found an auth header — try moving it to the first URL param name
		paramName := ah.urlParams[0]

		// Remove the auth header from the request. This stripped request is BOTH
		// the base for the URL-parameter probe and the no-credential control: if
		// the endpoint returns the same page with the credential removed entirely,
		// access never depended on the credential, so accepting it in the URL
		// proves nothing (the classic false positive — an unauthenticated endpoint
		// or an SPA/CDN catch-all that 2xx-es every request).
		strippedRaw, err := httpmsg.RemoveHeader(ctx.Request().Raw(), ah.header)
		if err != nil {
			return nil, nil
		}

		// No-credential control: header removed, no URL parameter added.
		controlStatus, controlBody, controlOK := fetch(httpClient, ctx.Service(), strippedRaw)

		// Add the value as a URL parameter.
		modifiedRaw, err := httpmsg.AppendURLParameter(strippedRaw, paramName, headerValue)
		if err != nil {
			return nil, nil
		}

		// AppendURLParameter produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			return nil, nil
		}

		if resp.Response() != nil && resp.Response().StatusCode >= 200 && resp.Response().StatusCode < 300 {
			// Confirm the URL parameter actually granted access: its response must
			// differ from the no-credential control (different status or a
			// genuinely dissimilar body after stripping the reflected credential).
			// Fail open when the control could not be fetched so a transient error
			// never silently drops a real finding.
			if controlOK {
				urlSig := modkit.NewResponseSignature(resp.Response().StatusCode, resp.Body().String(), headerValue)
				controlSig := modkit.NewResponseSignature(controlStatus, controlBody, headerValue)
				if modkit.RatioSimilar(controlSig, urlSig) {
					resp.Close()
					return nil, nil
				}
			}
			results := []*output.ResultEvent{
				{
					URL:      urlx.String(),
					Matched:  urlx.String(),
					Request:  string(modifiedRaw),
					Response: resp.FullResponseString(),
					ExtractedResults: []string{
						fmt.Sprintf("Auth header %s moved to URL parameter ?%s=", ah.header, paramName),
						fmt.Sprintf("Original status: %d, URL param status: %d", originalStatus, resp.Response().StatusCode),
					},
					Info: output.Info{
						Name:        fmt.Sprintf("API Key Accepted in URL Parameter (%s)", ah.header),
						Description: fmt.Sprintf("The server accepts the %s credential as a URL query parameter (?%s=). API keys in URLs are logged in server access logs, browser history, referrer headers, and proxy logs, increasing the risk of credential exposure.", ah.header, paramName),
					},
				},
			}
			resp.Close()
			return results, nil
		}
		resp.Close()

		// Only test the first matching auth header
		return nil, nil
	}

	return nil, nil
}

// fetch issues the given raw request and returns its status code and body. ok is
// false on any parse/HTTP/empty-response error so the caller can fail open.
// NoClustering bypasses the requester's short-lived response cache so the
// control probe is a genuinely fresh observation rather than a cached replay of
// a neighbouring request.
func fetch(client *http.Requester, service *httpmsg.Service, raw []byte) (status int, body string, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false
	}
	if service != nil {
		req = req.WithService(service)
	}
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), true
}
