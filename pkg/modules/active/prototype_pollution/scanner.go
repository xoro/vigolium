package prototype_pollution

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// pollutionPayload defines a prototype pollution test case.
type pollutionPayload struct {
	payload string
	desc    string
}

var payloads = []pollutionPayload{
	{
		payload: `{"__proto__":{"vigolium_pp_test":"polluted"}}`,
		desc:    "__proto__ property injection",
	},
	{
		payload: `{"constructor":{"prototype":{"vigolium_pp_test":"polluted"}}}`,
		desc:    "constructor.prototype injection",
	},
	{
		payload: `{"__proto__":{"status":510}}`,
		desc:    "__proto__ status code pollution (expects 510 response)",
	},
	{
		payload: `{"__proto__":{"__proto__":{"vigolium_pp_test":"polluted"}}}`,
		desc:    "Nested __proto__ injection",
	},
	{
		payload: `{"__proto__":{"toString":"polluted"}}`,
		desc:    "__proto__ toString gadget injection",
	},
}

// Module implements the Prototype Pollution active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Prototype Pollution module.
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
		rhm: dedup.LazyDefaultRHM("prototype_pollution"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// sendBody replaces the JSON request body with the given payload and returns the
// response status and body. NoClustering bypasses the response cache so the
// confirmation replays actually hit the server. ok is false on any error.
func (m *Module) sendBody(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, payload string) (int, string, bool) {
	raw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(payload))
	if err != nil {
		return 0, "", false
	}
	return modkit.ExecuteRaw(httpClient, ctx.Service(), raw, http.Options{NoClustering: true})
}

// confirmStatusPollution confirms a 510 status is reproducibly caused by the
// status-pollution payload rather than a transient 510. The status payload must
// return 510 across two rounds. (A benign after-the-fact control is intentionally
// NOT used: prototype pollution is stateful — once Object.prototype.status is
// polluted, every later response is 510 too, so such a control would false-
// negative a real sink. The pre-pollution baseline already establishes that the
// original request was not 510, which provides the attribution.) Fails OPEN on an
// inconclusive fetch error so a real finding is not suppressed.
func (m *Module) confirmStatusPollution(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	for range 2 {
		st, _, ok := m.sendBody(ctx, httpClient, `{"__proto__":{"status":510}}`)
		if !ok {
			return true // inconclusive
		}
		if st != 510 {
			return false // not reproducible
		}
	}
	return true
}

// confirmMarkerPollution confirms a reflected pollution marker is genuine across
// two rounds. Each round injects a fresh marker via __proto__ (which must
// reflect) and sends a SECOND, distinct marker as a normal top-level property
// that is never injected via __proto__ (the echo control). A real pollution sink
// surfaces only the __proto__-injected marker, never the plain one; an endpoint
// that merely echoes input reflects both — so a reflected echo-control marker
// drops the finding. Using a distinct control marker keeps this correct under
// stateful pollution (the control marker is never on the prototype). Fails OPEN
// on an inconclusive fetch error.
func (m *Module) confirmMarkerPollution(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, baseBody string) bool {
	for range 2 {
		markerA := "vgopp" + utils.RandomString(10)
		markerB := "vgopp" + utils.RandomString(10)
		_, pollResp, ok := m.sendBody(ctx, httpClient, `{"__proto__":{"`+markerA+`":"polluted"}}`)
		if !ok {
			return true // inconclusive
		}
		if !strings.Contains(pollResp, markerA) || strings.Contains(baseBody, markerA) {
			return false // not reproducibly introduced by the __proto__ payload
		}
		_, echoResp, ok := m.sendBody(ctx, httpClient, `{"`+markerB+`":"polluted"}`)
		if !ok {
			return true // inconclusive
		}
		if strings.Contains(echoResp, markerB) {
			return false // plain-property reflection → echoing endpoint, not pollution
		}
	}
	return true
}

// CanProcess limits to requests with JSON bodies.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Request() == nil {
		return false
	}
	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	method := ctx.Request().Method()
	// Only process POST/PUT/PATCH with JSON content
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}
	if !strings.Contains(ct, "json") {
		return false
	}
	return true
}

// ScanPerRequest tests the request for server-side prototype pollution.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Get baseline response (cached across modules)
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, nil
	}
	baseStatus := entry.StatusCode
	baseBody := entry.Response.BodyToString()

	var results []*output.ResultEvent

	for _, p := range payloads {
		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(p.payload))
		if err != nil {
			continue
		}

		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		detected := false
		var evidence string

		// Status code pollution (510). Strict drop-on-fail: a one-shot 510 is
		// unreliable (a server may 510 on any malformed input, or transiently).
		// Confirm it reproduces AND that a benign payload does NOT also 510.
		if resp.Response() != nil && strings.Contains(p.payload, "status") &&
			resp.Response().StatusCode == 510 && baseStatus != 510 {
			if m.confirmStatusPollution(ctx, httpClient) {
				detected = true
				evidence = fmt.Sprintf("Status code reproducibly changed from %d to 510", baseStatus)
			}
		}

		// Pollution marker reflected in response. Strict drop-on-fail: confirm
		// with a fresh random marker each round (proves input→output flow, kills
		// coincidental/transient matches) AND an echo control — the same marker
		// sent as a NORMAL property must NOT reflect, else the endpoint merely
		// echoes input and the reflection is not evidence of pollution.
		body := resp.Body().String()
		if !detected && strings.Contains(body, "vigolium_pp_test") && !strings.Contains(baseBody, "vigolium_pp_test") {
			if m.confirmMarkerPollution(ctx, httpClient, baseBody) {
				detected = true
				evidence = "Pollution marker reflected and confirmed (fresh-canary, echo control negative)"
			}
		}

		if detected {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: []string{p.payload, evidence},
				Info: output.Info{
					Name:        fmt.Sprintf("Prototype Pollution: %s", p.desc),
					Description: evidence,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
