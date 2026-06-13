// Package dashboard_fingerprint passively recognises third-party dashboards,
// admin consoles and developer tools (Grafana, Airflow, GitLab, Jenkins, Ollama,
// ...) in already-observed responses, using the shared dashboardsig catalog. It
// emits an INFO finding and marks the product in the per-host TechRegistry so the
// active dashboard-exposure prober (and CVE matching) can build on it.
package dashboard_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/dashboardsig"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// maxBodyMatch caps how much of the body is lowercased and scanned per response.
// Product fingerprints (titles, JS bootstrap globals, JSON banners) live near the
// top of a document, so this keeps the per-response cost bounded on large pages.
const maxBodyMatch = 512 * 1024

// Module implements the passive dashboard fingerprint scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet] // per (host, product) dedup: report each once per host
}

// New creates a new dashboard fingerprint module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("dashboard_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	host := urlx.Host

	obs := buildObserved(ctx)
	matches := dashboardsig.MatchPassive(obs)
	if len(matches) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	var results []*output.ResultEvent
	for _, mt := range matches {
		p := mt.Product
		// Mark tech regardless of dedup so the active prober always sees the hint.
		scanCtx.MarkTech(host, p.ID)
		scanCtx.MarkTech(host, "dashboard")

		if diskSet != nil && diskSet.IsSeen(host+"|"+p.ID) {
			continue // already reported this product on this host
		}

		desc := p.Name + " detected (" + p.Category + ")."
		if mt.Version != "" {
			desc += " Version: " + mt.Version + "."
		}
		meta := map[string]any{
			"product":  p.ID,
			"category": p.Category,
		}
		if mt.Version != "" {
			meta["version"] = mt.Version
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: mt.Signals,
			Info: output.Info{
				Name:        p.Name + " Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  mt.Confidence,
				Tags:        append([]string{"dashboard", "fingerprint"}, p.Tags...),
				Reference:   p.References(),
			},
			Metadata: meta,
		})
	}
	return results, nil
}

// buildObserved extracts the header map, Set-Cookie names and (capped) body the
// catalog matcher needs from the response.
func buildObserved(ctx *httpmsg.HttpRequestResponse) dashboardsig.Observed {
	headers := map[string]string{}
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			continue // cookies handled via Cookies() below
		}
		headers[h.Name] = h.Value
	}
	var cookieNames []string
	for _, c := range ctx.Response().Cookies() {
		cookieNames = append(cookieNames, c.Name)
	}

	body := ctx.Response().BodyToString()
	if len(body) > maxBodyMatch {
		body = body[:maxBodyMatch]
	}
	return dashboardsig.NewObserved(headers, cookieNames, body)
}
