package baas_endpoint_fingerprint

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/reconsig"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// maxBody caps how large a response body we scan for provider endpoints.
	maxBody = 2 << 20 // 2 MB
	// maxMatchesPerProvider caps endpoints harvested per provider per response.
	maxMatchesPerProvider = 20
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("baas_endpoint_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	if !reconsig.IsScannableContentType(ctx.Response().Header("Content-Type")) {
		return nil, nil
	}
	// Cheap size gate on the raw body slice (no copy) before the string copy.
	if n := len(ctx.Response().Body()); n == 0 || n > maxBody {
		return nil, nil
	}
	body := ctx.Response().BodyToString()
	// Cheap catalog-wide pre-filter: skip the 22-regex sweep when no provider
	// token is present (the common case for bodies with no backend references).
	if !providerGate.MatchString(body) {
		return nil, nil
	}

	pageHost := ""
	source := ""
	if urlx, err := ctx.URL(); err == nil {
		pageHost = reconsig.NormalizeHost(urlx.Hostname())
		source = urlx.String()
	}

	ds := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for i := range catalog {
		p := &catalog[i]
		matches := p.re.FindAllStringSubmatch(body, maxMatchesPerProvider)
		for _, m := range matches {
			matched := m[0]
			endpointHost := reconsig.HostOf(matched)
			if endpointHost == "" {
				continue
			}
			instance := joinSubmatches(m)

			// Report each distinct backend (provider + host) once per scan.
			if ds != nil && ds.IsSeen(p.name+"|"+endpointHost) {
				continue
			}

			scanCtx.MarkTech(pageHost, p.name)

			conf := severity.Certain
			if instance == "" {
				conf = severity.Firm
			}

			tags := append([]string{}, ModuleTags...)
			tags = append(tags, p.tags...)

			desc := fmt.Sprintf("%s endpoint referenced in this response (%s).", p.label, p.category)
			if instance != "" {
				desc += fmt.Sprintf(" Instance/tenant: %s", instance)
			}

			results = append(results, &output.ResultEvent{
				ModuleID:         ModuleID,
				Host:             pageHost,
				URL:              source,
				Matched:          matched,
				ExtractedResults: []string{matched},
				Info: output.Info{
					Name:        "Backend Service Referenced: " + p.label,
					Description: desc,
					Severity:    ModuleSeverity,
					Confidence:  conf,
					Tags:        tags,
				},
				Metadata: map[string]any{
					"provider": p.name,
					"category": p.category,
					"endpoint": endpointHost,
					"instance": instance,
				},
			})
		}
	}

	return results, nil
}
