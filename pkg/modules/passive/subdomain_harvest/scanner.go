package subdomain_harvest

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/reconsig"
)

const (
	// maxBody caps how large a response body we scan for hostnames.
	maxBody = 2 << 20 // 2 MB
	// maxCandidates caps the unique FQDN-shaped tokens pulled from one body
	// before apex filtering (minified bundles can reference thousands).
	maxCandidates = 5000
	// maxPerResponse caps the in-scope subdomains reported from one response.
	maxPerResponse = 50
)

// nonProdRe flags hostnames whose labels suggest a non-production environment.
// Matched against the subdomain portion (everything left of the apex).
var nonProdRe = regexp.MustCompile(`(?i)(^|[.-])(dev|develop|development|staging|stage|stg|test|testing|qa|uat|sandbox|sbx|preprod|pre-prod|demo|internal|int)([.-]|$)`)

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
		ds: dedup.LazyDiskSet("subdomain_harvest"),
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

	// Cheap size gate on the raw body slice (no copy) before the costlier URL
	// parse, publicsuffix lookup, and the body string copy below.
	if n := len(ctx.Response().Body()); n == 0 || n > maxBody {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	pageHost := reconsig.NormalizeHost(urlx.Hostname())
	apex := reconsig.RegistrableDomain(pageHost)
	if apex == "" {
		return nil, nil // no resolvable registrable domain (e.g. raw IP, localhost)
	}

	body := ctx.Response().BodyToString()

	suffix := "." + apex
	ds := m.ds.Get(scanCtx.DedupMgr())

	var found []string
	hasNonProd := false
	for _, c := range reconsig.ExtractHosts(body, maxCandidates) {
		// Org-scoped: keep only hosts under the page's registrable domain.
		if c != apex && !strings.HasSuffix(c, suffix) {
			continue
		}
		if c == pageHost {
			continue // the page's own host is not a new discovery
		}
		// Report each subdomain at most once per scan (across all pages).
		if ds != nil && ds.IsSeen(apex+"|"+c) {
			continue
		}
		found = append(found, c)
		if labels := subdomainLabels(c, apex); labels != "" && nonProdRe.MatchString(labels) {
			hasNonProd = true
		}
		if len(found) >= maxPerResponse {
			break
		}
	}

	if len(found) == 0 {
		return nil, nil
	}

	// Under --follow-subdomains, pull each discovered host into the scan: add the
	// EXACT host to the runtime scope allow-set (never the apex wildcard) and feed
	// its root URL back for scanning.
	fed := 0
	if scanCtx.ShouldFollowSubdomains() {
		feeder := scanCtx.Feeder()
		for _, c := range found {
			scanCtx.AllowHost(c)
			if rr, err := httpmsg.GetRawRequestFromURL("https://" + c + "/"); err == nil && feeder.Feed(rr) {
				fed++
			}
		}
	}

	tags := append([]string{}, ModuleTags...)
	if hasNonProd {
		tags = append(tags, "non-prod")
	}

	desc := fmt.Sprintf("Discovered %d in-scope subdomain(s) of '%s' referenced in this response. "+
		"These are additional hosts belonging to the target organization and may be worth scanning directly.", len(found), apex)
	if hasNonProd {
		desc += " At least one references a non-production environment (dev/staging/test), which often runs with weaker controls."
	}
	if fed > 0 {
		desc += fmt.Sprintf(" %d host(s) were added to scope and queued for scanning (--follow-subdomains).", fed)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             pageHost,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		ExtractedResults: found,
		Info: output.Info{
			Name:        "In-Scope Subdomains Referenced",
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        tags,
		},
		Metadata: map[string]any{
			"apex":       apex,
			"subdomains": found,
		},
	}}, nil
}

// subdomainLabels returns the portion of host to the left of the apex, i.e. the
// subdomain labels. Returns "" when host equals the apex.
func subdomainLabels(host, apex string) string {
	return strings.TrimSuffix(host, "."+apex)
}
