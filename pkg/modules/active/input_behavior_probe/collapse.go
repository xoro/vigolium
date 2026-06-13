package input_behavior_probe

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// collapseProbeFindings folds every behavior-change a single module run found for
// one endpoint into ONE finding. Each ResultEvent this module emits becomes its own
// row in the http_records table (the executor records result.Request per finding),
// so a probe-heavy run — dozens of header/path/debug/char probes — would otherwise
// write dozens of near-identical records and flood the table. The most
// security-relevant probe survives as the finding's primary request/response (the
// single record this finding links to); every other probe rides along as a labeled
// AdditionalEvidence pair, which is stored INLINE on the finding and never becomes
// its own http_records row. AdditionalEvidence is capped at modkit.MaxEvidencePairs,
// so the collapsed finding stays bounded. Returns nil for an empty input.
func collapseProbeFindings(results []*output.ResultEvent) []*output.ResultEvent {
	if len(results) == 0 {
		return nil
	}

	// All probes for one endpoint belong to a single group (constant key), so the
	// most security-relevant probe survives as the primary and the rest fold into
	// its AdditionalEvidence. probeFindingRank ranks a real status transition
	// (403→200 bypass, →5xx error) above a tag-structure-only change (the noisiest).
	collapsed := modkit.CollapseFindings(results, modkit.CollapseSpec{
		Key:   func(*output.ResultEvent) string { return "endpoint" },
		Rank:  probeFindingRank,
		Label: probeEvidenceLabel,
	})
	if len(collapsed) == 1 {
		if collapsed[0].Metadata == nil {
			collapsed[0].Metadata = map[string]any{}
		}
		// Record how many probes diverged so the operator knows the inline evidence is
		// a (capped) sample, not the full set, when the run exceeded MaxEvidencePairs.
		collapsed[0].Metadata["collapsed_probe_count"] = len(results)
	}
	return collapsed
}

// probeFindingRank scores a probe finding so collapseProbeFindings keeps the most
// security-relevant one as the surviving primary. Reads the status pair the probe
// recorded in Metadata (set by buildProbeResult).
func probeFindingRank(r *output.ResultEvent) int {
	base, _ := r.Metadata["base_status"].(int)
	fuzz, _ := r.Metadata["fuzz_status"].(int)
	switch {
	case base == 403 && fuzz == 200:
		return 3 // access-control bypass — most interesting
	case fuzz >= 500:
		return 2 // server/parser error surfaced
	case base != fuzz && fuzz != 0:
		return 1 // some other status transition
	default:
		return 0 // tag-structure-only change
	}
}

// probeEvidenceLabel renders a short marker (e.g. "path_prefix ../" or
// "header X-Forwarded-Host=localhost") for a collapsed probe's AdditionalEvidence
// entry so a reviewer can tell which input produced each captured pair.
func probeEvidenceLabel(r *output.ResultEvent) string {
	probeType, _ := r.Metadata["probe_type"].(string)
	payload := ""
	if len(r.ExtractedResults) > 0 {
		payload = r.ExtractedResults[0]
	}
	parts := make([]string, 0, 2)
	if probeType != "" {
		parts = append(parts, probeType)
	}
	switch {
	case r.FuzzingParameter != "" && payload != "":
		parts = append(parts, r.FuzzingParameter+"="+payload)
	case payload != "":
		parts = append(parts, payload)
	case r.FuzzingParameter != "":
		parts = append(parts, r.FuzzingParameter)
	}
	return strings.Join(parts, " ")
}
