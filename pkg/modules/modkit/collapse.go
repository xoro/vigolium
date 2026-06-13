package modkit

import (
	"sort"

	"github.com/vigolium/vigolium/pkg/output"
)

// CollapseSpec configures CollapseFindings.
type CollapseSpec struct {
	// Key maps a finding to its group key; findings sharing a key collapse into one.
	// REQUIRED — a nil Key returns the input unchanged (no grouping possible).
	Key func(*output.ResultEvent) string
	// Rank scores findings so the highest-ranked survives as its group's primary
	// (the primary's Request/Response is the single http_record the executor
	// persists for the group). Higher wins; ties keep first-seen order. Optional —
	// defaults to the finding's declared severity (Critical > High > … > Info).
	Rank func(*output.ResultEvent) int
	// Label renders the AdditionalEvidence marker for a folded (non-primary) finding
	// so a reviewer can tell the captured pairs apart. Optional — defaults to the
	// finding's first ExtractedResults value, falling back to Info.Name.
	Label func(*output.ResultEvent) string
}

// CollapseFindings folds findings that share a Key into ONE ResultEvent per group,
// so a probe/fuzz module that confirms the same logical issue many ways writes a
// single http_records row per issue instead of one per probe. (The executor records
// one row per emitted finding's Request; folded findings ride along in the primary's
// AdditionalEvidence, which is stored inline on the finding and creates no row.)
//
// Group order follows first appearance, so output ordering is deterministic. Within
// a group the highest-Rank finding stays primary; the rest are folded into its
// AdditionalEvidence — labeled, ordered best-rank-first, and capped at
// MaxEvidencePairs (so the cap drops the least informative pairs). nil findings are
// skipped. With a nil Key (or empty input) the input is returned unchanged.
func CollapseFindings(results []*output.ResultEvent, spec CollapseSpec) []*output.ResultEvent {
	if len(results) == 0 || spec.Key == nil {
		return results
	}
	rank := spec.Rank
	if rank == nil {
		rank = func(r *output.ResultEvent) int { return int(r.Info.Severity) }
	}
	label := spec.Label
	if label == nil {
		label = defaultCollapseLabel
	}

	type group struct {
		primary *output.ResultEvent
		others  []*output.ResultEvent
	}
	order := make([]string, 0, len(results))
	groups := make(map[string]*group, len(results))

	for _, r := range results {
		if r == nil {
			continue
		}
		k := spec.Key(r)
		g, ok := groups[k]
		if !ok {
			groups[k] = &group{primary: r}
			order = append(order, k)
			continue
		}
		if rank(r) > rank(g.primary) {
			g.others = append(g.others, g.primary)
			g.primary = r
		} else {
			g.others = append(g.others, r)
		}
	}

	out := make([]*output.ResultEvent, 0, len(order))
	for _, k := range order {
		g := groups[k]
		if len(g.others) > 0 {
			// Score each finding once, then fold best-ranked first so the
			// MaxEvidencePairs cap drops the least informative pairs. Decorating with
			// the precomputed rank avoids re-invoking the caller's Rank closure on
			// every sort comparison.
			scored := make([]rankedFinding, len(g.others))
			for i, o := range g.others {
				scored[i] = rankedFinding{finding: o, rank: rank(o)}
			}
			sort.SliceStable(scored, func(i, j int) bool { return scored[i].rank > scored[j].rank })
			collector := NewEvidenceCollector()
			for _, s := range scored {
				collector.Add(label(s.finding), s.finding.Request, s.finding.Response)
			}
			if ev := collector.Entries(); len(ev) > 0 {
				g.primary.AdditionalEvidence = append(g.primary.AdditionalEvidence, ev...)
			}
		}
		out = append(out, g.primary)
	}
	return out
}

// rankedFinding pairs a folded finding with its precomputed rank for the
// decorate-sort in CollapseFindings.
type rankedFinding struct {
	finding *output.ResultEvent
	rank    int
}

// defaultCollapseLabel is the evidence marker used when a CollapseSpec omits Label:
// the folded finding's first extracted result (the payload/value that triggered it),
// falling back to its name.
func defaultCollapseLabel(r *output.ResultEvent) string {
	if r == nil {
		return ""
	}
	if len(r.ExtractedResults) > 0 && r.ExtractedResults[0] != "" {
		return r.ExtractedResults[0]
	}
	return r.Info.Name
}
