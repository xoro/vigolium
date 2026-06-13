package modkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func ev(key, name string, sev severity.Severity, req string) *output.ResultEvent {
	return &output.ResultEvent{
		Request:          req,
		Response:         "HTTP/1.1 200 OK\r\n\r\n",
		ExtractedResults: []string{req},
		Host:             key,
		Info:             output.Info{Name: name, Severity: sev},
	}
}

// TestCollapseFindings_FoldsGroupToOneRecord verifies same-key findings collapse to
// one ResultEvent (one http_record) with the rest as inline AdditionalEvidence.
func TestCollapseFindings_FoldsGroupToOneRecord(t *testing.T) {
	in := []*output.ResultEvent{
		ev("h1", "a", severity.Low, "r1"),
		ev("h1", "b", severity.High, "r2"),
		ev("h1", "c", severity.Medium, "r3"),
	}
	out := CollapseFindings(in, CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1, "one group must collapse to one finding")
	assert.Equal(t, severity.High, out[0].Info.Severity, "highest-severity finding becomes primary")
	assert.Len(t, out[0].AdditionalEvidence, 2, "the other two ride along as inline evidence")
}

// TestCollapseFindings_KeepsDistinctGroups verifies different keys stay separate and
// output order follows first appearance.
func TestCollapseFindings_KeepsDistinctGroups(t *testing.T) {
	in := []*output.ResultEvent{
		ev("h1", "a", severity.Low, "r1"),
		ev("h2", "b", severity.Low, "r2"),
		ev("h1", "c", severity.Low, "r3"),
	}
	out := CollapseFindings(in, CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 2, "two distinct keys yield two findings")
	assert.Equal(t, "h1", out[0].Host, "first-seen group comes first")
	assert.Equal(t, "h2", out[1].Host)
	assert.Len(t, out[0].AdditionalEvidence, 1, "h1's second finding folds into evidence")
	assert.Empty(t, out[1].AdditionalEvidence, "h2 had only one finding")
}

// TestCollapseFindings_EvidenceCappedBestFirst verifies the cap retains the
// highest-ranked extra evidence and drops the tail.
func TestCollapseFindings_EvidenceCappedBestFirst(t *testing.T) {
	in := []*output.ResultEvent{ev("h", "primary", severity.Critical, "r0")}
	for i := 0; i < 20; i++ {
		in = append(in, ev("h", "extra", severity.Low, "x"))
	}
	out := CollapseFindings(in, CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1)
	assert.Equal(t, severity.Critical, out[0].Info.Severity, "the Critical finding stays primary")
	assert.LessOrEqual(t, len(out[0].AdditionalEvidence), MaxEvidencePairs, "evidence must be capped")
}

// TestCollapseFindings_NilKeyReturnsInput verifies a missing Key is a safe no-op.
func TestCollapseFindings_NilKeyReturnsInput(t *testing.T) {
	in := []*output.ResultEvent{ev("h", "a", severity.Low, "r1"), ev("h", "b", severity.Low, "r2")}
	out := CollapseFindings(in, CollapseSpec{})
	assert.Equal(t, in, out, "a nil Key returns the input unchanged")
}

func TestCollapseFindings_EmptyIsNil(t *testing.T) {
	assert.Nil(t, CollapseFindings(nil, CollapseSpec{Key: func(*output.ResultEvent) string { return "x" }}))
}

// TestCollapseFindings_SkipsNil verifies nil entries don't panic and are dropped.
func TestCollapseFindings_SkipsNil(t *testing.T) {
	in := []*output.ResultEvent{nil, ev("h", "a", severity.Low, "r1"), nil}
	out := CollapseFindings(in, CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1)
	assert.Equal(t, "a", out[0].Info.Name)
}
