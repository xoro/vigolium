package modkit_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestPathBypassPrefixes(t *testing.T) {
	t.Parallel()

	// Shallow observed path: single-level encoding variants only, no multi-climb.
	root := modkit.PathBypassPrefixes("/")
	assert.Contains(t, root, "/..;/")
	assert.Contains(t, root, "/.;/")
	assert.Contains(t, root, "/..%3b/")
	assert.Contains(t, root, "/..%23/")
	assert.Contains(t, root, "/..%2f")
	assert.Contains(t, root, "/..%252f")
	for _, p := range root {
		assert.NotContains(t, p, "..;/..;", "a root observed path must not chain climbs")
	}

	// Deep observed path: chains /..;/..;/ scaled to depth AND launches from the
	// observed app directory.
	deep := modkit.PathBypassPrefixes("/app/v1/users/42")
	joined := strings.Join(deep, " ")
	assert.Contains(t, joined, "/..;/..;/", "a deep path must produce multi-segment climbs")
	assert.Contains(t, deep, "/app/v1/users/..;/..;/..;/",
		"a deep path must also launch from the observed app directory back to root")

	// No duplicates.
	seen := map[string]bool{}
	for _, p := range deep {
		assert.False(t, seen[p], "prefix %q duplicated", p)
		seen[p] = true
	}
}

func TestIsProxyBlockedStatus(t *testing.T) {
	t.Parallel()
	assert.True(t, modkit.IsProxyBlockedStatus(403))
	assert.True(t, modkit.IsProxyBlockedStatus(401))
	assert.True(t, modkit.IsProxyBlockedStatus(405))
	assert.False(t, modkit.IsProxyBlockedStatus(404), "a clean not-present must not trigger a bypass")
	assert.False(t, modkit.IsProxyBlockedStatus(200))
	assert.False(t, modkit.IsProxyBlockedStatus(0))
}

func TestProbePathBypass_AnnotatesFirstHit(t *testing.T) {
	t.Parallel()

	var tried []string
	res := modkit.ProbePathBypass("/", "/manager/html", func(bypassPath string) *output.ResultEvent {
		tried = append(tried, bypassPath)
		if bypassPath == "/..%3b/manager/html" { // pretend only the encoded-';' form reaches it
			return &output.ResultEvent{Info: output.Info{Name: "Tomcat Manager"}, ExtractedResults: []string{"Deploy"}}
		}
		return nil
	})

	if assert.NotNil(t, res) {
		assert.Contains(t, res.Info.Name, "path-normalization bypass")
		assert.Contains(t, res.Info.Tags, "acl-bypass")
		assert.Equal(t, "bypass path: /..%3b/manager/html", res.ExtractedResults[0])
	}
	assert.Equal(t, "/..;/manager/html", tried[0], "the literal /..;/ form is tried first")

	// No hit → nil, all prefixes attempted.
	none := modkit.ProbePathBypass("/", "manager/html", func(string) *output.ResultEvent { return nil })
	assert.Nil(t, none)
}
