package dashboardsig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogIntegrity enforces the invariants the two consumers rely on: unique
// IDs, a category, at least one detection avenue, lowercase markers, and that
// every confirmer asserts something (otherwise it would "confirm" any 200).
func TestCatalogIntegrity(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, p := range Catalog {
		require.NotEmpty(t, p.ID, "product missing ID")
		assert.Falsef(t, seen[p.ID], "duplicate product ID %q", p.ID)
		seen[p.ID] = true
		assert.NotEmptyf(t, p.Name, "%s: missing Name", p.ID)
		assert.NotEmptyf(t, p.Category, "%s: missing Category", p.ID)

		passive := len(p.Headers) > 0 || len(p.BodyMarkers) > 0 || len(p.Cookies) > 0
		active := len(p.Confirmers) > 0
		assert.Truef(t, passive || active, "%s: not detectable passively or actively", p.ID)

		assertLowercaseGroups(t, p.ID, p.BodyMarkers)
		for _, c := range p.Confirmers {
			assert.NotEmptyf(t, c.Path, "%s: confirmer missing Path", p.ID)
			asserts := len(c.Markers) > 0 || c.BodyRe != "" || c.HeaderName != ""
			assert.Truef(t, asserts, "%s: confirmer %q asserts nothing", p.ID, c.Path)
			assertLowercaseGroups(t, p.ID+" "+c.Path, c.Markers)
		}
	}
}

func assertLowercaseGroups(t *testing.T, ctx string, groups [][]string) {
	t.Helper()
	for _, g := range groups {
		for _, m := range g {
			assert.Equalf(t, strings.ToLower(m), m, "%s: marker %q must be lowercase", ctx, m)
		}
	}
}

func get(id string) *Product {
	for i := range Catalog {
		if Catalog[i].ID == id {
			return &Catalog[i]
		}
	}
	return nil
}

func TestMatchPassive_BodyMarkers(t *testing.T) {
	t.Parallel()
	body := `<html><head><title>Grafana</title></head><body>` +
		`<script>window.grafanaBootData = {settings:{}}</script></body></html>`
	got := MatchPassive(NewObserved(nil, nil, body))
	require.Len(t, got, 1)
	assert.Equal(t, "grafana", got[0].Product.ID)
}

func TestMatchPassive_UniqueHeader(t *testing.T) {
	t.Parallel()
	obs := NewObserved(map[string]string{"X-Jenkins": "2.426.1"}, nil, "<html>unrelated</html>")
	got := MatchPassive(obs)
	require.Len(t, got, 1)
	assert.Equal(t, "jenkins", got[0].Product.ID)
	assert.Equal(t, "2.426.1", got[0].Version, "X-Jenkins header value should be extracted as version")
}

func TestMatchPassive_NoFalsePositive(t *testing.T) {
	t.Parallel()
	got := MatchPassive(NewObserved(nil, nil, `<html><body>just a normal marketing page</body></html>`))
	assert.Empty(t, got)
}

// TestMatchPassive_ProseMentionNoFP covers the engineering-blog false positives:
// a page that merely mentions a product in its title or body text must not be
// fingerprinted as that product's console.
func TestMatchPassive_ProseMentionNoFP(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"consul prose":  `<html><head><title>Service Mesh Evolution</title></head><body><p>We adopted HashiCorp Consul for service discovery.</p></body></html>`,
		"airflow prose": `<html><head><title>The Journey of Deploying Apache Airflow at Grab</title></head><body><p>apache airflow powered our pipelines.</p></body></html>`,
		"gitlab prose":  `<html><head><meta property="og:site_name" content="Grab Engineering"><title>Our CI Journey</title></head><body><p>We migrated to GitLab CI.</p></body></html>`,
		"mlflow prose":  `<html><head><title>Chimera Sandbox</title></head><body><p>Experiment tracking with mlflow.</p></body></html>`,
		"kafka title":   `<html><head><title>Kafka on Kubernetes</title></head><body><p>Running Apache Kafka at scale.</p></body></html>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, MatchPassive(NewObserved(nil, nil, body)), "prose mention must not fingerprint a product")
		})
	}
}

// TestMatchPassive_ArticleGuard verifies a published article/blog page that
// mentions a product (even via a marker that would otherwise match) is dropped
// for body-only matches, while a header signal still fingerprints it.
func TestMatchPassive_ArticleGuard(t *testing.T) {
	t.Parallel()
	// An og:type=article page whose title starts with "Grafana" would otherwise
	// match grafana's "<title>grafana" marker — the article guard drops it.
	articleBody := `<html><head><meta property="og:type" content="article">` +
		`<title>Grafana Dashboards We Built</title></head><body>lots of prose</body></html>`
	assert.Empty(t, MatchPassive(NewObserved(nil, nil, articleBody)), "body-only match on an article page must be dropped")

	// JSON-LD BlogPosting is also recognised as an article.
	ldBody := `<html><head><script type="application/ld+json">{"@type":"BlogPosting"}</script>` +
		`<title>Prometheus at Scale</title></head><body><title>prometheus</title></body></html>`
	assert.Empty(t, MatchPassive(NewObserved(nil, nil, ldBody)), "JSON-LD article must suppress body-only fingerprints")

	// A header signal is not something prose can fake, so it still fingerprints
	// even on an article-typed page.
	withHeader := MatchPassive(NewObserved(map[string]string{"X-Jenkins": "2.426.1"}, nil, articleBody))
	require.Len(t, withHeader, 1)
	assert.Equal(t, "jenkins", withHeader[0].Product.ID)
}

// TestMatchPassive_RealConsoleStillDetected guards against over-suppression: a
// genuine product UI shell (not an article) is still fingerprinted.
func TestMatchPassive_RealConsoleStillDetected(t *testing.T) {
	t.Parallel()
	consul := `<html><head><title>Consul by HashiCorp</title><meta name="consul-ui/config/environment" content="..."></head><body><div id="consul"></div></body></html>`
	got := MatchPassive(NewObserved(nil, nil, consul))
	require.Len(t, got, 1)
	assert.Equal(t, "consul", got[0].Product.ID)
}

func TestConfirm_ElasticsearchTagline(t *testing.T) {
	t.Parallel()
	es := get("elasticsearch")
	require.NotNil(t, es)
	c := &es.Confirmers[0] // GET / with the tagline
	body := `{"name":"node-1","cluster_name":"prod","version":{"number":"8.13.0"},"tagline":"You Know, for Search"}`
	version, signals, ok := c.Confirm(200, func(string) string { return "" }, body, strings.ToLower(body))
	require.True(t, ok)
	assert.Equal(t, "8.13.0", version)
	assert.GreaterOrEqual(t, signals, 2, "tagline + extracted version should be 2 corroborating signals")

	// A random/soft-404 body must not confirm (this is the catch-all guard the
	// active prober leans on).
	notFound := "<html>404 not found</html>"
	_, _, ok = c.Confirm(200, func(string) string { return "" }, notFound, strings.ToLower(notFound))
	assert.False(t, ok)
}

func TestConfirm_HeaderGated(t *testing.T) {
	t.Parallel()
	minio := get("minio")
	require.NotNil(t, minio)
	c := &minio.Confirmers[0] // /minio/health/live gated on Server: MinIO
	hdr := func(name string) string {
		if strings.EqualFold(name, "Server") {
			return "MinIO"
		}
		return ""
	}
	_, _, ok := c.Confirm(200, hdr, "", "")
	assert.True(t, ok, "MinIO health should confirm via the Server header on an empty body")

	_, _, ok = c.Confirm(200, func(string) string { return "nginx" }, "", "")
	assert.False(t, ok, "a non-MinIO server header must not confirm")
}

func TestLooksLikeSPAShell(t *testing.T) {
	t.Parallel()
	assert.True(t, LooksLikeSPAShell(`<!doctype html><html><body><div id="root"></div><script src="/static/js/main.abc.js"></script></body></html>`))
	assert.True(t, LooksLikeSPAShell(`<html><head><script>window.__NUXT__={}</script></head><body><div id="__nuxt"></div></body></html>`))
	assert.False(t, LooksLikeSPAShell(`{"database":"ok","version":"10.0.0"}`), "a JSON API body is not an SPA shell")
	assert.False(t, LooksLikeSPAShell(`<html><body>server-rendered marketing copy with lots of text</body></html>`))
}

func TestConfirm_LeakSeverity(t *testing.T) {
	t.Parallel()
	ollama := get("ollama")
	require.NotNil(t, ollama)
	// /api/tags is an unauth leak → High.
	assert.Equal(t, "installed model list", ollama.Confirmers[0].LeakName)
	assert.True(t, ollama.Confirmers[0].UnauthLeak)
	assert.NotZero(t, ollama.Confirmers[0].Severity())
}
