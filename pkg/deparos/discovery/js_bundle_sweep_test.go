package discovery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// jsBundleTestConfig builds an engine config with the JS-bundle sweep enabled
// and a small curated name list (keeps the per-test request count low).
func jsBundleTestConfig(startURL string, names []string) *config.Config {
	return &config.Config{
		Target: config.TargetConfig{
			StartURL:  startURL,
			Mode:      config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{Enabled: true, MaxDepth: 16},
			ScopeMode: "subdomain",
		},
		Filenames: config.FilenameConfig{Wordlists: config.WordlistConfig{}},
		Extensions: config.ExtensionConfig{
			JSBundleSweep: true,
			JSBundleNames: names,
		},
		Engine: config.EngineConfig{
			CaseSensitivity:  config.CaseInsensitive,
			DiscoveryThreads: 4,
			Timeout:          30 * time.Second,
		},
	}
}

// jsBundleServer serves the named files (full names like "admin.js" /
// "settings.json") with a matching content-type and 404s everything else, so
// the analyzer sees each real file as distinct from the soft-404 baseline. The
// landing page at "/" is plain server-rendered HTML.
func jsBundleServer(realFiles ...string) *httptest.Server {
	ctOf := func(p string) string {
		if strings.HasSuffix(p, ".json") {
			return "application/json"
		}
		return "application/javascript"
	}
	real := make(map[string]string, len(realFiles))
	for _, f := range realFiles {
		real["/"+f] = ctOf(f)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Acme Portal</h1><p>Welcome to the members area.</p></body></html>"))
			return
		}
		if ct, ok := real[r.URL.Path]; ok {
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write([]byte(`{"app":"acme","settings":{"api":"/api/v2/config","feature":true}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
}

func TestLooksLikeModernAppLanding(t *testing.T) {
	const monolith = `<html><body><h1>Acme Portal</h1><form action="/login"><input name="u"></form></body></html>`
	cases := []struct {
		name string
		body string
		ct   string
		path string
		want bool
	}{
		{"nextjs", `<html><head></head><body><div id="__next"></div><script id="__NEXT_DATA__">{}</script></body></html>`, "text/html", "/", true},
		{"react", `<html><body><div id="root"></div><script src="/static/js/main.js"></script><script>__REACT_DEVTOOLS_GLOBAL_HOOK__</script></body></html>`, "text/html", "/", true},
		{"angular", `<html><body><app-root ng-version="17.0.0"></app-root></body></html>`, "text/html", "/", true},
		{"monolith-html", monolith, "text/html", "/", false},
		{"spa-markers-but-json-ct", `{"__NEXT_DATA__":1}`, "application/json", "/", false},
		{"spa-markers-but-file-path", `<html>__NUXT__</html>`, "text/html", "/app.js", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := looksLikeModernAppLanding([]byte(tc.body), tc.ct, tc.path)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestJSONAcceptanceHelpers(t *testing.T) {
	// JSON content-type accepted; javascript must NOT match (no "json" substring).
	assert.True(t, isJSONContentType("application/json; charset=utf-8"))
	assert.True(t, isJSONContentType("application/ld+json"))
	assert.True(t, isJSONContentType("text/json"))
	assert.False(t, isJSONContentType("application/javascript"))
	assert.False(t, isJSONContentType("text/html"))

	jsonURL, _ := url.Parse("http://h/config.json")
	jsURL, _ := url.Parse("http://h/app.js")
	assert.True(t, hasJSONExtension(jsonURL))
	assert.False(t, hasJSONExtension(jsURL))
}

func TestIsHTMLContentType(t *testing.T) {
	assert.True(t, isHTMLContentType("text/html; charset=utf-8"))
	assert.True(t, isHTMLContentType("application/xhtml+xml"))
	assert.False(t, isHTMLContentType("application/javascript"))
	assert.False(t, isHTMLContentType("application/json"))
	assert.False(t, isHTMLContentType(""))
}

func TestJSDirBase(t *testing.T) {
	cases := map[string]string{
		"http://h/static/js/main.abc123.js": "http://h/static/js/",
		"http://h/app.js":                   "http://h/",
		"https://h:8443/a/b/c.js":           "https://h:8443/a/b/",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.Equal(t, want, jsDirBase(u), "jsDirBase(%q)", in)
	}
	// Schemeless / hostless inputs yield no base.
	rel, _ := url.Parse("/foo/bar.js")
	assert.Empty(t, jsDirBase(rel))
}

func TestJSBundleProbeBases_IncludesObservedDirs(t *testing.T) {
	engine, err := testEngineWithConfig(jsBundleTestConfig("http://example.test/app/", nil))
	require.NoError(t, err)
	defer engine.Stop()

	// Simulate JS observed on the start page under /static/js/.
	u, _ := url.Parse("http://example.test/static/js/main.abc.js")
	engine.recordObservedJSDir(u)
	engine.recordObservedJSDir(u) // dup is a no-op

	startURL, _ := url.Parse("http://example.test/app/")
	bases := engine.jsBundleProbeBases(startURL)

	assert.Contains(t, bases, "http://example.test/")           // root
	assert.Contains(t, bases, "http://example.test/app/")       // start dir
	assert.Contains(t, bases, "http://example.test/static/js/") // observed JS dir
}

func TestCollectJSBundleHits_MonolithFindsBundlesAndJSON(t *testing.T) {
	// Real .js bundles AND a sibling .json config; the same name list is probed
	// under both extensions.
	server := jsBundleServer("admin.js", "config.js", "settings.json")
	defer server.Close()

	engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"main", "admin", "config", "settings"}))
	require.NoError(t, err)
	defer engine.Stop()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	// Learn the soft-404 baseline first (initSession does this before probing).
	require.NoError(t, engine.learnBaselineFingerprints(u))

	hits := engine.collectJSBundleHits(u)

	paths := make([]string, 0, len(hits))
	for _, h := range hits {
		paths = append(paths, h.Path)
	}
	assert.Contains(t, paths, "/admin.js")
	assert.Contains(t, paths, "/config.js")
	assert.Contains(t, paths, "/settings.json", "sibling .json config must be discovered")
	assert.NotContains(t, paths, "/main.js", "main.js does not exist and must not be reported")
	assert.NotContains(t, paths, "/main.json", "main.json does not exist and must not be reported")
	assert.NotContains(t, paths, "/admin.json", "admin.json does not exist and must not be reported")
}

func TestCollectJSBundleHits_CatchAllSkipped(t *testing.T) {
	// Catch-all host: every path returns 200 application/javascript, so the
	// per-directory wildcard guard must suppress the whole directory.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("// universal bundle\nconsole.log('hi');"))
	}))
	defer server.Close()

	engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"main", "admin", "config"}))
	require.NoError(t, err)
	defer engine.Stop()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.NoError(t, engine.learnBaselineFingerprints(u))

	hits := engine.collectJSBundleHits(u)
	assert.Empty(t, hits, "a .js catch-all directory must yield no confirmed bundles")
}

func TestCollectJSBundleHits_HTMLAtJSPathRejected(t *testing.T) {
	// Soft-404 host: missing .js paths return a 200 HTML "not found" themed page
	// instead of a real 404. These must be rejected (HTML body at a .js path).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("// real admin bundle\nfetch('/api/admin');"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sorry, that page was not found.</body></html>"))
	}))
	defer server.Close()

	engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"main", "admin", "config"}))
	require.NoError(t, err)
	defer engine.Stop()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.NoError(t, engine.learnBaselineFingerprints(u))

	hits := engine.collectJSBundleHits(u)
	paths := make([]string, 0, len(hits))
	for _, h := range hits {
		paths = append(paths, h.Path)
	}
	assert.Contains(t, paths, "/admin.js", "the genuine JS bundle should be found")
	assert.NotContains(t, paths, "/main.js", "soft-404 HTML at /main.js must be rejected")
	assert.NotContains(t, paths, "/config.js", "soft-404 HTML at /config.js must be rejected")
	assert.NotContains(t, paths, "/admin.json", "soft-404 HTML at /admin.json must be rejected")
}

func TestSweepJSBundles_SkipsSPA(t *testing.T) {
	server := jsBundleServer("admin.js")
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Positive control: non-SPA HTML landing → admin.js is found and queued.
	t.Run("monolith sweeps", func(t *testing.T) {
		engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"admin"}))
		require.NoError(t, err)
		defer engine.Stop()
		require.NoError(t, engine.learnBaselineFingerprints(u))

		engine.startURLIsHTML = true
		engine.startURLIsModernApp = false

		assert.Equal(t, 1, engine.sweepJSBundles(), "monolith app should queue the discovered bundle")
	})

	// SPA landing → sweep is gated off, nothing queued (even though admin.js exists).
	t.Run("spa skips", func(t *testing.T) {
		engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"admin"}))
		require.NoError(t, err)
		defer engine.Stop()
		require.NoError(t, engine.learnBaselineFingerprints(u))

		engine.startURLIsHTML = true
		engine.startURLIsModernApp = true

		assert.Equal(t, 0, engine.sweepJSBundles(), "SPA landing must skip the JS-bundle sweep")
	})

	// Disabled via config → nothing queued regardless of app shape.
	t.Run("disabled", func(t *testing.T) {
		engine, err := testEngineWithConfig(jsBundleTestConfig(server.URL, []string{"admin"}))
		require.NoError(t, err)
		defer engine.Stop()
		engine.config.Extensions.JSBundleSweep = false
		engine.startURLIsHTML = true
		engine.startURLIsModernApp = false

		assert.Equal(t, 0, engine.sweepJSBundles(), "disabled sweep must do nothing")
	})
}
