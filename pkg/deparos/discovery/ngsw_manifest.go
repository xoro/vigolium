package discovery

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Angular's service worker (ngsw-worker.js) reads /ngsw.json at runtime and
// pre-caches every asset it lists — that manifest is how a browser ends up
// fetching the full set of lazy-loaded webpack chunks (e.g. 100.<hash>.js)
// even for routes the user never visits. Those chunk filenames are built at
// runtime from a chunkId→hash map inside runtime.js, so they appear nowhere as
// literal strings in the markup and can't be recovered by static link
// extraction. The discovery engine does not run a service worker, so without
// help it only sees the chunks for routes it actually navigates to.
//
// This file holds the Angular-specific detection and ngsw.json parsing. The
// general, framework-aware harvesting that drives it lives in spa_manifest.go.

// looksLikeAngularApp reports whether an HTML body looks like an Angular (or
// Angular-PWA) single-page app. It is intentionally conservative — a single
// strong marker is enough, but generic markers must co-occur — so the harvester
// only probes Angular-specific manifests (ngsw.json) on Angular pages.
func looksLikeAngularApp(body []byte) bool {
	return angularMarkers(strings.ToLower(string(body)))
}

// angularMarkers reports Angular markers in an already-lowercased body. Callers
// that test several frameworks lowercase once and call the *Markers helpers
// directly to avoid re-allocating a lowercase copy of a large HTML body.
func angularMarkers(ls string) bool {
	// Strong, near-unambiguous Angular / Angular-service-worker markers.
	if strings.Contains(ls, "ng-version") ||
		strings.Contains(ls, "<app-root") ||
		strings.Contains(ls, "ngsw-worker.js") ||
		strings.Contains(ls, "ngsw.json") {
		return true
	}

	// Angular CLI emits hashed runtime/polyfills/main bundles. Requiring the
	// runtime+polyfills pair (both unique to a webpack/Angular build shell)
	// avoids matching unrelated apps that merely ship a main.js.
	return strings.Contains(ls, "polyfills.") && strings.Contains(ls, "runtime.")
}

// isNgswManifest reports whether a URL points at an Angular service-worker
// manifest (ngsw.json), the file whose hashTable / assetGroups enumerate every
// pre-cached asset.
func isNgswManifest(u *url.URL) bool {
	if u == nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Path), "ngsw.json")
}

// ngswManifest is the subset of the Angular ngsw.json schema we read. assetGroups
// hold the prefetched/lazy asset URLs; hashTable is keyed by the full asset URL
// of every versioned file and is the most complete source (it includes the
// index, every webpack chunk, and the workers themselves).
type ngswManifest struct {
	AssetGroups []struct {
		URLs []string `json:"urls"`
	} `json:"assetGroups"`
	HashTable map[string]string `json:"hashTable"`
}

// parseNgswManifestAssets parses an ngsw.json body and returns every same-origin
// fetchable asset URL it lists, de-duplicated. These are the lazy-loaded webpack
// chunks (and other versioned JS/JSON) that are otherwise unreachable without
// running the service worker. Returns nil when the body is not a parseable ngsw
// manifest.
func parseNgswManifestAssets(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}

	var m ngswManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}

	c := newURLCollector(base)
	for _, g := range m.AssetGroups {
		for _, u := range g.URLs {
			c.addFetchable(u)
		}
	}
	for u := range m.HashTable {
		c.addFetchable(u)
	}
	return c.out
}
