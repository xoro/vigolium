//go:build canary

package e2e

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// fakeGCSObjectProxy simulates a CDN-fronted GCS/TOS object proxy with the
// HackerOne #3523931 behavior: a request path ending in a ..;-family segment
// collapses to the bucket and returns a ListObjects response, while a normal
// object fetch returns the (image) object and control suffixes 404.
func fakeGCSObjectProxy() *httptest.Server {
	const listing = `<?xml version="1.0"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>bucket</Name>` +
		`<Contents><Key>asset.png</Key></Contents>` +
		`<Contents><Key>secret-config.json</Key></Contents>` +
		`<Contents><Key>id_rsa</Key></Contents>` +
		`</ListBucketResult>`

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response carries a GCS backend signal.
		w.Header().Set("x-goog-generation", "1700000000")

		uri := strings.ToLower(r.RequestURI)
		traversal := strings.Contains(uri, "..;") ||
			strings.Contains(uri, "%2e%2e%3b") ||
			strings.Contains(uri, "%252e%252e%253b")

		switch {
		case traversal:
			// ..; collapses to the bucket -> ListObjects fallback.
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, listing)
		case r.URL.Path == "/obj/bucket/asset.png":
			// The object itself: an image (HEAD carries headers, no body).
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "\x89PNG\x0d\x0afake object bytes, not a listing")
			}
		default:
			// Everything else (control suffixes, wildcard probe) 404s like a
			// well-behaved backend.
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>`)
		}
	}))
}

// TestCanary_CDNObjectTraversal_StaticAsset drives the FULL native scan
// executor — including the object-storage static-file carve-out — against a
// faked GCS object proxy. The seed is a static .png object URL that the
// executor would normally drop; the carve-out keeps it (StaticMeta, HEAD), and
// the registered cdn-object-traversal-listing module confirms the ..; bucket
// listing end to end.
func TestCanary_CDNObjectTraversal_StaticAsset(t *testing.T) {
	srv := fakeGCSObjectProxy()
	defer srv.Close()

	// The default scope config classifies .png as a static file, so this seed
	// exercises the carve-out (without it the item would be dropped pre-fetch).
	staticMatcher := config.NewScopeMatcher(*config.DefaultScopeConfig())
	require.True(t, staticMatcher.IsStaticFile("/obj/bucket/asset.png"),
		"sanity: .png must be treated as a static file by the default config")

	activeModules := modules.GetActiveModulesByIDs([]string{"cdn-object-traversal-listing"})
	require.Len(t, activeModules, 1, "module must be registered")

	client := modtest.Requester(t)
	seed := modtest.Request(t, srv.URL+"/obj/bucket/asset.png")

	var mu sync.Mutex
	var findings []*output.ResultEvent

	cfg := core.ExecutorConfig{
		Workers:           2,
		Services:          &services.Services{Options: types.DefaultOptions(), DedupManager: dedup.NewManager()},
		HTTPRequester:     client,
		StaticFileMatcher: staticMatcher,
		MaxDuration:       60 * time.Second,
		OnResult: func(r *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, r)
			mu.Unlock()
		},
	}

	src := source.NewSliceSource([]*httpmsg.HttpRequestResponse{seed}, nil)
	executor := core.NewExecutor(cfg, src, activeModules, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := executor.Execute(ctx)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, findings, "expected a CDN object-storage traversal finding on the static .png seed")
	assert.Equal(t, "cdn-object-traversal-listing", findings[0].ModuleID)
	assert.Equal(t, "CDN Object-Storage Traversal Listing", findings[0].Info.Name)
}

// TestCanary_CDNObjectTraversal_CleanBackend confirms no finding against a
// well-behaved backend that 404s every ..; attempt (S3/Azure/ByteStore
// semantics) — guarding the end-to-end path against false positives.
func TestCanary_CDNObjectTraversal_CleanBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "CANARY")
		if r.URL.Path == "/obj/bucket/asset.png" && !strings.Contains(r.RequestURI, ";") {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "image bytes")
			}
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
	}))
	defer srv.Close()

	activeModules := modules.GetActiveModulesByIDs([]string{"cdn-object-traversal-listing"})
	require.Len(t, activeModules, 1)

	client := modtest.Requester(t)
	seed := modtest.Request(t, srv.URL+"/obj/bucket/asset.png")

	var mu sync.Mutex
	var findings []*output.ResultEvent
	cfg := core.ExecutorConfig{
		Workers:           2,
		Services:          &services.Services{Options: types.DefaultOptions(), DedupManager: dedup.NewManager()},
		HTTPRequester:     client,
		StaticFileMatcher: config.NewScopeMatcher(*config.DefaultScopeConfig()),
		MaxDuration:       60 * time.Second,
		OnResult: func(r *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, r)
			mu.Unlock()
		},
	}

	src := source.NewSliceSource([]*httpmsg.HttpRequestResponse{seed}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := core.NewExecutor(cfg, src, activeModules, nil).Execute(ctx)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, findings, "a clean backend must not produce a traversal finding")
}
