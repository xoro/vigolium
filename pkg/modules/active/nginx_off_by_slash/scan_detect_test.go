package nginx_off_by_slash

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const obsSecret = "<html><body>SECRET ALIASED DIRECTORY LISTING: db.conf app.py settings.py</body></html>"

// TestScanPerRequest_DetectsStableOffBySlash fires when an alias-traversal path
// (containing "..") returns a stable, distinct 200 across rounds while a random
// path 404s.
func TestScanPerRequest_DetectsStableOffBySlash(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(obsSecret))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a stable distinct 200 on an alias-traversal path must be reported")
}

// TestScanPerRequest_NoFalsePositive_TransientOffBySlash reproduces a one-shot
// 200: only the very first alias-traversal request succeeds, then 404s. The
// multi-round stability gate must drop it.
func TestScanPerRequest_NoFalsePositive_TransientOffBySlash(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			mu.Lock()
			first := !served
			served = true
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(obsSecret))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-shot transient 200 that does not reproduce must not be reported")
}
