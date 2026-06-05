package backup_file_discovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// validZip is a minimal but real ZIP archive (a single empty entry) — it begins
// with the PK\x03\x04 local-file-header magic and is padded past the 1KB floor.
func validZip() []byte {
	b := []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00}
	b = append(b, []byte(strings.Repeat("vigolium-backup-archive-bytes-", 64))...)
	return b
}

// TestScanPerHost_DetectsRealArchive serves a genuine ZIP (correct magic +
// archive Content-Type) at a probed backup path while 404-ing everything else.
func TestScanPerHost_DetectsRealArchive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.zip" {
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(validZip())
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a real ZIP archive at a backup path must be reported")
	assert.Contains(t, res[0].Info.Name, "Backup File Exposed")
}

// TestScanPerHost_NoFalsePositive_OctetStreamNoMagic reproduces the dominant
// false positive: a 200 with an archive Content-Type and a >1KB body that is NOT
// actually an archive (no magic bytes) — e.g. a catch-all serving octet-stream.
// The magic-byte gate must drop it.
func TestScanPerHost_NoFalsePositive_OctetStreamNoMagic(t *testing.T) {
	t.Parallel()
	junk := strings.Repeat("this is not an archive, just bytes. ", 64) // >1KB, no magic
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-bkp-404") {
			w.WriteHeader(http.StatusNotFound) // distinct 404 fingerprint
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		// Everything else: a 200 claiming to be a binary download but with no
		// real archive content.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(junk))
	}))
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "octet-stream 200 without archive magic bytes must not be reported")
}
