//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// End-to-end coverage for `--db-isolate`: a scan runs into a private temporary
// SQLite database and merges its results into the real --db once finished. The
// payoff is that many parallel scan processes can target ONE shared --db
// without contending on a single SQLite writer during the scan. These tests
// drive the real CLI binary as a subprocess against a local httptest server, so
// they exercise the full flag → scratch → merge → cleanup path with no Docker.

// runIsolatedDiscover runs `vigolium run discover --db-isolate` against target,
// merging into destDB. It isolates per-process state via HOME so concurrent
// first-run initialization (wordlist materialization, ~/.vigolium seeding)
// never races, and points TMPDIR at scratchTmp so the scratch DB's lifecycle
// can be asserted. Returns the (ANSI-stripped) combined output and run error.
func runIsolatedDiscover(t *testing.T, bin, target, destDB, home, scratchTmp string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "run", "discover",
		"-t", target,
		"--db", destDB,
		"--db-isolate",
		"--scanning-max-duration", "10s",
		"--skip-dependency-check",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TMPDIR="+scratchTmp,
		"VIGOLIUM_PROJECT=",
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return terminal.StripANSI(out.String()), err
}

// countHTTPRecords opens the SQLite DB at path and returns its http_records count.
func countHTTPRecords(t *testing.T, path string) int {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        path,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   2000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM http_records").Scan(&n))
	return n
}

// assertNoScratchLeftovers fails if any vigolium-isolate-* scratch files remain
// in dir — the scratch DB (and its WAL sidecars) must be removed after a
// successful merge.
func assertNoScratchLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "vigolium-isolate-",
			"scratch DB should be cleaned up after a successful merge, found %s", e.Name())
	}
}

// TestDBIsolate_SingleRun verifies a single --db-isolate discover run merges
// results into a fresh destination DB and cleans up its scratch DB.
func TestDBIsolate_SingleRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping db-isolate e2e in short mode")
	}
	bin := buildVigoliumBinary(t)
	srv := startTestHTTPServer(t)

	home := t.TempDir()
	scratchTmp := t.TempDir()
	destDB := filepath.Join(t.TempDir(), "dest.sqlite")

	out, err := runIsolatedDiscover(t, bin, srv.URL+"/", destDB, home, scratchTmp)
	if err != nil {
		t.Fatalf("discover --db-isolate failed: %v\n%s", err, out)
	}

	// The destination (created by the merge) must hold the discovered records.
	require.GreaterOrEqual(t, countHTTPRecords(t, destDB), 1,
		"expected at least one merged HTTP record in the destination DB")
	// The merge runs to the real --db, so the success line names it.
	assert.Contains(t, out, "Merged results into", "expected merge confirmation in output")
	assertNoScratchLeftovers(t, scratchTmp)
}

// TestDBIsolate_ParallelSharedDB is the core scenario: many concurrent scan
// processes all target ONE shared --db with --db-isolate. Every process must
// succeed (no SQLITE_BUSY contention failures), the destination must accumulate
// records from all of them, and no scratch DBs may be left behind.
func TestDBIsolate_ParallelSharedDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping db-isolate e2e in short mode")
	}
	bin := buildVigoliumBinary(t)
	srv := startTestHTTPServer(t)

	const procs = 4
	scratchTmp := t.TempDir() // shared, so we can assert all scratch DBs were removed
	destDB := filepath.Join(t.TempDir(), "shared.sqlite")

	var wg sync.WaitGroup
	errs := make([]error, procs)
	outs := make([]string, procs)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Per-process HOME avoids first-run init races; the shared --db is
			// what exercises the merge-contention path.
			home := filepath.Join(t.TempDir(), fmt.Sprintf("home-%d", idx))
			require.NoError(t, os.MkdirAll(home, 0o755))
			outs[idx], errs[idx] = runIsolatedDiscover(t, bin, srv.URL+"/", destDB, home, scratchTmp)
		}(i)
	}
	wg.Wait()

	for i := 0; i < procs; i++ {
		if errs[i] != nil {
			t.Fatalf("parallel process %d failed (db-isolate should serialize merges, not fail): %v\n%s",
				i, errs[i], outs[i])
		}
	}

	// All processes merged into one DB without contention loss.
	require.GreaterOrEqual(t, countHTTPRecords(t, destDB), procs,
		"shared destination should accumulate records from all %d processes", procs)
	assertNoScratchLeftovers(t, scratchTmp)
}
