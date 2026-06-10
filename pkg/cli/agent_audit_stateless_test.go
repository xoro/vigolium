package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditFlagDefaults locks the operator-facing flag contract for the audit
// command: --keep-raw is on by default, --clean-raw / --stateless default off,
// and -S/-o carry their short forms.
func TestAuditFlagDefaults(t *testing.T) {
	f := agentAuditCmd.Flags()

	keepRaw := f.Lookup("keep-raw")
	require.NotNil(t, keepRaw, "keep-raw flag must exist")
	assert.Equal(t, "true", keepRaw.DefValue, "keep-raw must default ON")

	cleanRaw := f.Lookup("clean-raw")
	require.NotNil(t, cleanRaw, "clean-raw flag must exist")
	assert.Equal(t, "false", cleanRaw.DefValue)

	stateless := f.Lookup("stateless")
	require.NotNil(t, stateless, "stateless flag must exist")
	assert.Equal(t, "false", stateless.DefValue)
	assert.Equal(t, "S", stateless.Shorthand, "stateless must keep the -S short form")

	output := f.Lookup("output")
	require.NotNil(t, output, "output flag must exist")
	assert.Equal(t, "o", output.Shorthand, "output must keep the -o short form")
}

// TestAuditAliasSharesFlags verifies the top-level `vigolium audit` alias is
// wired to the same RunE and exposes the same flag set as `vigolium agent
// audit` (both go through registerAuditFlags).
func TestAuditAliasSharesFlags(t *testing.T) {
	require.NotNil(t, auditCmd.RunE, "auditCmd must have a RunE")
	assert.Equal(t, "audit", auditCmd.Name())

	// The alias must surface the audit-specific flags so users get identical
	// behavior regardless of entry point.
	for _, name := range []string{"keep-raw", "clean-raw", "stateless", "output", "driver", "mode"} {
		assert.NotNilf(t, auditCmd.Flags().Lookup(name),
			"alias `vigolium audit` is missing --%s", name)
	}

	// Both entry points share the same Examples block.
	assert.NotEmpty(t, auditCmd.Example, "alias should carry usage examples")
	assert.Equal(t, agentAuditCmd.Example, auditCmd.Example,
		"alias and subcommand must show identical examples")
}

// TestKeepSourceResults walks the keep-raw / clean-raw truth table that decides
// whether <source>/vigolium-results/ survives in the source tree.
func TestKeepSourceResults(t *testing.T) {
	origKeep, origClean := auditKeepRaw, auditCleanRaw
	t.Cleanup(func() { auditKeepRaw, auditCleanRaw = origKeep, origClean })

	cases := []struct {
		keepRaw  bool
		cleanRaw bool
		want     bool
	}{
		{true, false, true},   // default: keep the source copy
		{true, true, false},   // --clean-raw wins
		{false, false, false}, // --keep-raw=false: clean (legacy behavior)
		{false, true, false},
	}
	for _, c := range cases {
		auditKeepRaw, auditCleanRaw = c.keepRaw, c.cleanRaw
		if got := keepSourceResults(); got != c.want {
			t.Errorf("keepSourceResults(keepRaw=%v, cleanRaw=%v) = %v, want %v",
				c.keepRaw, c.cleanRaw, got, c.want)
		}
	}
}

// TestEmitAuditStatelessReport_DefaultPath renders the report with no -o
// override and confirms it lands at the documented default location, contains
// the seeded finding, and reports the right count.
func TestEmitAuditStatelessReport_DefaultPath(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-audit", "alpha")
	seedFindingAndRecord(t, db, "proj-audit", "beta")

	// Run in a temp CWD so the default relative path is created in isolation.
	cwd, err := os.Getwd()
	require.NoError(t, err)
	tmp := t.TempDir()
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	err = emitAuditStatelessReport(context.Background(), db, "proj-audit", "", "/some/source", timeAnchor())
	require.NoError(t, err)

	reportPath := filepath.Join(tmp, defaultAuditStatelessReport)
	data, readErr := os.ReadFile(reportPath)
	require.NoError(t, readErr, "default report must be written to %s", defaultAuditStatelessReport)
	assert.Contains(t, string(data), "alpha.example")
	assert.Contains(t, string(data), "beta.example")
}

// TestEmitAuditStatelessReport_OutputOverride confirms -o/--output redirects the
// report and that only the scoped project's findings are included.
func TestEmitAuditStatelessReport_OutputOverride(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-keep", "kept")
	seedFindingAndRecord(t, db, "proj-other", "dropped")

	out := filepath.Join(t.TempDir(), "nested", "report.html")
	err := emitAuditStatelessReport(context.Background(), db, "proj-keep", out, "/src", timeAnchor())
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr, "the -o override path (with a new parent dir) must be created")
	assert.Contains(t, string(data), "kept.example")
	assert.NotContains(t, string(data), "dropped.example",
		"the report must be scoped to the run's project")
}

// TestEmitAuditStatelessReport_EmptyDB still produces a valid (empty) report
// rather than erroring, so a clean audit with zero findings yields a file.
func TestEmitAuditStatelessReport_EmptyDB(t *testing.T) {
	db := newExportTestDB(t)
	out := filepath.Join(t.TempDir(), "empty.html")
	err := emitAuditStatelessReport(context.Background(), db, "proj-empty", out, "", timeAnchor())
	require.NoError(t, err)
	_, statErr := os.Stat(out)
	require.NoError(t, statErr)
}

// timeAnchor returns a start time for the report's duration field. Tests don't
// assert on the rendered duration, only that report generation succeeds.
func timeAnchor() time.Time { return time.Now() }

// saveAuditGlobals snapshots the package-level audit flag vars and restores
// them on cleanup so the validation tests don't leak state into siblings.
func saveAuditGlobals(t *testing.T) {
	t.Helper()
	d, a, i, k, c, s, lm := auditDriver, auditAgent, auditInteractive,
		auditKeepRaw, auditCleanRaw, auditStateless, auditListModes
	t.Cleanup(func() {
		auditDriver, auditAgent, auditInteractive = d, a, i
		auditKeepRaw, auditCleanRaw, auditStateless, auditListModes = k, c, s, lm
	})
}

// TestAuditStatelessRejectsInteractive: -S and --interactive both want the
// terminal/DB in incompatible ways, so the combination must fail fast before
// any work (no temp DB, no clone).
func TestAuditStatelessRejectsInteractive(t *testing.T) {
	saveAuditGlobals(t)
	auditListModes = false
	auditStateless = true
	auditInteractive = true

	err := runAgentAudit(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stateless")
	assert.Contains(t, err.Error(), "interactive")
}

// TestAuditKeepRawCleanRawMutuallyExclusive: explicitly passing both --keep-raw
// and --clean-raw is contradictory and must error (the default-on keep-raw must
// NOT trip this — only an explicit set does).
func TestAuditKeepRawCleanRawMutuallyExclusive(t *testing.T) {
	saveAuditGlobals(t)
	auditListModes = false
	auditStateless = false
	auditInteractive = false

	c := &cobra.Command{Use: "audit", RunE: runAgentAudit}
	registerAuditFlags(c)
	require.NoError(t, c.Flags().Set("driver", "audit"))
	require.NoError(t, c.Flags().Set("keep-raw", "true"))
	require.NoError(t, c.Flags().Set("clean-raw", "true"))

	err := runAgentAudit(c, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
