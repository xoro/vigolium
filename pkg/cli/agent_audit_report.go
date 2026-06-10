package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// defaultAuditStatelessReport is the report destination used by `vigolium
// (agent) audit -S` when no -o/--output override is given. Relative to the
// current working directory; the parent dir is created if missing.
const defaultAuditStatelessReport = "vigolium-result/vigolium-audit-report.html"

// emitAuditStatelessReport renders the self-contained HTML report for a
// --stateless audit run. The audit drivers already imported the on-disk
// vigolium-results folder(s) into the throwaway temp DB, so this queries that
// DB (scoped to the run's project) and feeds the findings through the exact
// generator behind `vigolium import --format html` (reportGenerator), keeping
// the output identical to the manual two-step import.
//
// outputArg overrides the destination (-o/--output); empty falls back to
// defaultAuditStatelessReport. The path supports gs:// upload and {ts}
// placeholders via resolveExportOutput, mirroring `vigolium export`.
func emitAuditStatelessReport(ctx context.Context, db *database.DB, projectUUID, outputArg, target string, startedAt time.Time) error {
	outputArg = strings.TrimSpace(outputArg)
	if outputArg == "" {
		outputArg = defaultAuditStatelessReport
	}

	gen, defaultTitle, ok := reportGenerator("html")
	if !ok {
		return fmt.Errorf("html report generator unavailable")
	}

	localOutput, finalize, err := resolveExportOutput(ctx, outputArg)
	if err != nil {
		return err
	}
	// Ensure the parent directory exists for a local destination (e.g. the
	// default vigolium-result/). resolveExportOutput returns a temp path for
	// gs:// URLs, which already exists, so only create dirs for real paths.
	if !storage.IsGCSURI(outputArg) {
		if dir := filepath.Dir(localOutput); dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return fmt.Errorf("create report directory %s: %w", dir, mkErr)
			}
		}
	}

	// The throwaway temp DB holds only this run's data, so a project-scoped
	// query returns exactly the audit's findings.
	var findings []*database.Finding
	q := scopeProjectBun(db.NewSelect().Model(&findings).OrderExpr("found_at DESC"), projectUUID)
	if err := q.Scan(ctx); err != nil {
		return fmt.Errorf("query findings for report: %w", err)
	}

	items := make([]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, exportEnvelope{Type: "finding", Data: f})
	}

	meta := output.HTMLReportMeta{
		Title:   defaultTitle,
		Version: getVersion(),
	}
	if target != "" {
		meta.ScanTarget = terminal.ShortenHome(target)
	}
	if d := time.Since(startedAt).Round(time.Second); d > 0 {
		meta.ScanDuration = d.String()
	}

	if !globalJSON {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
			terminal.BoldCyan(fmt.Sprintf("Generating HTML report — %d findings ...", len(findings))))
	}
	if err := gen(items, localOutput, meta); err != nil {
		return err
	}
	if err := finalize(); err != nil {
		return err
	}

	fmt.Printf("%s Report written: %s (%d findings)\n",
		terminal.SuccessSymbol(), terminal.Cyan(outputArg), len(findings))
	return nil
}
