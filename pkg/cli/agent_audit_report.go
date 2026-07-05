package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// probeAgentModel runs a no-op prompt against the copilot CLI to determine
// the LLM model name from the session.tools_updated JSON event stream.
// The probe kills the subprocess immediately after the event fires — before
// any LLM round-trip occurs — so the probe typically completes in ~400ms.
// Returns "" when the model cannot be determined or the agent is not copilot.
func probeAgentModel(agentName string) string {
	if agentName != "copilot" {
		// Only copilot exposes a model via session.tools_updated today.
		// claude/codex can be added here when their JSON event schemas are known.
		return ""
	}
	bin, err := exec.LookPath("copilot")
	if err != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "--prompt", ".", "--output-format", "json", "--no-color", "--allow-all-tools")
	stdout, err := cmd.StdoutPipe() //nolint:gosec // bin is resolved by LookPath
	if err != nil {
		return ""
	}
	if err := cmd.Start(); err != nil {
		return ""
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	type toolsUpdatedEvent struct {
		Type string `json:"type"`
		Data struct {
			Model string `json:"model"`
		} `json:"data"`
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "session.tools_updated") {
			continue
		}
		var event toolsUpdatedEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Type == "session.tools_updated" && event.Data.Model != "" {
			return event.Data.Model
		}
	}
	return ""
}

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
func emitAuditStatelessReport(ctx context.Context, db *database.DB, projectUUID, outputArg, target, agentName, skills string, startedAt time.Time) error {
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
		label := terminal.ShortenHome(target)
		// Append short git SHA when the source is inside a git repo.
		if sha, err := gitShortSHA(target); err == nil && sha != "" {
			label += " (" + sha + ")"
		}
		meta.ScanTarget = label
	}
	if agentName != "" {
		meta.AgentName = agentName
	}
	meta.Skills = skills // may be empty; frontend renders "n/a" when empty
	if d := time.Since(startedAt).Round(time.Second); d > 0 {
		meta.ScanDuration = d.String()
	}

	// Query total token usage from all AgenticScan rows for this run.
	// The throwaway temp DB holds only this run's data, so summing by
	// project_uuid gives the scan-wide total. Errors are silently ignored;
	// the report is still generated without token data.
	type tokenSums struct {
		TotalInput  int64   `bun:"total_input"`
		TotalOutput int64   `bun:"total_output"`
		TotalCost   float64 `bun:"total_cost"`
	}
	var sums tokenSums
	if scanErr := db.NewSelect().
		TableExpr("agentic_scans").
		ColumnExpr("COALESCE(SUM(total_input_tokens), 0) AS total_input, COALESCE(SUM(total_output_tokens), 0) AS total_output, COALESCE(SUM(estimated_cost_usd), 0) AS total_cost").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &sums); scanErr == nil {
		meta.InputTokens = sums.TotalInput
		meta.OutputTokens = sums.TotalOutput
		meta.CostUSD = sums.TotalCost
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

// agentNameWithModel returns the agent name combined with the probed LLM model
// name (e.g. "copilot/claude-sonnet-5"). Falls back to agentName alone when the
// model probe fails or the agent is not supported.
func agentNameWithModel(agentName string) string {
	if agentName == "" {
		return ""
	}
	model := probeAgentModel(agentName)
	if model == "" {
		return agentName
	}
	return agentName + "/" + model
}

// gitShortSHA returns the 7-character short commit SHA of the HEAD commit for
// the git repository that contains dir. Returns ("", err) when dir is not
// inside a git repo or git is unavailable — callers should treat this as an
// optional enrichment and ignore the error.
func gitShortSHA(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
