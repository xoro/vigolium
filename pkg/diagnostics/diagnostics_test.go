package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

func TestResolveAlias(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"chrome", "chromium"},
		{"nuclei", "nuclei-templates"},
		{"CHROME", "chromium"},            // case-insensitive
		{"  nuclei ", "nuclei-templates"}, // trimmed
		{"chromium", "chromium"},          // already canonical
		{"unknown", "unknown"},            // pass-through
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := resolveAlias(tt.in); got != tt.want {
				t.Errorf("resolveAlias(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestToolFailing(t *testing.T) {
	r := &Report{Tools: map[string]*ToolCheck{
		"ok":   {Status: StatusOK},
		"warn": {Status: StatusWarning},
		"err":  {Status: StatusError},
	}}
	if toolFailing(r, "missing") {
		t.Error("missing tool should not be reported as failing")
	}
	if toolFailing(r, "ok") {
		t.Error("StatusOK tool should not be failing")
	}
	if !toolFailing(r, "warn") {
		t.Error("StatusWarning tool should be failing")
	}
	if !toolFailing(r, "err") {
		t.Error("StatusError tool should be failing")
	}
}

func TestRoundedAge(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"just now", 30 * time.Second, "just now"},
		{"minutes", 5 * time.Minute, "5m ago"},
		{"hours", 3 * time.Hour, "3h ago"},
		{"days", 50 * time.Hour, "2d ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundedAge(tt.d); got != tt.want {
				t.Errorf("roundedAge(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestComputeOverallStatus(t *testing.T) {
	t.Run("nil database is not_ready", func(t *testing.T) {
		if got := computeOverallStatus(&Report{}); got != "not_ready" {
			t.Errorf("got %q, want not_ready", got)
		}
	})
	t.Run("database error is not_ready", func(t *testing.T) {
		r := &Report{Database: &CheckResult{Status: StatusError}}
		if got := computeOverallStatus(r); got != "not_ready" {
			t.Errorf("got %q, want not_ready", got)
		}
	})
	t.Run("healthy is ready", func(t *testing.T) {
		r := &Report{Database: &CheckResult{Status: StatusOK}}
		if got := computeOverallStatus(r); got != "ready" {
			t.Errorf("got %q, want ready", got)
		}
	})
	t.Run("failing native dep degrades", func(t *testing.T) {
		r := &Report{
			Database:        &CheckResult{Status: StatusOK},
			NucleiTemplates: &CheckResult{Status: StatusError},
		}
		if got := computeOverallStatus(r); got != "degraded" {
			t.Errorf("got %q, want degraded", got)
		}
	})
	t.Run("failing embedded jsscan degrades", func(t *testing.T) {
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			EmbeddedBinaries: map[string]*CheckResult{
				"jsscan": {Status: StatusError},
			},
		}
		if got := computeOverallStatus(r); got != "degraded" {
			t.Errorf("got %q, want degraded", got)
		}
	})
	t.Run("failing embedded audit does not degrade", func(t *testing.T) {
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			EmbeddedBinaries: map[string]*CheckResult{
				"vigolium-audit": {Status: StatusError},
			},
		}
		if got := computeOverallStatus(r); got != "ready" {
			t.Errorf("got %q, want ready", got)
		}
	})
	t.Run("browser warning does not degrade", func(t *testing.T) {
		// A disabled browser (warning) is a user choice, not a failure.
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			Browser:  &CheckResult{Status: StatusWarning},
		}
		if got := computeOverallStatus(r); got != "ready" {
			t.Errorf("got %q, want ready (browser warning is not a failure)", got)
		}
	})
}

func TestAuditPathA(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		r := &Report{
			Tools: map[string]*ToolCheck{"claude": {Status: StatusOK}},
			Audit: &CheckResult{Status: StatusOK},
		}
		got := AuditPathA(r)
		if !got.OK || len(got.Reasons) != 0 {
			t.Errorf("expected OK with no reasons, got %+v", got)
		}
	})
	t.Run("missing claude and disabled audit", func(t *testing.T) {
		got := AuditPathA(&Report{Tools: map[string]*ToolCheck{}})
		if got.OK {
			t.Error("expected not OK")
		}
		if len(got.Reasons) != 2 {
			t.Errorf("expected 2 reasons (claude + audit), got %v", got.Reasons)
		}
	})
}

func TestAuditPathB(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		r := &Report{
			Tools:   map[string]*ToolCheck{"pi": {Status: StatusOK}},
			Piolium: &CheckResult{Status: StatusOK},
		}
		got := AuditPathB(r)
		if !got.OK || len(got.Reasons) != 0 {
			t.Errorf("expected OK with no reasons, got %+v", got)
		}
	})
	t.Run("missing pi and piolium", func(t *testing.T) {
		got := AuditPathB(&Report{Tools: map[string]*ToolCheck{}})
		if got.OK || len(got.Reasons) != 2 {
			t.Errorf("expected not OK with 2 reasons, got %+v", got)
		}
	})
}

func TestHasFixableIssues(t *testing.T) {
	if HasFixableIssues(nil) {
		t.Error("nil report should have no fixable issues")
	}
	// A failing nuclei-templates check is fixable regardless of claude/npm.
	r := &Report{NucleiTemplates: &CheckResult{Status: StatusError}}
	if !HasFixableIssues(r) {
		t.Error("failing nuclei-templates should be fixable")
	}
}

// TestCheckAgentCopilotCLI is a regression test for a bug where
// agent.olium.provider: copilot-cli was accepted by the runtime
// (pkg/olium/runner.go) but rejected by `vigolium doctor` as an "unknown
// olium provider" because this switch had never been updated with a
// matching case.
func TestCheckAgentCopilotCLI(t *testing.T) {
	settings := &config.Settings{Agent: *config.DefaultAgentConfig()}
	settings.Agent.Olium.Provider = "copilot-cli"

	t.Run("copilot binary not found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		got := checkAgent(settings)
		if got.Status != StatusError {
			t.Fatalf("expected StatusError, got %v (message=%q)", got.Status, got.Message)
		}
		if got.Protocol != "copilot-cli" {
			t.Errorf("expected protocol %q, got %q", "copilot-cli", got.Protocol)
		}
	})

	t.Run("copilot binary found", func(t *testing.T) {
		dir := t.TempDir()
		copilotPath := filepath.Join(dir, "copilot")
		if err := os.WriteFile(copilotPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)

		got := checkAgent(settings)
		if got.Status != StatusOK {
			t.Fatalf("expected StatusOK, got %v (message=%q)", got.Status, got.Message)
		}
		if got.Binary != copilotPath {
			t.Errorf("expected binary %q, got %q", copilotPath, got.Binary)
		}
	})
}
