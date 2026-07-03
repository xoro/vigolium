package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// Copilot drives the user's official GitHub Copilot CLI (`copilot -p
// --output-format json`) as an LLM provider. It unlocks a Copilot Business /
// Pro / Enterprise seat without requiring a separate API key, mirroring the
// anthropic-cli (Claude Code) provider's shell-out design.
//
// Important design note: like Claude Code, Copilot CLI has its OWN tool set
// (bash, file edit, the builtin github-mcp-server, etc.) and runs them
// internally. This provider does NOT surface those as engine-level tool
// calls -- if it did, the engine would try to re-execute them itself. Tool
// invocations are rendered inline as formatted text so the user still sees
// what the agent is doing.
type Copilot struct {
	binary string
	model  string
}

// NewCopilot constructs a Copilot CLI provider. `binary` is the absolute
// path to the `copilot` executable.
func NewCopilot(binary, model string) *Copilot {
	return &Copilot{binary: binary, model: model}
}

func (*Copilot) Name() string { return "copilot-cli" }

func (c *Copilot) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	prompt := renderCLIPrompt(req)

	// --allow-all-tools is required for non-interactive mode (per `copilot
	// --help`): without it, every tool call blocks on an interactive
	// permission prompt that can never be answered from a pipe.
	args := []string{
		"-p", prompt,
		"--output-format", "json",
		"--allow-all-tools",
		"--no-color",
	}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	cmd := exec.CommandContext(ctx, c.binary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // let copilot manage its own errors; the `result` event carries exitCode

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("copilot-cli: start: %w", err)
	}

	out := make(chan stream.Event, 32)
	go c.consume(ctx, cmd, stdout, out)
	return out, nil
}

// consume parses Copilot CLI's `--output-format json` event stream (one JSON
// object per line) and translates the subset olium's engine needs into
// stream.Event values. Session/MCP bookkeeping events are ignored; tool
// execution is rendered as inline text (see the Copilot type doc comment).
func (c *Copilot) consume(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, out chan<- stream.Event) {
	defer close(out)
	defer func() { _ = stdout.Close() }()

	scanner := bufio.NewScanner(stdout)
	// Copilot CLI can emit large lines (e.g. tool results with file dumps).
	scanner.Buffer(make([]byte, 0, 256*1024), 64*1024*1024)

	var usage stream.Usage

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		default:
		}

		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		t, _ := ev["type"].(string)
		data, _ := ev["data"].(map[string]any)

		switch t {
		case "assistant.message_delta":
			if delta, _ := data["deltaContent"].(string); delta != "" {
				out <- stream.Event{Type: stream.EventTextDelta, Delta: delta}
			}

		case "assistant.reasoning_delta":
			if delta, _ := data["deltaContent"].(string); delta != "" {
				out <- stream.Event{Type: stream.EventThinkingDelta, Delta: delta}
			}

		case "tool.execution_start":
			name, _ := data["toolName"].(string)
			argsJSON, _ := json.Marshal(data["arguments"])
			formatted := fmt.Sprintf("\n\n🔧 %s %s\n", name, truncateInline(string(argsJSON), 200))
			out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}

		case "tool.execution_complete":
			resultText := ""
			if result, ok := data["result"].(map[string]any); ok {
				resultText, _ = result["content"].(string)
			}
			formatted := fmt.Sprintf("   ↳ %s\n", truncateInline(resultText, 400))
			out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}

		case "result":
			// Copilot CLI reports usage as either `aiCredits` (current
			// token-based billing, effective 2026-06-01) or
			// `premiumRequests` (legacy request-based billing), depending
			// on the account's billing platform -- never raw input/output
			// token counts like Claude/Codex report. Usage.Input/Output
			// stay zero; the credit/request figure is carried in Cost
			// purely for display, not as a dollar amount.
			if u, ok := ev["usage"].(map[string]any); ok {
				if credits, ok := u["aiCredits"].(float64); ok {
					usage.Cost = credits
				} else if premium, ok := u["premiumRequests"].(float64); ok {
					usage.Cost = premium
				}
			}
			stop := stream.StopReasonStop
			if exitCode, _ := ev["exitCode"].(float64); exitCode != 0 {
				stop = stream.StopReasonError
				out <- stream.Event{Type: stream.EventError, Err: fmt.Sprintf("copilot-cli: exited with code %v", exitCode)}
				_ = cmd.Wait()
				return
			}
			out <- stream.Event{Type: stream.EventDone, StopReason: stop, Usage: &usage}
		}
	}
	if err := scanner.Err(); err != nil {
		out <- stream.Event{Type: stream.EventError, Err: err.Error()}
	}
	_ = cmd.Wait()
}
