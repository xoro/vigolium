package sessionlog_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// scriptedProvider drives one tool-using turn then a final text turn, so the
// engine produces the full event vocabulary a transcript must capture.
type scriptedProvider struct{}

func (scriptedProvider) Name() string { return "scripted" }

func (scriptedProvider) Stream(_ context.Context, req provider.Request) (<-chan stream.Event, error) {
	ch := make(chan stream.Event, 8)
	toolDone := false
	for _, m := range req.Messages {
		if m.Role == provider.RoleTool {
			toolDone = true
		}
	}
	go func() {
		defer close(ch)
		if !toolDone {
			ch <- stream.Event{Type: stream.EventThinkingDelta, Delta: "planning"}
			ch <- stream.Event{Type: stream.EventTextDelta, Delta: "running tool"}
			ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "c1", Name: "noop"}}
			ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "c1", Name: "noop", Arguments: map[string]any{"k": "v"}}}
			ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse, Usage: &stream.Usage{Input: 5, Output: 3}}
			return
		}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "finished"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{Input: 7, Output: 1}}
	}()
	return ch, nil
}

// TestEngineToTranscript wires a real engine to a real sessionlog.Recorder via
// engine.Config.Recorder (exactly how autopilot/TUI/headless do it) and
// asserts the on-disk transcript captures the user prompt, the tool-using
// assistant turn, the toolResult, and the final assistant turn.
func TestEngineToTranscript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.jsonl")
	rec, err := sessionlog.New(path, sessionlog.Meta{Provider: "scripted", Model: "m", Cwd: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	eng := engine.New(engine.Config{
		Provider: scriptedProvider{},
		Tools:    tool.NewRegistry(),
		Model:    "m",
		Recorder: rec,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range eng.Run(ctx, "please run the tool") { //nolint:revive // draining
	}
	if err := eng.CloseRecorder(); err != nil {
		t.Fatalf("CloseRecorder: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	roles := map[string]int{}
	types := map[string]int{}
	var sawToolArgs, sawToolResult bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad jsonl line %q: %v", line, err)
		}
		types[m["type"].(string)]++
		if body, ok := m["message"].(map[string]any); ok {
			role, _ := body["role"].(string)
			roles[role]++
			if role == "assistant" {
				if parts, ok := body["content"].([]any); ok {
					for _, p := range parts {
						pm, _ := p.(map[string]any)
						if pm["type"] == "toolCall" {
							if args, _ := pm["arguments"].(map[string]any); args["k"] == "v" {
								sawToolArgs = true
							}
						}
					}
				}
			}
			if role == "toolResult" {
				sawToolResult = true
			}
		}
	}

	if types["session"] != 1 || types["model_change"] != 1 || types["thinking_level_change"] != 1 {
		t.Fatalf("missing header trio: %+v", types)
	}
	if roles["user"] != 1 {
		t.Fatalf("want 1 user message, got %d", roles["user"])
	}
	if roles["assistant"] != 2 {
		t.Fatalf("want 2 assistant messages (tool turn + final), got %d", roles["assistant"])
	}
	if !sawToolArgs {
		t.Fatal("assistant tool call did not carry arguments end-to-end")
	}
	if !sawToolResult {
		t.Fatal("transcript missing toolResult message")
	}
}
