package sessionlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

var hex8 = regexp.MustCompile(`^[0-9a-f]{8}$`)

// readLines parses every JSONL line of the transcript into a generic map.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	var out []map[string]any
	for _, line := range splitNonEmptyLines(string(raw)) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func msgBody(t *testing.T, line map[string]any) map[string]any {
	t.Helper()
	body, ok := line["message"].(map[string]any)
	if !ok {
		t.Fatalf("line has no message body: %v", line)
	}
	return body
}

// TestRecorder_PiSchema feeds a realistic two-turn sequence (thinking + text +
// a tool call, then the tool result, then a final text turn) and asserts the
// transcript matches the Pi schema: header trio, role-typed messages, full
// tool arguments + untruncated result, and a linear parentId chain of 8-hex
// event ids.
func TestRecorder_PiSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.jsonl")
	rec, err := New(path, Meta{
		Provider:      "anthropic-api-key",
		Model:         "claude-opus-4-8",
		ThinkingLevel: "high",
		Cwd:           "/work/app",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec.UserPrompt("list the files")
	rec.Record(engine.Event{Type: engine.EventThinkingDelta, Delta: "I should "})
	rec.Record(engine.Event{Type: engine.EventThinkingDelta, Delta: "run ls."})
	rec.Record(engine.Event{Type: engine.EventTextDelta, Delta: "Running ls now."})
	rec.Record(engine.Event{
		Type:       engine.EventTurnDone,
		StopReason: stream.StopReasonToolUse,
		Usage:      &stream.Usage{Input: 100, Output: 20, TotalTokens: 120, Cost: 0.5},
		ToolCalls:  []stream.ToolCall{{ID: "call_1", Name: "bash", Arguments: map[string]any{"command": "ls -la"}}},
	})
	rec.Record(engine.Event{
		Type:       engine.EventToolExecEnd,
		ToolCallID: "call_1",
		ToolName:   "bash",
		ToolResult: "file1\nfile2\n",
		ToolIsErr:  false,
	})
	rec.Record(engine.Event{Type: engine.EventTextDelta, Delta: "Done — two files."})
	rec.Record(engine.Event{
		Type:       engine.EventTurnDone,
		StopReason: stream.StopReasonStop,
		Usage:      &stream.Usage{Input: 130, Output: 8, TotalTokens: 138, Cost: 0.1},
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 7 {
		t.Fatalf("want 7 transcript lines, got %d: %+v", len(lines), lines)
	}

	// 0: session header (no parentId, version 3).
	if lines[0]["type"] != "session" {
		t.Fatalf("line 0 type = %v, want session", lines[0]["type"])
	}
	if v, _ := lines[0]["version"].(float64); int(v) != sessionFormatVersion {
		t.Fatalf("session version = %v, want %d", lines[0]["version"], sessionFormatVersion)
	}
	if lines[0]["cwd"] != "/work/app" {
		t.Fatalf("session cwd = %v", lines[0]["cwd"])
	}
	if _, present := lines[0]["parentId"]; present {
		t.Fatalf("session line should not carry parentId")
	}

	// 1: model_change with explicit null parent.
	if lines[1]["type"] != "model_change" {
		t.Fatalf("line 1 type = %v, want model_change", lines[1]["type"])
	}
	if lines[1]["provider"] != "anthropic-api-key" || lines[1]["modelId"] != "claude-opus-4-8" {
		t.Fatalf("model_change provider/model wrong: %+v", lines[1])
	}
	if pid, present := lines[1]["parentId"]; !present || pid != nil {
		t.Fatalf("model_change parentId = %v (present=%v), want explicit null", pid, present)
	}

	// 2: thinking_level_change.
	if lines[2]["type"] != "thinking_level_change" || lines[2]["thinkingLevel"] != "high" {
		t.Fatalf("line 2 thinking_level wrong: %+v", lines[2])
	}

	// 3: user message.
	if lines[3]["type"] != "message" {
		t.Fatalf("line 3 not a message: %+v", lines[3])
	}
	user := msgBody(t, lines[3])
	if user["role"] != "user" {
		t.Fatalf("line 3 role = %v, want user", user["role"])
	}
	if got := firstPartText(t, user); got != "list the files" {
		t.Fatalf("user text = %q", got)
	}

	// 4: assistant message — thinking + text + toolCall, usage, stopReason.
	asst := msgBody(t, lines[4])
	if asst["role"] != "assistant" {
		t.Fatalf("line 4 role = %v, want assistant", asst["role"])
	}
	if asst["stopReason"] != "toolUse" {
		t.Fatalf("assistant stopReason = %v, want toolUse", asst["stopReason"])
	}
	parts, _ := asst["content"].([]any)
	if len(parts) != 3 {
		t.Fatalf("assistant should have 3 content parts (thinking,text,toolCall), got %d: %+v", len(parts), parts)
	}
	thinking := parts[0].(map[string]any)
	if thinking["type"] != "thinking" || thinking["thinking"] != "I should run ls." {
		t.Fatalf("thinking part wrong (deltas should coalesce): %+v", thinking)
	}
	textPart := parts[1].(map[string]any)
	if textPart["type"] != "text" || textPart["text"] != "Running ls now." {
		t.Fatalf("text part wrong: %+v", textPart)
	}
	tc := parts[2].(map[string]any)
	if tc["type"] != "toolCall" || tc["id"] != "call_1" || tc["name"] != "bash" {
		t.Fatalf("toolCall part wrong: %+v", tc)
	}
	args, _ := tc["arguments"].(map[string]any)
	if args["command"] != "ls -la" {
		t.Fatalf("toolCall arguments not preserved: %+v", args)
	}
	usage, _ := asst["usage"].(map[string]any)
	if v, _ := usage["totalTokens"].(float64); int(v) != 120 {
		t.Fatalf("usage.totalTokens = %v, want 120", usage["totalTokens"])
	}
	cost, _ := usage["cost"].(map[string]any)
	if v, _ := cost["total"].(float64); v != 0.5 {
		t.Fatalf("usage.cost.total = %v, want 0.5", cost["total"])
	}

	// 5: toolResult message — full untruncated result, isError false.
	tr := msgBody(t, lines[5])
	if tr["role"] != "toolResult" || tr["toolCallId"] != "call_1" || tr["toolName"] != "bash" {
		t.Fatalf("toolResult envelope wrong: %+v", tr)
	}
	if tr["isError"] != false {
		t.Fatalf("toolResult isError = %v, want false", tr["isError"])
	}
	if got := firstPartText(t, tr); got != "file1\nfile2\n" {
		t.Fatalf("toolResult content = %q, want full untruncated result", got)
	}

	// 6: final assistant text-only turn.
	final := msgBody(t, lines[6])
	if final["role"] != "assistant" || final["stopReason"] != "stop" {
		t.Fatalf("final assistant wrong: %+v", final)
	}
	if got := firstPartText(t, final); got != "Done — two files." {
		t.Fatalf("final assistant text = %q", got)
	}

	// Every event id is 8 hex chars, and parentIds form one linear chain
	// from model_change onward (session is excluded — it carries no parentId).
	assertLinearChain(t, lines)
}

func firstPartText(t *testing.T, body map[string]any) string {
	t.Helper()
	parts, ok := body["content"].([]any)
	if !ok || len(parts) == 0 {
		t.Fatalf("body has no content parts: %+v", body)
	}
	p := parts[0].(map[string]any)
	s, _ := p["text"].(string)
	return s
}

func assertLinearChain(t *testing.T, lines []map[string]any) {
	t.Helper()
	var prevID string
	for i, ln := range lines {
		id, _ := ln["id"].(string)
		if ln["type"] == "session" {
			// UUID id, no parent link; don't fold into the hex/chain checks.
			prevID = "" // chain starts null at the next node
			continue
		}
		if !hex8.MatchString(id) {
			t.Fatalf("line %d id %q is not 8 hex chars", i, id)
		}
		pidRaw, present := ln["parentId"]
		if !present {
			t.Fatalf("line %d (%v) missing parentId", i, ln["type"])
		}
		if prevID == "" {
			if pidRaw != nil {
				t.Fatalf("line %d parentId = %v, want null (chain head)", i, pidRaw)
			}
		} else {
			pid, _ := pidRaw.(string)
			if pid != prevID {
				t.Fatalf("line %d parentId = %q, want %q (broken chain)", i, pid, prevID)
			}
		}
		prevID = id
	}
}

// TestRecorder_EmptyTurnWritesNothing ensures a nudged empty turn (turn_done
// with no thinking, text, or tool calls) does not emit a hollow assistant
// message.
func TestRecorder_EmptyTurnWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.jsonl")
	rec, err := New(path, Meta{Provider: "p", Model: "m"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec.UserPrompt("hi")
	rec.Record(engine.Event{Type: engine.EventTurnDone, StopReason: stream.StopReasonStop})
	_ = rec.Close()

	lines := readLines(t, path)
	// header(3) + user(1) = 4; the empty turn adds nothing.
	if len(lines) != 4 {
		t.Fatalf("empty turn should write nothing; got %d lines: %+v", len(lines), lines)
	}
	for _, ln := range lines {
		if body, ok := ln["message"].(map[string]any); ok && body["role"] == "assistant" {
			t.Fatalf("unexpected assistant message for empty turn: %+v", ln)
		}
	}
}

// TestRecorder_ToolErrorFidelity checks an errored tool result is recorded
// with isError true and its full content.
func TestRecorder_ToolErrorFidelity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.jsonl")
	rec, _ := New(path, Meta{Provider: "p", Model: "m"})
	rec.UserPrompt("go")
	rec.Record(engine.Event{
		Type: engine.EventTurnDone, StopReason: stream.StopReasonToolUse,
		ToolCalls: []stream.ToolCall{{ID: "c1", Name: "missing", Arguments: map[string]any{}}},
	})
	rec.Record(engine.Event{
		Type: engine.EventToolExecEnd, ToolCallID: "c1", ToolName: "missing",
		ToolResult: "error: tool \"missing\" is not available", ToolIsErr: true,
	})
	_ = rec.Close()

	lines := readLines(t, path)
	last := lines[len(lines)-1]
	body := msgBody(t, last)
	if body["role"] != "toolResult" || body["isError"] != true {
		t.Fatalf("want errored toolResult, got %+v", body)
	}
}

// TestRecorder_EmptyPathErrors confirms a recorder cannot be built without a
// destination, so callers must gate on a configured session dir.
func TestRecorder_EmptyPathErrors(t *testing.T) {
	if _, err := New("", Meta{}); err == nil {
		t.Fatal("New(\"\") should error")
	}
	if _, err := New("   ", Meta{}); err == nil {
		t.Fatal("New(blank) should error")
	}
}

// TestRecorder_CloseIdempotent verifies a double Close is safe.
func TestRecorder_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	rec, _ := New(filepath.Join(dir, "t.jsonl"), Meta{})
	if err := rec.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got: %v", err)
	}
}

// TestRecorder_GeneratesSessionID checks a session id is minted when none is
// supplied, and a supplied one is preserved.
func TestRecorder_GeneratesSessionID(t *testing.T) {
	dir := t.TempDir()
	rec, _ := New(filepath.Join(dir, "gen.jsonl"), Meta{})
	_ = rec.Close()
	lines := readLines(t, filepath.Join(dir, "gen.jsonl"))
	if id, _ := lines[0]["id"].(string); id == "" {
		t.Fatal("expected a generated session id")
	}

	rec2, _ := New(filepath.Join(dir, "pin.jsonl"), Meta{SessionID: "fixed-session"})
	_ = rec2.Close()
	lines2 := readLines(t, filepath.Join(dir, "pin.jsonl"))
	if lines2[0]["id"] != "fixed-session" {
		t.Fatalf("session id = %v, want fixed-session", lines2[0]["id"])
	}
}
