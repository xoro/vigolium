package toollog

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// disableColor flips terminal.colorEnabled off for the duration of a test
// so assertions can match plain ASCII without ANSI noise.
func disableColor(t *testing.T) {
	t.Helper()
	prev := terminal.IsColorEnabled()
	terminal.SetColorEnabled(false)
	t.Cleanup(func() { terminal.SetColorEnabled(prev) })
}

func TestLoggerStartAndEndSuccess(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)

	l.Handle(engine.Event{
		Type:       engine.EventToolExecStart,
		ToolCallID: "call-1",
		ToolName:   "ls",
		ToolArgs:   map[string]any{"path": "/tmp"},
	})
	l.Handle(engine.Event{
		Type:       engine.EventToolExecEnd,
		ToolCallID: "call-1",
		ToolName:   "ls",
		ToolResult: strings.Repeat("x", 1694),
	})

	out := buf.String()
	if !strings.Contains(out, "▶ ls path=/tmp") {
		t.Errorf("expected start line with arrow + tool + args, got: %q", out)
	}
	if !strings.Contains(out, "✓ 1694 bytes") {
		t.Errorf("expected success line with byte count, got: %q", out)
	}
}

func TestLoggerErrorIncludesReason(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)

	l.Handle(engine.Event{
		Type:       engine.EventToolExecStart,
		ToolCallID: "call-2",
		ToolName:   "web_fetch",
		ToolArgs:   map[string]any{"url": "http://x"},
	})
	l.Handle(engine.Event{
		Type:       engine.EventToolExecEnd,
		ToolCallID: "call-2",
		ToolName:   "web_fetch",
		ToolIsErr:  true,
		ToolResult: "connection refused\nstack trace ...",
	})

	out := buf.String()
	if !strings.Contains(out, "✗ failed: connection refused") {
		t.Errorf("expected failure line with first error line, got: %q", out)
	}
	if strings.Contains(out, "stack trace") {
		t.Errorf("error summary should clip after first line, got: %q", out)
	}
}

func TestLoggerNilWriterIsNoop(t *testing.T) {
	l := New(nil)
	// Should not panic and should report not-handled.
	if l.Handle(engine.Event{Type: engine.EventToolExecStart, ToolCallID: "x"}) {
		t.Error("nil-writer logger should report unhandled")
	}
}

func TestThinkingLaneFlushesCompactedBlock(t *testing.T) {
	disableColor(t)
	var tools, think bytes.Buffer
	l := NewWith(&tools, true).WithThinkingWriter(&think)

	// Reasoning deltas accumulate; nothing renders until a flush trigger.
	l.HandleThinking(engine.Event{Type: engine.EventThinkingDelta, Delta: "**Plan**\n\n\n\nProbe the login flow"})
	l.HandleThinking(engine.Event{Type: engine.EventThinkingDelta, Delta: " for IDOR.\n"})
	if think.Len() != 0 {
		t.Fatalf("thinking should not render before a flush trigger, got: %q", think.String())
	}

	// A tool-exec-start flushes the reasoning first (think → act ordering),
	// then writes the tool line.
	l.Handle(engine.Event{Type: engine.EventToolExecStart, ToolCallID: "c1", ToolName: "replay_request"})

	got := think.String()
	if !strings.Contains(got, "⋈ thinking") {
		t.Errorf("expected ⋈ thinking header on the thinking writer, got: %q", got)
	}
	if !strings.Contains(got, "**Plan**") || !strings.Contains(got, "Probe the login flow for IDOR.") {
		t.Errorf("expected compacted reasoning body, got: %q", got)
	}
	if strings.Contains(got, "\n\n\n") {
		t.Errorf("blank-line runs should be compacted away, got: %q", got)
	}
	// The reasoning went to the thinking writer, not the tool-line writer.
	if strings.Contains(tools.String(), "thinking") {
		t.Errorf("reasoning must not land on the tool-line writer, got: %q", tools.String())
	}
	if !strings.Contains(tools.String(), "replay_request") {
		t.Errorf("tool line should still render on the tool writer, got: %q", tools.String())
	}

	// Buffer was reset on flush — a second flush with no new deltas is a no-op.
	think.Reset()
	l.FlushThinking()
	if think.Len() != 0 {
		t.Errorf("second flush with empty buffer should write nothing, got: %q", think.String())
	}
}

func TestThinkingLaneGatedOnVerbose(t *testing.T) {
	disableColor(t)
	var think bytes.Buffer
	// verbose=false: reasoning is consumed but never rendered.
	l := NewWith(&bytes.Buffer{}, false).WithThinkingWriter(&think)
	if !l.HandleThinking(engine.Event{Type: engine.EventThinkingDelta, Delta: "secret reasoning"}) {
		t.Fatal("HandleThinking should report the thinking delta as consumed even when not verbose")
	}
	l.FlushThinking()
	if think.Len() != 0 {
		t.Errorf("non-verbose logger must not render reasoning, got: %q", think.String())
	}
}

func TestThinkingLaneRendersWhenToolWriterNil(t *testing.T) {
	disableColor(t)
	var think bytes.Buffer
	// w (tool-line writer) is nil — mirrors a query with streaming off — but
	// the reasoning lane is pinned to a real writer and must still render.
	l := NewWith(nil, true).WithThinkingWriter(&think)
	if !l.HandleThinking(engine.Event{Type: engine.EventThinkingDelta, Delta: "reasoning"}) {
		t.Fatal("thinking delta should be consumed even with a nil tool writer")
	}
	l.FlushThinking()
	if !strings.Contains(think.String(), "reasoning") {
		t.Errorf("reasoning should render to thinkW even when w is nil, got: %q", think.String())
	}
}

func TestHandleThinkingIgnoresNonThinkingEvents(t *testing.T) {
	l := NewWith(&bytes.Buffer{}, true)
	if l.HandleThinking(engine.Event{Type: engine.EventToolExecStart}) {
		t.Error("HandleThinking should not consume a non-thinking event")
	}
}

func TestFormatElapsed(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0ms"},
		{12 * time.Millisecond, "12ms"},
		{438 * time.Millisecond, "438ms"},
		{2500 * time.Millisecond, "2.5s"},
		{45 * time.Second, "45s"},
		{83 * time.Second, "1m23s"},
	}
	for _, c := range cases {
		if got := formatElapsed(c.in); got != c.want {
			t.Errorf("formatElapsed(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
