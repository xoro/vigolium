package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// scriptedTwoTurnProvider drives a deterministic two-turn run: the first turn
// emits text plus one tool call (stop reason toolUse); once a tool-result
// message is present in history, the second turn emits a final text and stops.
type scriptedTwoTurnProvider struct{}

func (scriptedTwoTurnProvider) Name() string { return "scripted" }

func (scriptedTwoTurnProvider) Stream(_ context.Context, req provider.Request) (<-chan stream.Event, error) {
	ch := make(chan stream.Event, 8)
	toolResultSeen := false
	for _, m := range req.Messages {
		if m.Role == provider.RoleTool {
			toolResultSeen = true
		}
	}
	go func() {
		defer close(ch)
		if !toolResultSeen {
			ch <- stream.Event{Type: stream.EventTextDelta, Delta: "calling a tool"}
			ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "call_x", Name: "echo"}}
			ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
				ID: "call_x", Name: "echo", Arguments: map[string]any{"v": "1"},
			}}
			ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse, Usage: &stream.Usage{Input: 10, Output: 5}}
			return
		}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "all done"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{Input: 12, Output: 2}}
	}()
	return ch, nil
}

// captureRecorder is a test EventRecorder that records the seeded prompt and
// every teed event.
type captureRecorder struct {
	mu      sync.Mutex
	prompts []string
	events  []Event
}

func (c *captureRecorder) UserPrompt(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prompts = append(c.prompts, p)
}

func (c *captureRecorder) Record(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

// TestEngine_RecorderTee asserts Engine.Run tees the initiating prompt and
// every event through a configured recorder, in order, and that EventTurnDone
// carries the turn's tool calls (with arguments) so a transcript can render a
// complete assistant message.
func TestEngine_RecorderTee(t *testing.T) {
	rec := &captureRecorder{}
	eng := New(Config{
		Provider: scriptedTwoTurnProvider{},
		Tools:    tool.NewRegistry(), // empty: the unknown "echo" tool still emits a tool_exec_end
		Model:    "test",
		Recorder: rec,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Drain the public channel — the tee forwards every event here too.
	var forwarded int
	for range eng.Run(ctx, "do the thing") {
		forwarded++
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if len(rec.prompts) != 1 || rec.prompts[0] != "do the thing" {
		t.Fatalf("recorder prompts = %v, want [\"do the thing\"]", rec.prompts)
	}
	if forwarded != len(rec.events) {
		t.Fatalf("forwarded %d events but recorder saw %d — tee dropped or duplicated", forwarded, len(rec.events))
	}

	// Find the first turn_done and assert it carries the tool call + args.
	var firstTurn *Event
	var sawToolExecEnd bool
	for i := range rec.events {
		ev := rec.events[i]
		if ev.Type == EventTurnDone && firstTurn == nil {
			firstTurn = &rec.events[i]
		}
		if ev.Type == EventToolExecEnd {
			sawToolExecEnd = true
		}
	}
	if firstTurn == nil {
		t.Fatal("recorder never saw a turn_done event")
	}
	if len(firstTurn.ToolCalls) != 1 {
		t.Fatalf("first turn_done ToolCalls = %d, want 1", len(firstTurn.ToolCalls))
	}
	tc := firstTurn.ToolCalls[0]
	if tc.ID != "call_x" || tc.Name != "echo" || tc.Arguments["v"] != "1" {
		t.Fatalf("turn_done tool call wrong: %+v", tc)
	}
	if !sawToolExecEnd {
		t.Fatal("recorder never saw a tool_exec_end event (toolResult source)")
	}
}

// TestEngine_NoRecorderNoPanic confirms the non-recording fast path still
// works when Config.Recorder is nil.
func TestEngine_NoRecorderNoPanic(t *testing.T) {
	eng := New(Config{Provider: scriptedTwoTurnProvider{}, Tools: tool.NewRegistry(), Model: "test"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	for range eng.Run(ctx, "go") {
		n++
	}
	if n == 0 {
		t.Fatal("expected events on the public channel")
	}
}

// TestEngine_ForkDropsRecorder verifies a fork does not inherit the parent's
// recorder (concurrent sub-runs must not share one transcript file).
func TestEngine_ForkDropsRecorder(t *testing.T) {
	rec := &captureRecorder{}
	parent := New(Config{Provider: scriptedTwoTurnProvider{}, Tools: tool.NewRegistry(), Model: "test", Recorder: rec})
	child := parent.Fork()
	if child.cfg.Recorder != nil {
		t.Fatal("fork inherited the parent recorder")
	}
}
