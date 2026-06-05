package olium

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
)

// HeadlessOptions configures a non-interactive single-prompt run.
type HeadlessOptions struct {
	Options
	Prompt  string    // required
	Out     io.Writer // default os.Stdout
	Verbose bool      // enable per-tool result preview in the tool log
}

// RunHeadless executes a single prompt through the Engine and streams
// text deltas + a terse tool-card log to Out. Used for smoke tests and
// scripting.
func RunHeadless(ctx context.Context, opts HeadlessOptions) error {
	if opts.Prompt == "" {
		return fmt.Errorf("olium: prompt is required in headless mode")
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}

	eng, provName, model, err := buildHeadlessEngine(opts.Options)
	if err != nil {
		return err
	}
	// Flush + close the JSONL transcript when the one-shot run ends. No-op
	// when opts.SessionDir was empty (no recorder attached).
	defer func() { _ = eng.CloseRecorder() }()

	// Under -v/--verbose (or --debug), print which provider+model is actually
	// resolved before any output streams. Answers "what model are you running"
	// deterministically — independent of whether the model itself answers it
	// correctly — and orients the request/SSE dumps that --debug emits below.
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[olium] provider=%s model=%s\n", provName, model)
	}

	ch := eng.Run(ctx, opts.Prompt)
	// Tool lifecycle on stderr; per-turn usage line on opts.Out so it
	// follows the assistant text deterministically (independent buffering
	// of stdout/stderr otherwise reorders them).
	tlog := toollog.NewWithStreams(os.Stderr, opts.Out, opts.Verbose)
	thinking := false
	for ev := range ch {
		// Tool exec + turn-done formatting goes through the shared
		// logger so headless, autopilot, and the swarm adapter look
		// the same to operators.
		if tlog.Handle(ev) {
			continue
		}
		switch ev.Type {
		case engine.EventTextDelta:
			if thinking {
				fmt.Fprintln(os.Stderr) // close the thinking block
				thinking = false
			}
			if _, werr := io.WriteString(opts.Out, ev.Delta); werr != nil {
				return werr
			}

		case engine.EventThinkingDelta:
			if !thinking {
				fmt.Fprint(os.Stderr, "\n[thinking]\n")
				thinking = true
			}
			fmt.Fprint(os.Stderr, ev.Delta)
		case engine.EventRunDone:
			_, _ = io.WriteString(opts.Out, "\n")
		case engine.EventError:
			return fmt.Errorf("olium: %s", ev.Err)
		}
	}
	return nil
}
