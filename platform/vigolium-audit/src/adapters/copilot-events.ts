import type { AdapterEvent } from "./adapter.js";

/**
 * Mutable accumulator threaded through every normalizeCopilotEvent() call for
 * one `run()` invocation. Needed only to detect the "refused with plain text
 * but exited 0" case at the terminal `result` event -- see REFUSAL_PATTERN.
 */
export interface CopilotNormalizeState {
  assistantText: string;
  toolCallCount: number;
  outputTokens: number; // summed from assistant.message.outputTokens
}

export function createCopilotNormalizeState(): CopilotNormalizeState {
  return { assistantText: "", toolCallCount: 0, outputTokens: 0 };
}

/**
 * Matches Copilot's plain-text refusal openings ("I'm sorry, but I cannot
 * assist with that request.", "Sorry, I can't help with that.", etc.).
 * Confirmed empirically: refusals exit 0 like any other successful turn, so
 * exit-code alone can't distinguish "refused" from "actually done" -- see
 * isLikelyRefusal() below for the full heuristic (also requires zero tool
 * calls and a short response, to avoid false-positiving on legitimate audit
 * prose that happens to contain an apologetic phrase).
 */
const REFUSAL_PATTERN =
  /\b(i'?m\s+sorry,?\s+(but\s+)?)?i\s+(cannot|can'?t|won'?t|am\s+unable\s+to|am\s+not\s+able\s+to)\s+(assist|help)\b/i;

function isLikelyRefusal(state: CopilotNormalizeState): string | null {
  if (state.toolCallCount > 0) return null;
  const trimmed = state.assistantText.trim();
  if (trimmed.length === 0 || trimmed.length > 300) return null;
  return REFUSAL_PATTERN.test(trimmed.slice(0, 120)) ? trimmed : null;
}

/**
 * Normalize one JSON object from the official GitHub Copilot CLI's
 * `copilot -p ... --output-format json` NDJSON stream into zero or more
 * AdapterEvents.
 *
 * Copilot's event shape (confirmed empirically against CLI v1.0.68 -- there
 * is no public wire-format spec to cite):
 *   session.*                    -- MCP/skill/tool init bookkeeping (ignored)
 *   user.message                 -- echo of the prompt we sent (ignored)
 *   assistant.turn_start/turn_end/idle -- turn bookkeeping (ignored)
 *   assistant.reasoning_delta    -- incremental thinking text  -> "thinking"
 *   assistant.reasoning          -- full thinking block (redundant with the
 *                                   deltas above; ignored to avoid duplicates)
 *   assistant.message_start      -- message begins (ignored)
 *   assistant.message_delta      -- incremental reply text     -> "textDelta"
 *   assistant.message            -- full final message: text is redundant with
 *                                   the deltas above and is skipped, but
 *                                   outputTokens is accumulated into state
 *   tool.execution_start         -- a tool call begins          -> "toolCall"
 *   tool.execution_partial_result -- streaming partial tool output (ignored;
 *                                   vigolium-audit's orchestrator only needs
 *                                   the final result, not intermediate ticks)
 *   tool.execution_complete      -- a tool call finished        -> "toolResult"
 *   result                       -- terminal event, one per run -> "finish"
 *
 * Copilot never reports raw input/output token counts or a USD cost in this
 * JSON stream -- only `premiumRequests` (legacy request-based billing) or
 * `aiCredits` (current token-based billing, effective 2026-06-01), depending
 * on the account's billing platform. Neither maps to `tokens`/`usd` cleanly,
 * so both stay 0 on the `finish` event; this mirrors Codex's "usd not
 * reported" comment in codex-events.ts.
 */
export function* normalizeCopilotEvent(
  event: unknown,
  startedAt: number,
  state: CopilotNormalizeState,
): Iterable<AdapterEvent> {
  if (!event || typeof event !== "object") return;
  const e = event as Record<string, unknown>;
  const type = typeof e.type === "string" ? e.type : "";
  const data = (e.data && typeof e.data === "object" ? e.data : {}) as Record<string, unknown>;

  switch (type) {
    case "assistant.message": {
      // Text content is already captured via message_delta; only collect
      // outputTokens which is not present on the delta events.
      const n = typeof data.outputTokens === "number" ? data.outputTokens : 0;
      if (n > 0) state.outputTokens += n;
      return;
    }
    case "assistant.message_delta": {
      const text = typeof data.deltaContent === "string" ? data.deltaContent : "";
      if (text) {
        state.assistantText += text;
        yield { kind: "textDelta", text };
      }
      return;
    }
    case "assistant.reasoning_delta": {
      const text = typeof data.deltaContent === "string" ? data.deltaContent : "";
      if (text) yield { kind: "thinking", text };
      return;
    }
    case "tool.execution_start": {
      const id = typeof data.toolCallId === "string" ? data.toolCallId : "";
      const tool = typeof data.toolName === "string" ? data.toolName : "unknown";
      if (id) {
        state.toolCallCount++;
        yield { kind: "toolCall", id, tool, input: data.arguments ?? {} };
      }
      return;
    }
    case "tool.execution_complete": {
      const id = typeof data.toolCallId === "string" ? data.toolCallId : "";
      if (!id) return;
      const success = data.success !== false;
      const result = (data.result && typeof data.result === "object" ? data.result : {}) as Record<string, unknown>;
      const output = "content" in result ? result.content : result;
      yield { kind: "toolResult", id, output, isError: !success };
      return;
    }
    case "result": {
      const exitCode = typeof e.exitCode === "number" ? e.exitCode : 0;
      const usage = (e.usage && typeof e.usage === "object" ? e.usage : {}) as Record<string, unknown>;
      // Neither field is a real token count -- see the doc comment above.
      // We surface whichever the account's billing platform reports as the
      // `usd` field so it's at least visible somewhere, clearly not USD.
      const credits =
        typeof usage.aiCredits === "number"
          ? usage.aiCredits
          : typeof usage.premiumRequests === "number"
            ? usage.premiumRequests
            : 0;
      // Copilot exits 0 even when it flatly refuses the request in plain
      // text (no tool calls, just an apology) -- exit code alone can't tell
      // "refused" apart from "actually finished". Downgrade that case to a
      // non-ok finish so the orchestrator doesn't record a refusal as a
      // completed phase.
      const refusalText = exitCode === 0 ? isLikelyRefusal(state) : null;
      if (exitCode === 0 && refusalText === null) {
        yield {
          kind: "finish",
          ok: true,
          result: "",
          usd: credits,
          tokens: { input: 0, output: state.outputTokens },
          durationMs: Date.now() - startedAt,
        };
      } else {
        const reason =
          refusalText !== null
            ? `Copilot refused the request: "${refusalText.slice(0, 200)}"`
            : `copilot CLI exited ${exitCode}`;
        yield {
          kind: "finish",
          ok: false,
          reason,
          usd: credits,
          tokens: { input: 0, output: state.outputTokens },
          durationMs: Date.now() - startedAt,
        };
      }
      return;
    }
    default:
      return;
  }
}
