import { readFile } from "fs/promises";
import { join } from "path";
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
  /** sessionId from the result event — used to read events.jsonl after process exit. */
  sessionId: string | null;
  /** Pending finish payload built in the result event; emitted by buildCopilotFinish(). */
  pendingFinish: {
    ok: boolean;
    credits: number;
    reason?: string;
    startedAt: number;
  } | null;
}

export function createCopilotNormalizeState(): CopilotNormalizeState {
  return { assistantText: "", toolCallCount: 0, outputTokens: 0, sessionId: null, pendingFinish: null };
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
 * Copilot does not expose raw input/output token counts in this JSON stream
 * (only outputTokens per assistant.message, which we now collect — see the
 * assistant.message case below). Cost is reported as:
 *   aiCredits     — token-based billing (github.com, effective 2026-06-01);
 *                   1 AI credit = $0.01 USD.
 *   premiumRequests — legacy request-based billing (GHE / annual plans);
 *                   GitHub reference rate = $1/request.
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
      // aiCredits: token-based billing (github.com since 2026-06-01).
      //   1 AI credit = $0.01 USD — multiply to get real USD.
      // premiumRequests: legacy request-based billing (GHE and annual plans).
      //   GitHub's reference rate is $1/request; enterprise plans typically
      //   include these in the subscription so marginal cost may be $0.
      const credits =
        typeof usage.aiCredits === "number"
          ? usage.aiCredits * 0.01 // convert AI credits → USD
          : typeof usage.premiumRequests === "number"
            ? usage.premiumRequests // $1/request reference rate for legacy billing
            : 0;
      // Capture the session ID so buildCopilotFinish() can read events.jsonl
      // after the process exits to get the full token breakdown.
      const sid = typeof e.sessionId === "string" ? e.sessionId : null;
      state.sessionId = sid;
      // Copilot exits 0 even when it flatly refuses the request in plain
      // text (no tool calls, just an apology) -- exit code alone can't tell
      // "refused" apart from "actually finished". Downgrade that case to a
      // non-ok finish so the orchestrator doesn't record a refusal as a
      // completed phase.
      const refusalText = exitCode === 0 ? isLikelyRefusal(state) : null;
      if (exitCode === 0 && refusalText === null) {
        state.pendingFinish = { ok: true, credits, startedAt };
      } else {
        const reason =
          refusalText !== null
            ? `Copilot refused the request: "${refusalText.slice(0, 200)}"`
            : `copilot CLI exited ${exitCode}`;
        state.pendingFinish = { ok: false, credits, reason, startedAt };
      }
      // Do NOT yield finish here — buildCopilotFinish() will emit it after
      // reading events.jsonl for the full token breakdown.
      return;
    }
    default:
      return;
  }
}

/**
 * Build and return the finish AdapterEvent after the copilot process has
 * exited. Reads `~/.copilot/session-state/<sessionId>/events.jsonl` to
 * extract the full token breakdown (input, cacheRead, cacheWrite, output)
 * from the `session.shutdown` event written during normal copilot shutdown.
 *
 * Falls back to state.outputTokens (already accumulated from
 * assistant.message events) if events.jsonl is absent or unparseable.
 */
export async function buildCopilotFinish(
  state: CopilotNormalizeState,
): Promise<AdapterEvent | null> {
  if (!state.pendingFinish) return null;
  const { ok, credits, reason, startedAt } = state.pendingFinish;

  // Attempt to read the full token breakdown from events.jsonl.
  let inputTokens = 0;
  let cacheReadTokens: number | undefined;
  let cacheWriteTokens: number | undefined;
  let outputTokens = state.outputTokens; // fallback: already accumulated

  if (state.sessionId) {
    try {
      const copilotHome = process.env.COPILOT_HOME
        ?? join(process.env.HOME ?? process.env.USERPROFILE ?? "", ".copilot");
      const eventsPath = join(copilotHome, "session-state", state.sessionId, "events.jsonl");
      const raw = await readFile(eventsPath, "utf8");
      for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const ev = JSON.parse(trimmed) as Record<string, unknown>;
          if (ev.type !== "session.shutdown") continue;
          const d = (ev.data && typeof ev.data === "object" ? ev.data : {}) as Record<string, unknown>;
          // Prefer per-model metrics when available; fall back to tokenDetails.
          const mm = d.modelMetrics as Record<string, unknown> | undefined;
          if (mm) {
            // Sum across all models (usually just one per run).
            for (const model of Object.values(mm)) {
              const mu = (model as Record<string, unknown>).usage as Record<string, unknown> | undefined;
              if (!mu) continue;
              inputTokens      += (typeof mu.inputTokens      === "number" ? mu.inputTokens      : 0)
                                - (typeof mu.cacheReadTokens  === "number" ? mu.cacheReadTokens  : 0)
                                - (typeof mu.cacheWriteTokens === "number" ? mu.cacheWriteTokens : 0);
              cacheReadTokens   = (cacheReadTokens  ?? 0) + (typeof mu.cacheReadTokens  === "number" ? mu.cacheReadTokens  : 0);
              cacheWriteTokens  = (cacheWriteTokens ?? 0) + (typeof mu.cacheWriteTokens === "number" ? mu.cacheWriteTokens : 0);
              outputTokens      = (typeof mu.outputTokens     === "number" ? mu.outputTokens     : outputTokens);
            }
          } else {
            // tokenDetails fallback
            const td = d.tokenDetails as Record<string, Record<string, unknown>> | undefined;
            if (td) {
              inputTokens      = (td.input?.tokenCount      as number | undefined) ?? 0;
              cacheReadTokens  = (td.cache_read?.tokenCount  as number | undefined) ?? 0;
              cacheWriteTokens = (td.cache_write?.tokenCount as number | undefined) ?? 0;
              outputTokens     = (td.output?.tokenCount      as number | undefined) ?? outputTokens;
            }
          }
          break; // found the shutdown event
        } catch {
          // malformed line — skip
        }
      }
    } catch {
      // events.jsonl absent or unreadable — use accumulated output tokens
    }
  }

  const tokens = {
    input: inputTokens,
    output: outputTokens,
    ...(cacheReadTokens  !== undefined ? { cacheRead:  cacheReadTokens  } : {}),
    ...(cacheWriteTokens !== undefined ? { cacheWrite: cacheWriteTokens } : {}),
  };

  if (ok) {
    return {
      kind: "finish",
      ok: true,
      result: "",
      usd: credits,
      tokens,
      durationMs: Date.now() - startedAt,
    };
  } else {
    return {
      kind: "finish",
      ok: false,
      reason: reason ?? "copilot run failed",
      usd: credits,
      tokens,
      durationMs: Date.now() - startedAt,
    };
  }
}
