import { describe, expect, test } from "bun:test";
import { createCopilotNormalizeState, normalizeCopilotEvent, buildCopilotFinish } from "../../src/adapters/copilot-events.js";
import type { AdapterEvent } from "../../src/adapters/adapter.js";

async function collect(events: unknown[]): Promise<AdapterEvent[]> {
  const out: AdapterEvent[] = [];
  const startedAt = Date.now();
  const state = createCopilotNormalizeState();
  for (const e of events) {
    for (const a of normalizeCopilotEvent(e, startedAt, state)) out.push(a);
  }
  // Emit the finish event built from pendingFinish + events.jsonl fallback
  const finish = await buildCopilotFinish(state);
  if (finish) out.push(finish);
  return out;
}

describe("normalizeCopilotEvent (GitHub Copilot CLI NDJSON shape)", () => {
  test("assistant.message_delta → textDelta", async () => {
    const events = await collect([
      { type: "assistant.message_delta", data: { deltaContent: "Pong" } },
    ]);
    expect(events).toEqual([{ kind: "textDelta", text: "Pong" }]);
  });

  test("empty deltaContent yields nothing", async () => {
    const events = await collect([{ type: "assistant.message_delta", data: { deltaContent: "" } }]);
    expect(events).toEqual([]);
  });

  test("assistant.reasoning_delta → thinking", async () => {
    const events = await collect([
      { type: "assistant.reasoning_delta", data: { deltaContent: "considering the auth flow…" } },
    ]);
    expect(events).toEqual([{ kind: "thinking", text: "considering the auth flow…" }]);
  });

  test("tool.execution_start → toolCall", async () => {
    const events = await collect([
      {
        type: "tool.execution_start",
        data: { toolCallId: "call-1", toolName: "bash", arguments: { command: "ls -la" } },
      },
    ]);
    expect(events).toEqual([
      { kind: "toolCall", id: "call-1", tool: "bash", input: { command: "ls -la" } },
    ]);
  });

  test("tool.execution_start without a toolCallId is dropped (no id to correlate)", async () => {
    const events = await collect([
      { type: "tool.execution_start", data: { toolName: "bash", arguments: {} } },
    ]);
    expect(events).toEqual([]);
  });

  test("tool.execution_complete success → toolResult isError=false", async () => {
    const events = await collect([
      {
        type: "tool.execution_complete",
        data: { toolCallId: "call-1", success: true, result: { content: "total 0" } },
      },
    ]);
    expect(events).toEqual([{ kind: "toolResult", id: "call-1", output: "total 0", isError: false }]);
  });

  test("tool.execution_complete failure → toolResult isError=true", async () => {
    const events = await collect([
      {
        type: "tool.execution_complete",
        data: { toolCallId: "call-1", success: false, result: { content: "command not found" } },
      },
    ]);
    expect(events).toEqual([
      { kind: "toolResult", id: "call-1", output: "command not found", isError: true },
    ]);
  });

  test("result with exitCode 0 → finish ok=true", async () => {
    const events = await collect([{ type: "result", exitCode: 0, usage: { aiCredits: 3 } }]);
    expect(events.length).toBe(1);
    const ev = events[0]!;
    if (ev.kind !== "finish" || !ev.ok) throw new Error("expected finish ok=true");
    // 3 aiCredits × $0.01/credit = $0.03 USD (GitHub billing: 1 AI credit = $0.01)
    expect(ev.usd).toBe(0.03);
    expect(ev.tokens).toEqual({ input: 0, output: 0 });
  });

  test("result with non-zero exitCode → finish ok=false", async () => {
    const events = await collect([{ type: "result", exitCode: 1, usage: {} }]);
    expect(events.length).toBe(1);
    const ev = events[0]!;
    if (ev.kind !== "finish" || ev.ok) throw new Error("expected finish ok=false");
    expect(ev.reason).toBe("copilot CLI exited 1");
  });

  test("result falls back to premiumRequests when aiCredits is absent", async () => {
    const events = await collect([{ type: "result", exitCode: 0, usage: { premiumRequests: 1 } }]);
    const ev = events[0]!;
    if (ev.kind !== "finish" || !ev.ok) throw new Error("expected finish ok=true");
    expect(ev.usd).toBe(1);
  });

  test("unrecognized event types (session.*, user.message, ...) are ignored", async () => {
    const events = await collect([
      { type: "session.mcp_servers_loaded", data: {} },
      { type: "user.message", data: { content: "ping" } },
      { type: "assistant.turn_start", data: {} },
    ]);
    expect(events).toEqual([]);
  });

  test("malformed / non-object input is ignored without throwing", async () => {
    expect(await collect([null, undefined, "not json", 42])).toEqual([]);
  });

  test("plain-text refusal with exitCode 0 and no tool calls → finish ok=false", async () => {
    const events = await collect([
      {
        type: "assistant.message_delta",
        data: { deltaContent: "I'm sorry, but I cannot assist with that request." },
      },
      { type: "result", exitCode: 0, usage: {} },
    ]);
    const finish = events.find((e) => e.kind === "finish");
    if (!finish || finish.kind !== "finish" || finish.ok) throw new Error("expected finish ok=false");
    expect(finish.reason).toBe(
      `Copilot refused the request: "I'm sorry, but I cannot assist with that request."`,
    );
  });

  test("short refusal-like phrase is NOT flagged once a tool call happened", async () => {
    const events = await collect([
      { type: "tool.execution_start", data: { toolCallId: "call-1", toolName: "bash", arguments: {} } },
      { type: "tool.execution_complete", data: { toolCallId: "call-1", success: true, result: {} } },
      {
        type: "assistant.message_delta",
        data: { deltaContent: "I'm sorry, but I cannot assist with that request." },
      },
      { type: "result", exitCode: 0, usage: {} },
    ]);
    const finish = events.find((e) => e.kind === "finish");
    if (!finish || finish.kind !== "finish") throw new Error("expected a finish event");
    expect(finish.ok).toBe(true);
  });

  test("long legitimate audit output containing an apologetic phrase is NOT flagged as a refusal", async () => {
    const longText =
      "## Findings\n\n" +
      "After a thorough review of the codebase spanning multiple modules, I identified three " +
      "issues worth reporting in detail below, including their severity, affected files, and " +
      "suggested remediations for the maintainers to review and act upon at their discretion. " +
      "Note: I cannot assist with actively exploiting these in a production environment, only " +
      "documenting them here for defensive purposes. See the full report below for details.";
    const events = await collect([
      { type: "assistant.message_delta", data: { deltaContent: longText } },
      { type: "result", exitCode: 0, usage: {} },
    ]);
    const finish = events.find((e) => e.kind === "finish");
    if (!finish || finish.kind !== "finish") throw new Error("expected a finish event");
    expect(finish.ok).toBe(true);
  });
});
