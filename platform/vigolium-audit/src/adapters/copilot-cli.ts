import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError } from "./claude-events.js";
import { createCopilotNormalizeState, normalizeCopilotEvent } from "./copilot-events.js";
import { spawnAndStream } from "./cli-process.js";

export interface CopilotCliAdapterOptions {
  /** Absolute path to the `copilot` binary. Required. */
  pathToCopilotExecutable: string;
  /** Default model passed to `copilot -p --model`. */
  defaultModel?: string;
}

/**
 * Drives the official GitHub Copilot CLI (`copilot -p <prompt>
 * --output-format json --allow-all-tools`) and parses its NDJSON stream into
 * AdapterEvents via normalizeCopilotEvent.
 *
 * Unlike Codex/Claude, Copilot takes the whole prompt as a `-p` CLI argument
 * rather than reading it from stdin, and has no separate "SDK" flavor -- it
 * is CLI-only, authenticated via whatever `copilot login` state the binary
 * already has (no API-key/OAuth-cred-file override path; see
 * engine/auth-overrides.ts).
 *
 * `--allow-all-tools` is required for non-interactive mode (per `copilot
 * --help`): without it, every tool call blocks on an interactive permission
 * prompt that can never be answered from a pipe. This is unconditional here
 * (not gated on `input.bypassPermissions`) since headless vigolium-audit runs
 * always need it -- there's no supervised approval loop to fall back to.
 */
export class CopilotCliAdapter implements Adapter {
  readonly id = "copilot-cli";
  readonly platform = "copilot" as const;
  readonly description: string;

  constructor(private readonly options: CopilotCliAdapterOptions) {
    this.description = `GitHub Copilot (CLI: ${options.pathToCopilotExecutable})`;
  }

  async probe(): Promise<void> {
    let got = false;
    let lastError: Error | null = null;
    try {
      for await (const ev of this.run({
        systemPrompt: "Reply with exactly: pong",
        userPrompt: "ping",
        maxTurns: 1,
      })) {
        if (ev.kind === "finish") {
          got = ev.ok;
          if (!ev.ok) lastError = new Error(`probe finished non-ok: ${ev.reason}`);
          break;
        }
        if (ev.kind === "error") {
          lastError = ev.cause;
          break;
        }
      }
    } catch (err) {
      lastError = err as Error;
    }
    if (!got) throw lastError ?? new Error("Copilot CLI probe did not return a finish event");
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const startedAt = Date.now();
    const cwd = input.cwd ?? process.cwd();
    const state = createCopilotNormalizeState();

    const composedPrompt = `${input.systemPrompt ?? ""}\n\n${input.userPrompt}`.trim();

    const args = ["-p", composedPrompt, "--output-format", "json", "--allow-all-tools", "--no-color"];

    const model = input.model ?? this.options.defaultModel;
    if (model) args.push("--model", model);

    const { stream } = spawnAndStream<never>({
      command: this.options.pathToCopilotExecutable,
      args,
      cwd,
      // Copilot reads its prompt from the `-p` argument, not stdin; the
      // empty string is written then the pipe is closed, which the CLI
      // simply ignores.
      stdin: "",
      ...(input.debug !== undefined ? { debug: input.debug } : {}),
      ...(input.abortSignal !== undefined ? { abortSignal: input.abortSignal } : {}),
    });

    for await (const item of stream) {
      if (item.kind === "line") {
        let event: unknown;
        try {
          event = JSON.parse(item.line);
        } catch {
          yield { kind: "textDelta", text: item.line + "\n" };
          continue;
        }
        yield* normalizeCopilotEvent(event, startedAt, state);
      } else if (item.kind === "exit") {
        if (item.crashed) {
          yield { kind: "error", cause: item.crashed, transient: isTransientError(item.crashed) };
        } else if (item.exitCode !== null && item.exitCode !== 0) {
          const cause = new Error(
            `copilot CLI exited ${item.exitCode}${item.stderr ? `: ${item.stderr.slice(0, 500)}` : ""}`,
          );
          yield { kind: "error", cause, transient: isTransientError(cause) };
        }
      }
    }
  }
}
