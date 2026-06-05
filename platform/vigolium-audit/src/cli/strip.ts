import { existsSync, statSync } from "fs";
import { resolve, basename, join } from "path";
import chalk from "chalk";
import { finalizeOutput } from "../engine/redact-artifacts.js";

export interface StripOptions {
  json?: boolean;
  /** Retain DB snapshots and skip scrubbing confirm-workspace secrets. */
  keepSecrets?: boolean;
}

/**
 * `vigolium-audit strip <path>` — apply the same post-audit pruning that the
 * orchestrator's `--strip-raw` flag does, on demand. Accepts either the
 * project directory (containing `vigolium-results/`) or the `vigolium-results/` directory itself.
 *
 * Always preserved: durable state JSON (`audit-state.json`, `file-state.json`,
 * revisit state), `findings/`, `findings-theoretical/`, `attack-surface/`,
 * `confirm-workspace/`, `quarantine/`, and any top-level `*.md` reports.
 * Drafts in `findings-draft/` are promoted into `findings/` before deletion
 * (without clobbering same-named finals).
 *
 * By default it also recursively removes scanner scratch (`*.sarif`, `*.bqrs`,
 * `tmp/`) and redacts secrets from `confirm-workspace/`: DB snapshots are
 * dropped, and passwords / tokens / API keys / connection strings in the
 * JSON + log files are masked. Pass `--keep-secrets` to retain those.
 */
export async function stripCommand(targetPath: string, opts: StripOptions): Promise<void> {
  const json = !!opts.json;
  const fail = (msg: string, exit = 2): never => {
    if (json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(exit);
  };

  const resolved = resolve(targetPath);
  if (!existsSync(resolved)) {
    return fail(`path does not exist: ${resolved}`);
  }
  if (!statSync(resolved).isDirectory()) {
    return fail(`path is not a directory: ${resolved}`);
  }

  // Accept either `vigolium-results/` directly (audit-state.json sibling) or a project
  // dir that contains a `vigolium-results/` subdir. We refuse to operate on directories
  // that look like neither, to avoid nuking unrelated trees.
  const looksLikeResultsDir =
    basename(resolved) === "vigolium-results" || existsSync(join(resolved, "audit-state.json"));
  const resultsDir = looksLikeResultsDir ? resolved : join(resolved, "vigolium-results");

  if (!existsSync(resultsDir)) {
    return fail(`no vigolium-results/ directory found at ${resultsDir}`);
  }
  if (!existsSync(join(resultsDir, "audit-state.json"))) {
    return fail(
      `${resultsDir} has no audit-state.json — refusing to strip`,
    );
  }

  const report = await finalizeOutput(resultsDir, {
    ...(opts.keepSecrets ? { keepSecrets: true } : {}),
  });

  if (json) {
    process.stdout.write(JSON.stringify({ ok: true, resultsDir, redaction: report }) + "\n");
  } else {
    console.log(chalk.green(`[vigolium-audit] stripped raw artifacts from ${resultsDir}`));
    if (report.junkRemoved.length > 0) {
      console.log(chalk.dim(`  removed ${report.junkRemoved.length} junk file(s) (sarif/bqrs/tmp)`));
    }
    if (opts.keepSecrets) {
      console.log(chalk.yellow("  --keep-secrets: DB snapshots and confirm-workspace secrets retained"));
    } else if (report.artifactsDropped.length > 0 || report.valuesMasked > 0) {
      console.log(
        chalk.dim(
          `  redacted ${report.valuesMasked} secret(s) across ${report.filesScrubbed} file(s), ` +
            `dropped ${report.artifactsDropped.length} DB snapshot(s)`,
        ),
      );
    }
  }
}
