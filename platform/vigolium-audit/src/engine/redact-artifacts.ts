import { readdir, readFile, rm, writeFile } from "fs/promises";
import { join, relative } from "path";
import { stripRawArtifacts, type StripRawArtifactsOptions } from "./strip-artifacts.js";

/**
 * Content-level cleanup that runs *after* the structural prune
 * (`stripRawArtifacts`). Two concerns, both recursive into the surviving tree:
 *
 *   - `sweepJunk`     — delete scanner scratch that survives inside kept dirs
 *                       (`*.sarif`, `*.bqrs`, stray `tmp/` directories).
 *   - `redactSecrets` — drop DB snapshots wholesale and scrub secret values
 *                       (passwords, tokens, API keys, connection strings) out
 *                       of the JSON + log files under `confirm-workspace/`.
 *
 * `finalizeOutput` composes strip → sweep → (unless `keepSecrets`) redact so
 * the three call sites (the `strip` CLI command, run's deep/confirm auto-prune,
 * and the orchestrator's `--strip-raw` path) share one ordering.
 *
 * Every operation is idempotent: snapshots are already gone, junk extensions
 * no longer exist, and masked values (`***`) are skipped on a second pass.
 */

export interface RedactionReport {
  /** Paths (relative to resultsDir) of high-risk artifacts deleted wholesale. */
  artifactsDropped: string[];
  /** Paths (relative to resultsDir) of junk files/dirs removed by the sweep. */
  junkRemoved: string[];
  /** Number of files whose contents were scrubbed in place. */
  filesScrubbed: number;
  /** Total count of individual secret values masked across all files. */
  valuesMasked: number;
}

export interface FinalizeOptions extends StripRawArtifactsOptions {
  /**
   * Retain DB snapshots and skip scrubbing `confirm-workspace/` JSON + logs.
   * The junk sweep still runs (junk is not a secret). Default: redact.
   */
  keepSecrets?: boolean;
}

const REDACTED = "***";

// Scanner scratch that can survive inside kept directories. Exported so the
// `output-structure` command can describe the sweep without duplicating it.
export const JUNK_FILE_EXTENSIONS = [".sarif", ".bqrs"];
export const JUNK_DIR_NAMES = new Set(["tmp"]);

// Full DB dumps can't be reliably scrubbed, so confirm mode's snapshots are
// removed wholesale rather than redacted.
function isHighRiskArtifact(name: string): boolean {
  return /^db-snapshot\.[^.]+$/i.test(name);
}

// JSON keys whose values are secrets. Matched case-insensitively against the
// *exact* key name (not a substring) so counters like `tokens` / `total_tokens`
// in state files are never touched.
const SECRET_JSON_KEYS = new Set([
  "password",
  "passwd",
  "pwd",
  "token",
  "secret",
  "client_secret",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "bearer",
  "authorization",
  "private_key",
  "credential",
  "credentials",
  "db_password",
]);

// KEY=VALUE / KEY: VALUE where the key name marks the value secret. The value
// is the first quoted string or non-space run after the separator.
const ENV_SECRET_RE =
  /\b([A-Za-z][A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTHORIZATION|DATABASE_URL|DB_PASS|CONN(?:ECTION)?_?STR(?:ING)?)[A-Za-z0-9_]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi;
// Inline credentials in a connection URL: scheme://user:pass@host.
const URL_CRED_RE = /\b([a-z][a-z0-9+.-]*:\/\/[^:/@\s]+):([^@/\s]+)@/gi;
// Well-known opaque token shapes anywhere in a line.
const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g;
const TOKEN_SHAPE_RE =
  /\b(?:sk-[A-Za-z0-9]{16,}|gh[posru]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

/**
 * Strip + sweep + (optionally) redact, in that order. Returns a combined
 * report of everything dropped/scrubbed.
 */
export async function finalizeOutput(
  resultsDir: string,
  options: FinalizeOptions = {},
): Promise<RedactionReport> {
  const { keepSecrets, ...stripOptions } = options;
  await stripRawArtifacts(resultsDir, stripOptions);
  const junkRemoved = await sweepJunk(resultsDir);
  const secrets = keepSecrets
    ? { artifactsDropped: [] as string[], filesScrubbed: 0, valuesMasked: 0 }
    : await redactSecrets(resultsDir);
  return { ...secrets, junkRemoved };
}

/**
 * Recursively delete scanner scratch (`*.sarif`, `*.bqrs`, `tmp/` dirs) left
 * inside the surviving tree. Returns the relative paths removed.
 */
export async function sweepJunk(resultsDir: string): Promise<string[]> {
  const removed: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (JUNK_DIR_NAMES.has(entry.name)) {
          await rm(full, { recursive: true, force: true }).catch(() => {});
          removed.push(relative(resultsDir, full));
          continue;
        }
        await walk(full);
      } else if (JUNK_FILE_EXTENSIONS.some((ext) => entry.name.toLowerCase().endsWith(ext))) {
        await rm(full, { force: true }).catch(() => {});
        removed.push(relative(resultsDir, full));
      }
    }
  };
  await walk(resultsDir);
  return removed;
}

/**
 * Drop DB snapshots and scrub secrets from the `confirm-workspace/` subtree.
 * Scoped to `confirm-workspace/` so durable state files (`audit-state.json`,
 * `file-state.json`) that downstream tooling parses are never rewritten.
 */
export async function redactSecrets(
  resultsDir: string,
): Promise<Omit<RedactionReport, "junkRemoved">> {
  const workspace = join(resultsDir, "confirm-workspace");
  const report = { artifactsDropped: [] as string[], filesScrubbed: 0, valuesMasked: 0 };

  const walk = async (dir: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      if (isHighRiskArtifact(entry.name)) {
        await rm(full, { force: true }).catch(() => {});
        report.artifactsDropped.push(relative(resultsDir, full));
        continue;
      }
      const lower = entry.name.toLowerCase();
      const masked = lower.endsWith(".json")
        ? await scrubJsonFile(full)
        : lower.endsWith(".log")
          ? await scrubLogFile(full)
          : 0;
      if (masked > 0) {
        report.filesScrubbed++;
        report.valuesMasked += masked;
      }
    }
  };

  await walk(workspace);
  return report;
}

/** Parse a JSON file, mask secret-keyed values, rewrite only if anything changed. */
async function scrubJsonFile(path: string): Promise<number> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return 0;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return 0; // not valid JSON — leave it untouched
  }
  const counter = { n: 0 };
  const scrubbed = redactJsonValue(parsed, counter);
  if (counter.n === 0) return 0;
  const out = JSON.stringify(scrubbed, null, 2) + (raw.endsWith("\n") ? "\n" : "");
  await writeFile(path, out, "utf8").catch(() => {});
  return counter.n;
}

function redactJsonValue(value: unknown, counter: { n: number }, keyName?: string): unknown {
  if (keyName !== undefined && SECRET_JSON_KEYS.has(keyName.toLowerCase())) {
    if (typeof value === "string") {
      if (value === "" || value === REDACTED) return value;
      counter.n++;
      return REDACTED;
    }
    if (typeof value === "number") {
      counter.n++;
      return REDACTED;
    }
    // null / boolean / nested structures under a secret key fall through.
  }
  if (Array.isArray(value)) {
    return value.map((v) => redactJsonValue(v, counter, keyName));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactJsonValue(v, counter, k);
    }
    return out;
  }
  return value;
}

/** Scrub secret values out of a log file, rewriting only if anything changed. */
async function scrubLogFile(path: string): Promise<number> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return 0;
  }
  const counter = { n: 0 };
  const out = redactLogText(raw, counter);
  if (counter.n === 0) return 0;
  await writeFile(path, out, "utf8").catch(() => {});
  return counter.n;
}

export function redactLogText(text: string, counter: { n: number }): string {
  let out = text.replace(ENV_SECRET_RE, (m, key: string, sep: string, val: string) => {
    const bare = val.replace(/^["']|["']$/g, "");
    if (bare === REDACTED || bare === "") return m;
    counter.n++;
    return `${key}${sep}${REDACTED}`;
  });
  out = out.replace(URL_CRED_RE, (m, prefix: string, pass: string) => {
    if (pass === REDACTED) return m;
    counter.n++;
    return `${prefix}:${REDACTED}@`;
  });
  out = out.replace(JWT_RE, () => {
    counter.n++;
    return REDACTED;
  });
  out = out.replace(TOKEN_SHAPE_RE, () => {
    counter.n++;
    return REDACTED;
  });
  return out;
}
