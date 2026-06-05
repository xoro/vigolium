import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { premergeResults } from "../../src/engine/premerge.js";

/** Minimal but valid audit-state.json with one audit record. */
function auditState(opts: { id: string; agent: string; model: string }): string {
  return JSON.stringify({
    schema_version: 1,
    audits: [
      {
        audit_id: opts.id,
        commit: null,
        branch: null,
        repository: "owner/repo",
        mode: "deep",
        model: opts.model,
        agent_sdk: opts.agent,
        started_at: opts.id,
        completed_at: opts.id,
        status: "complete",
        phases: {},
      },
    ],
  });
}

function writeFinding(resultsDir: string, bucket: string, id: string, severity: string): void {
  const dir = join(resultsDir, bucket, id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "draft.md"), `Slug: ${id}\nSeverity-Final: ${severity}\n\n## Summary\n`);
  writeFileSync(join(dir, "report.md"), `## Summary\n${id} in ${bucket}\n`);
}

/** Seed an audit output folder (project dir containing vigolium-results/). */
function seedSource(opts: {
  tag: string;
  id: string;
  agent: string;
  model: string;
  findings: Array<[string, string, string]>; // [bucket, id, severity]
  attackSurface?: boolean;
}): { projectDir: string; resultsDir: string } {
  const projectDir = mkdtempSync(join(tmpdir(), `vigolium-audit-premerge-${opts.tag}-`));
  const resultsDir = join(projectDir, "vigolium-results");
  mkdirSync(resultsDir, { recursive: true });
  writeFileSync(join(resultsDir, "audit-state.json"), auditState(opts));
  for (const [bucket, id, sev] of opts.findings) writeFinding(resultsDir, bucket, id, sev);
  if (opts.attackSurface) {
    mkdirSync(join(resultsDir, "attack-surface"), { recursive: true });
    writeFileSync(join(resultsDir, "attack-surface", "kb.md"), `# KB ${opts.tag}\n`);
  }
  return { projectDir, resultsDir };
}

describe("premergeResults", () => {
  test("in-place: merges B into A, collision-safe, with merge_metadata + backup", async () => {
    const a = seedSource({
      tag: "a",
      id: "2026-01-01T00:00:00.000Z",
      agent: "claude",
      model: "opus",
      findings: [
        ["findings", "C1-sqli-login", "CRITICAL"],
        ["findings", "H1-xss-search", "HIGH"],
      ],
      attackSurface: true,
    });
    const b = seedSource({
      tag: "b",
      id: "2026-02-02T00:00:00.000Z",
      agent: "codex",
      model: "gpt-5.5",
      findings: [
        ["findings", "C1-sqli-login", "CRITICAL"], // collides with A's C1
        ["findings-theoretical", "M1-ssrf-webhook", "MEDIUM"],
      ],
      attackSurface: true,
    });

    const result = await premergeResults({ inputs: [a.projectDir, b.projectDir] });

    // Destination is A's results dir, in place.
    expect(result.destinationInPlace).toBe(true);
    expect(result.destResultsDir).toBe(a.resultsDir);
    expect(result.destProjectDir).toBe(a.projectDir);

    // A's originals untouched.
    expect(existsSync(join(a.resultsDir, "findings", "C1-sqli-login"))).toBe(true);
    expect(existsSync(join(a.resultsDir, "findings", "H1-xss-search"))).toBe(true);

    // B's colliding C1 was renamed to the next free C-id (C2) — not overwritten.
    const remap = result.idRemap.find((r) => r.from === "C1-sqli-login");
    expect(remap).toBeDefined();
    expect(remap!.to).toBe("C2-sqli-login");
    expect(remap!.source).toBe(b.resultsDir);
    expect(existsSync(join(a.resultsDir, "findings", "C2-sqli-login"))).toBe(true);
    // The renamed dir holds B's content, not A's.
    expect(readFileSync(join(a.resultsDir, "findings", "C2-sqli-login", "report.md"), "utf8")).toContain(
      "in findings",
    );

    // B's theoretical bucket copied across (no collision → kept its id).
    expect(existsSync(join(a.resultsDir, "findings-theoretical", "M1-ssrf-webhook"))).toBe(true);
    expect(result.findingsCopied).toBe(2);

    // Backup of A's original state.
    expect(result.backup).toBe(join(a.resultsDir, "audit-state.json.pre-merge.bak"));
    expect(existsSync(result.backup!)).toBe(true);

    // merge_metadata stamped, with both sources + concatenated audits.
    const state = JSON.parse(readFileSync(join(a.resultsDir, "audit-state.json"), "utf8"));
    expect(state.merge_metadata).toBeDefined();
    expect(state.merge_metadata.sources).toEqual([a.resultsDir, b.resultsDir]);
    expect(state.merge_metadata.destination_in_place).toBe(true);
    expect(state.audits.map((x: { audit_id: string }) => x.audit_id)).toEqual([
      "2026-01-01T00:00:00.000Z",
      "2026-02-02T00:00:00.000Z",
    ]);
    // Attribution captured per source.
    expect(state.merge_metadata.source_audits[1].agents).toEqual(["codex"]);
    expect(state.merge_metadata.source_audits[1].models).toEqual(["gpt-5.5"]);
    // attack-surface is unified, not first-wins: both A and B contribute. A's
    // kb.md stays; B's same-named-but-different kb.md is kept under a labelled name.
    expect(result.attackSurfaceSources).toEqual([a.resultsDir, b.resultsDir]);
    expect(existsSync(join(a.resultsDir, "attack-surface", "kb.md"))).toBe(true);
    expect(readFileSync(join(a.resultsDir, "attack-surface", "kb.md"), "utf8")).toContain("# KB a");
    const renamed = result.attackSurfaceRenamed.find((r) => r.from === "kb.md");
    expect(renamed).toBeDefined();
    expect(renamed!.source).toBe(b.resultsDir);
    expect(existsSync(join(a.resultsDir, "attack-surface", renamed!.to))).toBe(true);
    expect(readFileSync(join(a.resultsDir, "attack-surface", renamed!.to), "utf8")).toContain("# KB b");
  });

  test("attack-surface union dedupes byte-identical files and keeps unique ones", async () => {
    const a = seedSource({ tag: "asa", id: "2026-09-01T00:00:00.000Z", agent: "claude", model: "opus", findings: [] });
    const b = seedSource({ tag: "asb", id: "2026-09-02T00:00:00.000Z", agent: "codex", model: "gpt-5.5", findings: [] });
    // A: shared.md + only-a.md. B: shared.md (identical bytes) + only-b.md.
    mkdirSync(join(a.resultsDir, "attack-surface"), { recursive: true });
    mkdirSync(join(b.resultsDir, "attack-surface"), { recursive: true });
    writeFileSync(join(a.resultsDir, "attack-surface", "shared.md"), "# same\n");
    writeFileSync(join(a.resultsDir, "attack-surface", "only-a.md"), "# a\n");
    writeFileSync(join(b.resultsDir, "attack-surface", "shared.md"), "# same\n");
    writeFileSync(join(b.resultsDir, "attack-surface", "only-b.md"), "# b\n");

    const result = await premergeResults({ inputs: [a.projectDir, b.projectDir] });

    // Only B's unique file is copied in; the byte-identical shared.md dedupes.
    expect(result.attackSurfaceCopied).toBe(1);
    expect(result.attackSurfaceRenamed).toEqual([]);
    expect(readdirSync(join(a.resultsDir, "attack-surface")).sort()).toEqual([
      "only-a.md",
      "only-b.md",
      "shared.md",
    ]);
  });

  test("--output: non-destructive, copies all sources, mutates neither", async () => {
    const a = seedSource({
      tag: "a2",
      id: "2026-03-03T00:00:00.000Z",
      agent: "claude",
      model: "opus",
      findings: [["findings", "C1-foo", "CRITICAL"]],
    });
    const b = seedSource({
      tag: "b2",
      id: "2026-04-04T00:00:00.000Z",
      agent: "codex",
      model: "gpt-5.5",
      findings: [["findings", "C1-bar", "CRITICAL"]],
    });
    const outRoot = mkdtempSync(join(tmpdir(), "vigolium-audit-premerge-out-"));

    const result = await premergeResults({ inputs: [a.projectDir, b.projectDir], output: outRoot });

    expect(result.destinationInPlace).toBe(false);
    expect(result.backup).toBeNull();
    expect(result.destResultsDir).toBe(join(outRoot, "vigolium-results"));
    // Both sources' findings present in the fresh destination.
    expect(existsSync(join(result.destResultsDir, "findings", "C1-foo"))).toBe(true);
    // C1-bar collides with C1-foo on the shared id slot → renamed to C2-bar.
    expect(existsSync(join(result.destResultsDir, "findings", "C2-bar"))).toBe(true);
    expect(result.findingsCopied).toBe(2);
    // Neither source mutated.
    expect(readdirSync(join(a.resultsDir, "findings"))).toEqual(["C1-foo"]);
    expect(readdirSync(join(b.resultsDir, "findings"))).toEqual(["C1-bar"]);
    expect(existsSync(join(a.resultsDir, "audit-state.json.pre-merge.bak"))).toBe(false);
  });

  test("rejects fewer than two inputs", async () => {
    const a = seedSource({
      tag: "solo",
      id: "2026-05-05T00:00:00.000Z",
      agent: "claude",
      model: "opus",
      findings: [],
    });
    await expect(premergeResults({ inputs: [a.projectDir] })).rejects.toThrow(/at least two/);
  });

  test("rejects an input that isn't an audit output dir", async () => {
    const a = seedSource({
      tag: "ok",
      id: "2026-06-06T00:00:00.000Z",
      agent: "claude",
      model: "opus",
      findings: [],
    });
    const empty = mkdtempSync(join(tmpdir(), "vigolium-audit-premerge-empty-"));
    await expect(premergeResults({ inputs: [a.projectDir, empty] })).rejects.toThrow(/no vigolium-results/);
  });

  test("rejects a non-empty --output without --force", async () => {
    const a = seedSource({ tag: "a3", id: "2026-07-07T00:00:00.000Z", agent: "claude", model: "opus", findings: [] });
    const b = seedSource({ tag: "b3", id: "2026-08-08T00:00:00.000Z", agent: "codex", model: "gpt-5.5", findings: [] });
    const outRoot = mkdtempSync(join(tmpdir(), "vigolium-audit-premerge-busy-"));
    mkdirSync(join(outRoot, "vigolium-results"), { recursive: true });
    writeFileSync(join(outRoot, "vigolium-results", "stale.txt"), "x");
    await expect(
      premergeResults({ inputs: [a.projectDir, b.projectDir], output: outRoot }),
    ).rejects.toThrow(/not empty/);
    // With --force it proceeds.
    const forced = await premergeResults({ inputs: [a.projectDir, b.projectDir], output: outRoot, force: true });
    expect(forced.destinationInPlace).toBe(false);
  });
});
