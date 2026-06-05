import { describe, expect, test } from "bun:test";
import { buildSpec, renderMarkdown } from "../../src/cli/output-structure.js";
import { DURABLE_DIRS, DURABLE_STATE_FILES } from "../../src/engine/strip-artifacts.js";
import { JUNK_DIR_NAMES, JUNK_FILE_EXTENSIONS } from "../../src/engine/redact-artifacts.js";

describe("buildSpec — keep set stays in sync with the strip pass", () => {
  const spec = buildSpec();
  const keepPaths = new Set(spec.keep.map((k) => k.path));

  test("every durable state file the strip pass keeps is in the keep set", () => {
    for (const name of DURABLE_STATE_FILES) {
      expect(keepPaths.has(name)).toBe(true);
    }
  });

  test("every durable directory the strip pass keeps is in the keep set", () => {
    for (const name of DURABLE_DIRS) {
      expect(keepPaths.has(`${name}/`)).toBe(true);
    }
  });

  test("confirm-workspace/ and *.md reports are kept", () => {
    expect(keepPaths.has("confirm-workspace/")).toBe(true);
    expect(keepPaths.has("*.md")).toBe(true);
  });

  test("every keep entry carries a non-empty note", () => {
    for (const k of spec.keep) expect(k.note.length).toBeGreaterThan(0);
  });
});

describe("buildSpec — sweep matches the junk constants", () => {
  test("sweep lists every junk extension and dir from redact-artifacts", () => {
    const spec = buildSpec();
    for (const ext of JUNK_FILE_EXTENSIONS) expect(spec.sweep).toContain(`*${ext}`);
    for (const dir of JUNK_DIR_NAMES) expect(spec.sweep).toContain(`${dir}/`);
  });
});

describe("buildSpec — remove + redact guidance", () => {
  const spec = buildSpec();

  test("findings-draft/ is removed with a 'promote first' note (must not silently drop drafts)", () => {
    const draft = spec.remove.find((r) => r.path === "findings-draft/");
    expect(draft).toBeDefined();
    expect(draft!.note.toLowerCase()).toContain("promote");
  });

  test("nothing that the strip pass keeps appears in the remove list", () => {
    const keepPaths = new Set(spec.keep.map((k) => k.path));
    for (const r of spec.remove) expect(keepPaths.has(r.path)).toBe(false);
  });

  test("redaction is scoped to confirm-workspace and drops db snapshots", () => {
    expect(spec.redact.scope).toContain("confirm-workspace");
    expect(spec.redact.drop).toContain("db-snapshot.*");
  });

  test("instructions warn against rewriting durable state files", () => {
    const joined = spec.instructions.join(" ").toLowerCase();
    expect(joined).toContain("audit-state.json");
    expect(joined).toContain("file-state.json");
  });
});

describe("renderMarkdown", () => {
  const md = renderMarkdown(buildSpec());

  test("emits the canonical headings a downstream agent keys off", () => {
    expect(md).toContain("# Ideal vigolium-results/ layout");
    expect(md).toContain("## Keep");
    expect(md).toContain("## Remove");
    expect(md).toContain("## Instructions for the cleanup agent");
  });

  test("renders KEEP and REMOVE markers in the canonical tree", () => {
    expect(md).toContain("KEEP");
    expect(md).toContain("REMOVE");
    expect(md).toContain("vigolium-results/");
  });

  test("instructions are numbered", () => {
    expect(md).toContain("1. ");
  });
});
