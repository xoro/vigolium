# Updating vigolium-audit (Vendored Copy)

This document describes how to pull new changes from the upstream
`vigolium-audit` project into vigolium's vendored copy at
`platform/vigolium-audit/`, without losing this fork's GitHub Copilot
support (the `--agent copilot` platform, added on top of upstream's
claude/codex-only support).

## Overview

Unlike a git submodule, `platform/vigolium-audit/` is a **plain vendored
copy** — full source, committed directly into vigolium's own git history.
It is kept in sync with upstream manually, via `make sync-audit`, which
`rsync -a --delete`s a sibling `vigolium-audit` checkout on top of it and
then rebuilds the embedded binary (`make update-audit`).

**This is destructive.** `rsync --delete` overwrites and deletes files to
match upstream exactly — it will silently wipe out every fork-specific
Copilot change and the two Copilot-only source files, reverting
`platform/vigolium-audit/` to upstream's claude/codex-only state. There is
no merge, no conflict markers — just a full-tree replace.

Fork-specific additions on top of upstream:

- **GitHub Copilot CLI adapter** (`src/adapters/copilot-cli.ts`,
  `src/adapters/copilot-events.ts`) — headless-only, no BYOK auth path,
  no `-i`/interactive support.
- **Refusal detection** — Copilot exits 0 even when it flatly refuses a
  prompt in plain text; the normalizer detects this and reports
  `finish ok=false` instead of a false "success".
- **3-way platform validation** in every CLI entry point that previously
  hardcoded `claude | codex` (`run`, `verify`, `uninstall`, `setup`,
  `dry-run`).
- **Copilot unit tests** (`tests/unit/copilot-events.test.ts`).
- The corresponding Go-side wiring in `vigolium` itself
  (`pkg/agent/agenttypes/constants.go`, `pkg/agent/audit_driver_args.go`,
  `pkg/agent/auth_override.go`, `pkg/cli/agent_audit.go`,
  `pkg/server/handlers_agent_audit*.go`) is **not** touched by
  `sync-audit` at all (it lives outside `platform/vigolium-audit/`), but
  still needs re-testing after any upstream sync since it depends on
  vigolium-audit's `--agent copilot` flag continuing to exist and behave
  the same way.

## Prerequisites

A sibling checkout of upstream `vigolium-audit`, matching the
`AUDIT_UPSTREAM` default (`../vigolium-audit` relative to this repo):

```sh
cd /Users/palltimo/Development
git clone git@github.com:vigolium/vigolium-audit.git
# or your own fork, e.g. git@github.com:xoro/vigolium-audit.git
cd vigolium-audit && git checkout main && git pull
```

Override the path if your checkout lives elsewhere:

```sh
make sync-audit AUDIT_UPSTREAM=/path/to/vigolium-audit
```

## Update Steps

### 1. Check what's new upstream before syncing

```sh
diff <(jq -r .version platform/vigolium-audit/package.json) \
     <(jq -r .version ../vigolium-audit/package.json)
cd ../vigolium-audit && git log --oneline -20 && cd -
```

### 2. Back up the fork-specific diff

`platform/vigolium-audit/` is committed in vigolium's own history, so the
current state is always recoverable from git — but capturing an explicit
patch makes step 4 mechanical instead of a memory exercise:

```sh
git diff -- platform/vigolium-audit > /tmp/vigolium-audit-copilot-fork.patch
git status --porcelain -- platform/vigolium-audit  # should be clean before syncing
```

If step 2's `git status` isn't clean, commit or stash first — `sync-audit`
will otherwise mix your in-progress edits with upstream's.

### 3. Sync from upstream

```sh
make sync-audit
```

This rsyncs `../vigolium-audit/` → `platform/vigolium-audit/` (excluding
`node_modules`, `build/dist`, `.git`, `src/content-bundle.json`,
`src/content/sdk-variants/`), then runs `make update-audit` automatically
(rebuilds the embedded binary for all targets and stages the host one at
`pkg/audit/bin/_bin/vigolium-audit`).

At this point, **all Copilot support is gone** from
`platform/vigolium-audit/` — this is expected. Continue to step 4.

### 4. Restore fork-specific Copilot changes

Re-apply the patch from step 2 as a starting point:

```sh
git apply --reject /tmp/vigolium-audit-copilot-fork.patch
```

`--reject` writes any hunk that no longer applies cleanly to a `.rej`
file next to the target — expect at least a few rejects if upstream
touched the same functions. Resolve each `.rej` by hand using the
per-file guide below, then delete the `.rej` files.

#### New files (never present upstream — restore verbatim if deleted)

| File | Purpose |
| --- | --- |
| `src/adapters/copilot-cli.ts` | `CopilotCliAdapter` — spawns `copilot -p <prompt> --output-format json --allow-all-tools --no-color`, parses NDJSON via `normalizeCopilotEvent` |
| `src/adapters/copilot-events.ts` | `normalizeCopilotEvent()` + `CopilotNormalizeState` — event normalizer, including the plain-text-refusal detector (`REFUSAL_PATTERN`, `isLikelyRefusal()`) |
| `tests/unit/copilot-events.test.ts` | Unit tests for the normalizer, including refusal-detection cases |

If `git apply` couldn't re-add these (e.g. upstream now has a file at the
same path with different content), just re-copy them from before the sync
(`git show HEAD:platform/vigolium-audit/src/adapters/copilot-cli.ts >
platform/vigolium-audit/src/adapters/copilot-cli.ts`, etc.) and adjust
imports (`spawnAndStream`, `Adapter`/`AdapterEvent`/`AdapterRunInput`,
`isTransientError`) if upstream renamed anything in `cli-process.ts` /
`adapter.ts` / `claude-events.ts`.

#### Modified files — what must be re-applied

| File | What to restore |
| --- | --- |
| `src/engine/types.ts` | `AgentPlatform` must include `"copilot"`: `"claude" \| "codex" \| "copilot"` |
| `src/adapters/detect.ts` | `probeCopilotBinary()` (env override `VIGOLIUM_AUDIT_COPILOT_PATH`, no bundled packages); `chooseAdapter()` special-cases `platform === "copilot"` → always `flavor: "cli"`, auth from binary presence only; `platformApiKeyEnv()` returns `string \| null`, `null` for copilot |
| `src/engine/auth-overrides.ts` | `applyAuthOverrides()` throws immediately if `platform === "copilot"` and any of `oauthToken`/`oauthCredFile`/`apiKey` is set (no BYOK path); `platformCredFilePath()` throws for copilot |
| `src/engine/harness.ts` | `installHarness`, `uninstallHarness`, `uninstallHarnessSync`, `registerEphemeralHarness` (and `harnessInstalled` if present) all accept `"copilot"` as a **no-op** (no harness ever installed) — copilot is headless-only |
| `src/cli/run.ts` | 3-way `--agent` validation; explicit early failure when `opts.interactive && platform === "copilot"` (placed before `runInteractive()` is ever called — do **not** touch `run-interactive.ts` itself); adapter-construction ternary gets a third `new CopilotCliAdapter(...)` branch; install-hint message extended |
| `src/cli/verify.ts` | Same 3-way validation + install-hint pattern; `buildChecks()`'s "auth source" and "message round-trip" checks get a copilot branch |
| `src/cli/uninstall.ts` | `PLATFORMS` tuple (or equivalent validation) includes `"copilot"` |
| `src/cli/setup.ts` | Same — `PLATFORMS` tuple includes `"copilot"` (installs as a no-op, matching `harness.ts`) |
| `src/cli/dry-run.ts` | 3-way validation. The `variant: ContentVariant = platform === "codex" ? "sdk" : "default"` ternary needs **no change** — copilot already falls into `"default"` automatically (it uses Claude-shaped content, since Copilot has a real agent/skill/plugin system unlike Codex) |
| `src/index.ts` | `--agent <agent>` help text mentions `copilot` and notes it's headless-only |
| `CLAUDE.md` | Architecture section lists `copilot-cli` as a fifth adapter; harness section notes copilot never gets one |

After manual restoration, also check `src/engine/orchestrator.ts` line
~596 (`contentVariant()`) — same `"codex" ? "sdk" : "default"` pattern,
should need no change for the same reason as `dry-run.ts` above.

### 5. Rebuild

```sh
cd /Users/palltimo/Development/vigolium/platform/vigolium-audit
bun install
bun run typecheck
bun test
cd /Users/palltimo/Development/vigolium
make update-audit   # rebuilds + re-stages the embedded binary
make build
```

### 6. Verify

```sh
./bin/vigolium agent audit --agent copilot --source /tmp verify 2>&1 || true
# or, once built:
platform/vigolium-audit/build/dist/vigolium-audit-darwin-arm64 verify copilot
```

Also re-run the Go-side tests, since they assert on vigolium-audit's
`--agent` behavior indirectly:

```sh
go build ./...
go test ./pkg/agent/... ./pkg/cli/... ./pkg/server/...
```

### 7. Commit

```sh
git add platform/vigolium-audit pkg/audit/bin/_bin/vigolium-audit
printf '%s\n' "chore(audit): sync vigolium-audit vX.Y.Z, restore copilot support" > /tmp/msg.txt
git commit --file /tmp/msg.txt && rm /tmp/msg.txt
```

## Known fragile merge points

| Area | Why fragile | What to check |
| --- | --- | --- |
| `auditAgentSelFromProvider` (Go, `pkg/agent/audit_driver_args.go`) | Not part of `sync-audit` at all, but assumes vigolium-audit's `--agent` flag accepts exactly `claude\|codex\|copilot` with those literal string values | If upstream/fork ever renames the flag value, update the Go-side `AuditDriverAgent` constants and mapping to match |
| `ValidateAuditDriverInvocation` / `ValidateAuthOverride` (Go) | Assumes copilot has **no** BYOK auth path | If upstream ever adds a copilot auth mechanism (API key, OAuth), these Go-side rejections become wrong and need loosening |
| Copilot CLI's NDJSON event shape (`copilot-events.ts`) | Determined empirically against Copilot CLI v1.0.68 — no public wire-format spec | Re-verify `assistant.message_delta` / `assistant.reasoning_delta` / `tool.execution_start` / `tool.execution_complete` / `result` shapes haven't changed after a Copilot CLI upgrade; the standalone `bun run dev -- verify copilot` command is the fastest way to catch a broken adapter |
| Refusal-detection heuristic (`REFUSAL_PATTERN` / `isLikelyRefusal`) | English-only, pattern-matches the opening of Copilot's known refusal phrasing | If Copilot CLI's refusal wording changes, false negatives (refusals reported as success) are the failure mode — watch for phases that report `done` with `$0.00 — 0/0 tok` in well under a minute and no tool calls |
