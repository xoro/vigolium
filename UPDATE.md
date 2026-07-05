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
| Upstream `run.ts` options (`tmux`, `agentBinary`, `disallowedTools`) | Added upstream in 0.1.14; our fork's `run.ts` doesn't include them (only affects interactive mode — copilot is headless-only) | When syncing, decide per-option whether to integrate into fork's `run.ts`. Currently safe to omit; revisit if a future upstream uses them in code paths copilot also exercises |

## Sync history

| vigolium-audit | Synced | Notes |
| -------------- | ------ | ----- |
| 0.1.13-alpha   | initial vendoring | Baseline; copilot adapter added on top |
| 0.1.14-alpha   | 2026-07-05 | Upstream adds: `version-check.ts` (SDK drift detection), `setup.ts` command, `tmux`/`agentBinary`/`disallowedTools` in `run.ts`. Test fix: `copilot-events.test.ts` aiCredits expectation updated to 0.03 (3 credits × $0.01). |

## Token availability gap — check on each update

The Copilot CLI's `--output-format json` stream exposes `outputTokens` per
`assistant.message` event, but never `inputTokens`. The `result` event only
contains `premiumRequests` (billing units), not raw token counts. vigolium
therefore cannot report input tokens for `--agent copilot` runs; they are
displayed as `in: n/a` in HTML reports.

The vigolium-audit binary emits `tokens: { input: 0, output: 0 }` for copilot
because it collects tokens from the `result` event, not from individual
`assistant.message.outputTokens` fields. Both input and output are 0 in the
audit stream for copilot today.

**After every Copilot CLI upgrade, verify:**

```sh
# Run a minimal prompt and check all event fields in the JSON stream
copilot --prompt "say hi" --output-format json --no-color --allow-all-tools \
  2>/dev/null | grep -o '"input_tokens":[0-9]*\|"inputTokens":[0-9]*' | head -5
```

If the above starts returning non-zero values, the copilot CLI has added
input token reporting to its JSON stream. At that point:

1. Update `platform/vigolium-audit/src/adapters/copilot-events.ts` to read
   `inputTokens` from `assistant.message` events and sum them per phase.
2. In `platform/static-reports/src/components/StatisticsTab.tsx`, remove the
   `agentName.startsWith("copilot")` guard that forces `in: n/a` and let the
   real count render.
3. Update this section to reflect the new state.

## aiCredits billing — check on each update

GitHub switched from request-based to token-based billing (AI credits) on
2026-06-01. **1 AI credit = $0.01 USD** (fixed rate). The copilot CLI now
emits `aiCredits` in the `result` event for github.com accounts (legacy
`premiumRequests` remains for GHE / annual plans).

vigolium-audit converts `aiCredits * 0.01` → USD. After each Copilot CLI
upgrade, verify the `result` event still has `aiCredits` (not a renamed field)
and that the exchange rate hasn't changed:

```sh
copilot --prompt "say hi" --output-format json --no-color --allow-all-tools \
  2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    o = json.loads(line)
    if o.get('type') == 'result':
        print(json.dumps(o.get('usage', {}), indent=2))
"
```

Expected output for github.com accounts (new billing):
```json
{ "aiCredits": 7.89, "totalApiDurationMs": ..., "sessionDurationMs": ... }
```
Expected output for GHE / legacy accounts:
```json
{ "premiumRequests": 1, "totalApiDurationMs": ..., "sessionDurationMs": ... }
```

If `aiCredits` is renamed or the rate changes from $0.01, update
`copilot-events.ts` accordingly.

**When shs.ghe.com migrates from legacy to token-based billing**, the `result`
event will switch from `premiumRequests` to `aiCredits`. No code change is
needed — the `aiCredits * 0.01` path in `copilot-events.ts` already handles
it. Run the command above after a Copilot CLI upgrade to detect the migration:
if you see `aiCredits` instead of `premiumRequests`, GHE has moved to
token-based billing and the cost display will automatically become accurate.

## Model pricing table — update when prices change

The HTML report computes per-token costs using `MODEL_PRICING` in
`platform/static-reports/src/components/StatisticsTab.tsx`. Each entry covers
all four token types (input, cached input, cache write, output), all in
USD per 1M tokens.

**Source**: https://docs.github.com/en/copilot/reference/copilot-billing/models-and-pricing

**⚠️ Time-sensitive**: Claude Sonnet 5 is at **promotional pricing** ($2.00
input / $10.00 output per 1M tokens) **through 2026-08-31**. After that date
revert `"claude-sonnet-5"` to standard Sonnet rates ($3.00 / $15.00).

**Update process** (run after any GitHub Copilot pricing page change):

1. Open `platform/static-reports/src/components/StatisticsTab.tsx`.
2. Update the affected model entry in `MODEL_PRICING`, or add a new entry
   for newly listed models. All prices are USD per 1M tokens.
3. Build and deploy:
   ```sh
   cd platform/static-reports && bun run build
   cp dist/template.html ../../public/static-reports/template.html
   cd ../.. && make install
   ```
4. Add a row to the "Sync history" table below, noting the pricing change.

## Embedded skills — check for upstream updates

Vigolium ships embedded skills under `internal/resources/olium/skills/`. The
caveman skill was sourced from the upstream project at
**https://github.com/juliusbrussee/caveman** and vendored verbatim. Check for
updates after each Copilot CLI upgrade or when token-reduction behavior
regresses.

**Check for upstream changes:**

```sh
# View the upstream SKILL.md
curl --silent --show-error \
  https://raw.githubusercontent.com/juliusbrussee/caveman/main/SKILL.md

# Diff against the vendored copy
diff internal/resources/olium/skills/caveman/SKILL.md \
     <(curl --silent https://raw.githubusercontent.com/juliusbrussee/caveman/main/SKILL.md)
```

**Update process** (if upstream changed):

1. Copy the new `SKILL.md` content into
   `internal/resources/olium/skills/caveman/SKILL.md`.
2. Rebuild and install:
   ```sh
   make install
   ```
   The skill is embedded at compile time via `//go:embed skills` in
   `internal/resources/olium/embed.go` — no binary re-staging needed.
3. Run a quick comparison audit to confirm token reduction still holds:
   ```sh
   vigolium agent audit --source <small-target> --mode lite \
     --agent copilot --skill caveman --stateless -S
   ```
