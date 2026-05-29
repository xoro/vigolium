# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.17-beta] - 2026-05-29

Expand XSS detection with additive modules that sit alongside the existing scanners rather than changing them. The WAF-aware evasion and encoding-payload work takes inspiration from [dalfox](https://github.com/hahwul/dalfox).

### XSS

- **Stored XSS (`xss-stored`)** — browser-confirmed persistent XSS: writes a unique canary, re-fetches the page with a clean request, and only reports when the canary both persists and executes, distinguishing stored from reflected.
- **DOM-XSS taint (`dom-xss-taint`)** — passive AST taint analysis that raises a finding only when a DOM-controlled source (`location.hash`, `document.cookie`, …) provably flows into a dangerous sink (`innerHTML`, `eval`, …), complementing the pattern-based `dom-xss-detect`.
- **Pre-encoded injection (`xss-light-encoded`)** — targets filters that decode a parameter (base64 / double-URL) before reflecting it.
- **WAF-aware evasion** — a per-host `WAFRegistry` lets modules publish the detected WAF/CDN so later insertion points reuse it, and a package-level `waf.ClassifyParts` helper classifies blocks from raw response primitives. Inspired by dalfox's WAF handling.
- **Encoding payloads** — `pkg/modules/infra/xssencode` supplies execution-preserving payload mutators and an encoding ladder for bypassing filters. Inspired by dalfox's evasion payloads.

### jsscan

- Add axios and custom-protocol request-pattern extraction.
- Surface DOM-XSS source→sink taint flows (`dom_flows`) in scanner output.
- Add `linux/arm64` / `darwin/amd64` correlation testdata.

### Audit

- vigolium-audit no longer forces a hardcoded per-platform model and reasoning effort; it now inherits the agent runtime's own configured default unless `--model` or `VIGOLIUM_AUDIT_MODEL` is set explicitly.

## [v0.1.16-beta] - 2026-05-28

Fix cross-platform release packaging for embedded helper binaries: GoReleaser, snapshot, release, public-release, and Docker builds now stage the matching `vigolium-audit` blob per target, run cross-builds sequentially where the shared go:embed path would otherwise race, and restore the host blob afterward so local builds do not inherit the last release target. Add runtime and npm packaging guards that detect wrong-platform embedded audit blobs before users hit opaque exec-format failures. Also add missing `jsscan` embeds for `linux/arm64` and `darwin/amd64`, with coverage tests to ensure every shipped release target has a real scanner binary instead of the unsupported stub.

## [v0.1.15-beta] - 2026-05-28

Make `--format jsonl` emit the same post-scan, project-scoped `{"type":...,"data":...}` envelope as `vigolium export` (instead of the live nuclei-style stream) across scan, scan-url phase mode, and stateless runs; default stateless multi-target scans (`-S -T file`) to a single unified output file with new `--split-by-host` to opt into per-host files; surface timed-out modules in the scan status line (`X/Y (A active, P passive, T timed out)`); make failed scans exit non-zero and skip the "completed" banner instead of logging at INFO; accept `--session`/`--session-file` as aliases for `--auth`/`--auth-file`; and fold phases, intensities, and agent modes into `vigolium strategy` (dropping the `ls` subcommand).

## [v0.1.14-beta] - 2026-05-25

Publish multi-arch Docker images: `make docker-publish` now builds and pushes both `linux/amd64` and `linux/arm64` (override via `DOCKER_PLATFORMS`) as a single manifest using `docker buildx`.

## [v0.1.13-beta] - 2026-05-24

Make `--scanning-max-duration` cap total scan wall-clock time (all phases combined), widen severities to all levels for single-phase known-issue-scan runs, and add `cve`/`kis`/`known-issues` phase aliases.

## [v0.1.12-beta] - 2026-05-24

Bound the known-issue-scan phase to its `max_duration` and default it to critical+high severities.

## [v0.1.11-beta] - 2026-05-24

Initial release of Vigolium open source.
