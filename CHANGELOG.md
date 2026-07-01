# Changelog

All notable changes to KnoSky. Versions are git-tagged on this repo.

## [0.5.0] - 2026-07-01 -- Route engine + PR-GPS (Protocol v1)

### Added
- **`.knosky` protocol foundation:** versioned config (`.knosky/config.yml`), `route.json` and `intent-manifest` schemas (`knosky_protocol: "1.0"`).
- **Route engine (`kc_route`):** point at a destination -- a file, a folder, an import chain, a "district" (category) -- and get a ranked, advisory route through the repo with waypoints, alternates, confidence, and caveats. Structural only: file/folder/imports/dependency-chain, never semantic/code-meaning.
- **`kc_bundle`:** builds a shareable intent-manifest (paths + sha256 + edges) with a fail-closed secret scan, for agents that need to share a scoped, verifiable file set.
- **PR-GPS:** `knosky ci` generates an advisory navigation report for a pull request's changed files. A new GitHub Action posts/updates it as a single PR comment automatically -- advisory only, never blocks or gates a build.

### Security
- Independent adversarial pass ahead of this release: fixed a symlink-escape read and an unreadable-file fail-open in the bundle engine, a git-ref option-injection in the CI report generator, plus two additional issues found during the pass. See the repo's PR history for detail.

### Notes
- Everything above is **advisory-only, metadata-only, local, no telemetry** -- KnoSky reads structure, never uploads your code, and nothing here blocks or gates a build.

## [0.4.1] - 2026-06-29 — Security review fixes

### Security
- **The fail-closed secret scan now actually fails closed.** It previously ran *after* scrubbing, so a secret in a title/heading/summary was silently redacted instead of blocking the build. It now scans the **un-scrubbed** projections before serialization and blocks (the post-scrub residual is kept as a defense-in-depth gap detector). A secret in a heading now stops the build.
- **Embedded mode is fail-closed.** The postMessage bridge now requires a non-empty `window.__KC_ALLOWED_ORIGINS` allowlist (the bridge is disabled if it is empty), only accepts messages from the embedding parent frame, and never broadcasts readiness to `"*"`.

### Added
- `test/security-fixtures.mjs` — pure-Node regression tests (secret block, ignore rules, XSS escaping, embed fail-closed). Run `node test/security-fixtures.mjs`.
- `.github/workflows/ci.yml` — runs the fixtures + `npm audit` on every PR.
- Root `package-lock.json` for reproducible `npx` / `npm ci` installs.

### Changed
- README: removed a "zero data risk" line that contradicted PRIVACY.md.

## [0.4.0] - 2026-06-29 — File Connections + churn (code-intel)

### Added
- **File Connections:** import/dependency edges drawn as roads between buildings — select a file to see what it imports and what imports it. Per-language import scan over a bounded prefix; specifiers are resolved to repo files and then discarded (file-to-file edges only).
- **Churn heat:** recently-changed files glow on the map, from `git log` (per-file commit count only).
- **MCP `kc_related`:** ask your assistant "what connects to this file?" — out-edges, in-edges, and churn, with citations.
- Flags: `--no-graph`, `--no-churn` to omit either signal.

### Notes
- Strictly **file-level metadata** (decision D-155): no symbol names, no ASTs, no code bodies, no commit messages/diffs. KnoSky maps how files connect; it does not analyze your code.

## [0.3.0] - 2026-06-29 — One-command launcher (npx)

### Added
- `npx knosky [path]` one-command launcher: indexes the folder, builds and opens the city, prints the MCP config (Claude Code / Claude Desktop / Cursor / VS Code) and suggested first prompts, then starts the local MCP server. Flags: `--no-open`, `--no-serve`. Reuses the verified indexer/renderer/MCP and inherits fail-closed `--share-safe` safety.
- Root `package.json` with a `knosky` bin and a `files` allowlist for publishing.

## [0.2.0] - 2026-06-29 — Security hardening + safe-share

### Security
- **Generated artifacts hardened against injection.** City data is embedded as inert JSON (`<script type="application/json">`) and the builder escapes `<` and U+2028/U+2029, so a repo containing `</script>` can no longer execute code in a generated city.
- **Untrusted names escaped.** District/category names, file titles, and kinds render through HTML escaping; colors are validated. A folder named `<img onerror=...>` renders as harmless text, not a live element.
- **Fail-closed secret scanning.** Expanded patterns (GitHub, OpenAI, Stripe, Google, Slack, GitLab, npm, JWT, SSH, AWS, PEM). The build now **fails closed** if a secret-like value is detected (override with `--allow-leaks`).
- **postMessage bridge gated.** Disabled in the standalone build; only active in embedded mode with an origin allowlist.

### Added
- `--share-safe` — strips the absolute root path (basename only) and prints a safety report.
- `--include-absolute-root` — opt back in to the full local path for private diagnostics.
- `SECURITY.md`, `PRIVACY.md`, `LIMITATIONS.md` — disclosure path + trust docs.

### Changed
- **Privacy default:** the generated index stores the folder **basename**, not the absolute path.
- **Ignore accuracy:** inside a git repo, git's own ignore rules are applied (`git check-ignore`); the conservative parser remains the fallback for non-git folders.
- **MCP input caps:** `kc_search` bounds query length and result count; ids are length-capped — avoids token burn and runaway output.
- Committed a lockfile for reproducible MCP installs.

## [0.1.0] - 2026-06-27 — Initial public release
- Local-first repo/folder → explorable isometric city (Kenney CC0 art).
- Local stdio MCP: `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`.
- Single-file, self-contained city HTML. FSL-1.1-MIT license.
