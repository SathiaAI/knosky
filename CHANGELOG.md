# Changelog

All notable changes to KnoSky. Versions are git-tagged on this repo.

## [0.8.0] — Enterprise / Regulated path (opt-in)

### Added
- **Enterprise / Regulated Mode** (`knosky enterprise .` / `knosky regulated .`): named opt-in
  profile with safer defaults — local-first, share-safe indexing, fail-closed on secret-like
  values — that writes a **security report** (`.knosky/security-report.json` + `security-summary.md`)
  and an **MCP capability matrix** (map read-only tools vs Mode B vs forbidden write/run).
- **Audit bundle** (`knosky audit pack` / `knosky audit verify <dir>`): portable evidence folder a
  reviewer can re-run without the author present — config, ignores, hashes, tool manifest,
  provenance, security report. `audit verify` re-checks integrity and reports `PASS`/`FAIL`.
- **Read-only map guarantee** (`docs/READ_ONLY_GUARANTEE.md`): documents and tests that map tools
  (`kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`) never write,
  execute, or read outside the indexed root; Mode B stays a separate governed lane.
- **Architecture intelligence** (`knosky intel .`): local district hangboard — documentation,
  ownership (CODEOWNERS-aware), test-adjacency, churn, drift-vs-prior, and risk scores. Local
  proxies for pilots; not a full static-analysis/CVE product; nothing uploaded.
- **Private synthetic adversarial gauntlet** (`knosky adversarial list` / `run`): disposable
  synthetic hosts (never customer data) across 8 attack classes — secrets, ignore rules, path
  disclosure, MCP traversal, prompt injection, stale citation, symlink escape, hostile scale —
  with attacker/probe/reviewer roles and a rollup report. **Private by default**; not a public
  "attack-tested" claim.

### Security
- **LLM reviewer is no-egress by default.** The optional model-backed reviewer makes an outbound
  call only when all three hold: the `--llm` flag, `KS_ADV_LLM` env opt-in, and a present API key.
  A key or env var alone never triggers a network call; default `adversarial run` is fully local.
- Synthetic credential fixtures are assembled at runtime (base64) so no credential-shaped literal
  ships in source.

### Docs
- README rewritten to lead with value/outcomes (efficiency, risk averted, cost) and the Enterprise
  path; claim-honesty preserved (L3 = coordinator **foundation**, Windows egress caveat, single
  operator lease-revoke risk, private-gauntlet not public by default).

## [Unreleased] — F0.5 OS-level network lockdown for the evaluator process

### Security
- **F0.5 network lockdown (SAT-549):** the evaluator process can now be placed in an OS-level
  network sandbox that structurally denies non-loopback network syscalls at the kernel level —
  defense-in-depth beyond the existing static no-egress import lint (F1 Fix 7, which stays as a
  cheap first-line check).
  - **Linux:** unprivileged user+network namespace via `unshare --user --net`.  The kernel-level
    routing table inside the namespace has no external routes; all TCP/UDP attempts to non-loopback
    addresses return ENETUNREACH immediately.  Unix-domain sockets (used by F0.4/SO_PEERCRED IPC)
    are unaffected.
  - **macOS:** `sandbox-exec(1)` with a minimal SBPL profile that denies outbound network and
    permits loopback and Unix sockets.  Full App Sandbox requires packaging-time entitlements;
    `knosky doctor` reports availability.
  - **Windows:** WFP/AppContainer is a packaging-time concern; `knosky doctor` detects whether
    the current process is running inside an AppContainer and reports plainly if not.
  - **F0.4-survives-sandbox conformance:** SO_PEERCRED (Unix-domain socket IPC) is verified to
    work correctly inside the Linux net namespace — no carve-out needed, no general sandbox
    loosening required.
- **`knosky doctor` subcommand:** new `knosky doctor` command surfaces the F0.5 sandbox status
  (active / available-but-not-running / unsupported-with-reason) so operators can confirm the
  lockdown is in effect rather than silently proceeding without it.

### Notes
- `core/net-lockdown.mjs` exports `probeNetworkLockdownSupport()`, `wrapArgsForLockdown()`, and
  `doctorLines()` — pure stdlib, no new dependencies.
- The static no-egress import lint (F1 Fix 7) is unchanged; F0.5 is an additional OS-level layer,
  not a replacement.

## [0.6.3] - 2026-07-04 -- Zoomed-out view redesigned as a clean city silhouette

### Changed
- **Default zoomed-out view:** replaced the per-district badge overview added in 0.6.1/0.6.2 with a single flat-green city silhouette -- closer to viewing a map/globe from far out than a dashboard of counters. District and building detail now appears once you zoom in or select a district, which is also when the underlying ground/building geometry renders.

### Fixed
- **Missing island surface:** the isometric island's top face was never filled at any zoom level -- only its two side walls and an edge outline were drawn. This is also the root cause of earlier reports that the zoomed-out view showed "just an outline."

### Notes
- No change to indexing, protocol, or trust-root behavior.

## [0.6.2] - 2026-07-03 -- District badges and building markers were rendering at sub-pixel size

### Fixed
- **Invisible zoomed-out markers:** district badges (added in 0.6.1) and individual building dots at the next zoom level in were both sized in world units that get scaled down by the camera's own zoom factor. At the very low zoom values those two tiers are designed for, this shrank every badge and dot to about a pixel or less -- present in the data, invisible on screen. Both were made a constant, readable size on screen regardless of zoom (superseded by the 0.6.3 redesign above for the district-badge tier).

### Notes
- No change to indexing, protocol, or trust-root behavior.

## [0.6.1] - 2026-07-03 -- District overview badges were never rendering

### Fixed
- **Zoomed-out district badges:** the renderer computed a per-district "cluster badge" overview for the fully-zoomed-out view, but the function that populates it was never actually called, so zooming all the way out showed nothing but the map's outline. Badges populated correctly after this fix (superseded by the 0.6.3 redesign above).

### Notes
- No change to indexing, protocol, or trust-root behavior.

## [0.6.0] - 2026-07-02 -- Trust-root hardening, rendering at scale, adversarial red-team suite

### Added
- **Rendering engine at scale:** level-of-detail rendering, clustering, virtualization, and streaming for large single-repo graphs; a cross-repo graph concept and rendering for multi-repo sets.
- **Adversarial red-team suite:** a full pass across four categories -- indexer/artifact safety, local trust root, rendering engine, protocol/schema -- now wired into CI as a required check on every PR, and into the release workflow as a hard gate before any `npm publish`. Findings, fixes, and accepted limitations are published in [RED-TEAM.md](RED-TEAM.md).
- **Conditional publish gate:** the release workflow now runs the complete test suite (including the full red-team suite) before publishing; any failure blocks the release rather than proceeding silently.
- **Real-world validation:** indexing and rendering validated at scale against a large real monorepo and a real 4-repo linked set with genuine cross-repo dependencies, plus an adversarial case with deliberately stale/conflicting policy data.
- **Measurement infrastructure (advisory, offline, no telemetry):** a naive-vs-KnoSky-guided agent comparison protocol, and a harness to run the same benchmark simultaneously across multiple model families for independent comparison.
- **Protocol Adoption Kit:** a start-here doc, a machine-readable protocol spec with schemas, a model-agnostic onboarding contract, and GitHub Action packaging reusing the PR-GPS pattern.
- Comparison page and additional launch documentation under `wiki/`.

### Security
- **Trust-root hardening (Hardening Addendum 2):** full key rotation/revocation lifecycle. Two quorum-math edge cases are identified, fixed where fixable, and explicitly documented rather than hidden: the N=2 degenerate case (mathematically unavoidable at N=2 -- maintain N>=3 for real threshold protection) and the M=0 sole-remaining-key self-revocation case (an intentional design choice -- see SECURITY.md). The ledger high-water-mark guard is now correctly consumed by the freshness-attestation check it was built to protect.
- **CI hardening:** a new AI-assisted security review runs on every pull request alongside the existing gitleaks secret scan.

### Changed
- Public wording on the local trust model's TUF-evolution is now locked to the reviewed sentence across docs/README/site copy.

### Notes
- Everything above remains **local-first, no telemetry, no hosted backend** -- nothing in this release changes that.

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
