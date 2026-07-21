# KnoSky

*Your knowledge as a skyline.*

**Turn any repo or folder of docs into a living, explorable city — and give your AI assistant grounded, cited answers from your own source. Runs entirely on your machine. Free.**

> *Born from building [Sathia](https://sathia.ai).*

---


> **Trust model (approved wording):** KnoSky's local trust model applies the core security principles of TUF — role separation, threshold signing, survivable key compromise, and freshness-guaranteed revocation — adapted from TUF's server-oriented update distribution to a fully local, no-egress agentic environment, with attestation formats based on in-toto/DSSE.

## See it in 10 seconds

Open **[`demo/knosky-demo.html`](./demo/knosky-demo.html)** in your browser (just double-click it — it's a single self-contained file). That's a sample project rendered as a city. Now point it at your own.

---

## The problem
Your project grows faster than anyone can hold in their head. Hundreds of files, decisions, and docs across folders. A file tree tells you what files exist — not what the *system* is. So things get lost, decisions get re-litigated, and your AI assistant confidently makes things up about your own codebase.

## What you get (the outcome)

> **Measured (SAT-439, 5 tasks, naive agent vs. KnoSky-guided agent):**
> **68% fewer tokens · 70% fewer tool calls · 6× faster to the right file**
> *(All guided runs answered correctly; the naive agent found the target in 3 of 5 tasks and answered correctly in 0.)*

- **See your whole project in one screen.** Instead of scrolling a file tree, you see the *shape* of everything — which areas are big, how they connect, where the gaps are. New collaborators get oriented in minutes, not weeks.
- **Find anything in seconds.** Search the city — or ask your assistant *"where does auth live / what did we decide about billing"* — and jump straight to the **live file**.
- **Your AI answers from YOUR source, with citations.** Connect it to Claude / Cursor / VS Code / Gemini and your assistant stops guessing about your codebase — it cites the real file, every time.
- **Zero setup tax, local-first by default.** Point it at a folder → a city in under a minute. Deterministic, **$0 tokens** to keep fresh, **nothing ever leaves your machine**, and a fail-closed secret scan before you share. (KnoSky does not claim "zero data risk" — see [PRIVACY.md](./PRIVACY.md).)

**Net:** faster comprehension, reliable recall of your own knowledge, and a grounded AI — without giving up privacy or paying a cent.

## Who it's for
Developers, founders, and architects sitting on a sprawling repo or knowledge base who want to *understand and navigate their own work fast* — and want their AI assistant grounded in it — without uploading anything.

---

## How it works

**Quickstart — one command:**
```bash
npx knosky .
```
Indexes the current folder, opens the city, prints the MCP config for your AI assistant (Claude Code / Claude Desktop / Cursor / VS Code) plus a few starter prompts, and starts the local connector. Point it anywhere with `npx knosky /path/to/your/repo`. Flags: `--no-open`, `--no-serve`.

Prefer a clone? `git clone https://github.com/SathiaAI/knosky && cd knosky && npm install && node bin/knosky.mjs .`

Want the individual pieces instead? Read on.

**Requirements:** [Node.js](https://nodejs.org) 18+.

**1. Build your city from a folder or repo**
```bash
node core/fs-indexer.mjs --root /path/to/your/repo --out city-data.json --share-safe
node renderer/build-rich.mjs city-data.json city.html
```
Open `city.html`. Every top-level folder is a **district**, every file a **building**, every building links to the real source.

**Flags:** `--share-safe` strips your absolute path (basename only) and prints a safety report — and the build **fails closed** if a secret-like value is detected. `--redact AcmeCorp,SecretProject` masks (and skips files matching) project-specific terms. `--include-absolute-root` keeps the full local path (private diagnostics only). `--allow-leaks` overrides the secret block (not recommended).

**2. Connect it to your AI assistant (MCP)** — DEC-108 menu

SSOT: [`ssot/tool-menu.json`](./ssot/tool-menu.json) · decision codes: [`ssot/decision-codes.json`](./ssot/decision-codes.json) · ladder: [`ssot/ladder-l0-l3.md`](./ssot/ladder-l0-l3.md). README = wiki = binary for tool names (AR-03).

```bash
cd mcp && npm install && cd ..
# Claude Code (coding profile — default packs):
claude mcp add knosky -e KC_CITY=/abs/path/city-data.json -e KC_PROFILE=coding -- node /abs/path/mcp/server.mjs
```
Or add to your Claude Desktop / Cursor / VS Code / Codex MCP config:
```json
"knosky": {
  "command": "node",
  "args": ["/abs/path/mcp/server.mjs"],
  "env": {
    "KC_CITY": "/abs/path/city-data.json",
    "KC_PROFILE": "coding"
  }
}
```

| Profile (`KC_PROFILE`) | What it is for | Tools |
| :--- | :--- | :--- |
| **coding** (default packs) | Hermes, Claude Code, Cursor, Codex CLI, VS Code | Tier 0 map + Tier 1 governed |
| **security** | Operators / CI verify | Coding tools + `kc_audit_query`, `kc_audit_verify` |
| **advisory** | Explicit non-authorizing explore | Tier 0 map (+ labeled Mode A `kc_route`) |

**Mode A vs Mode B (DEC-106 / DEC-108)**

| Mode | Label on the wire | Meaning |
| :--- | :--- | :--- |
| **Mode A** | `ADVISORY_UNAUTH` | Non-authorizing map / tips. Not policy-certified, not swarm-safe. |
| **Mode B** | `ALLOW` or `DENY_*` (+ receipt on ALLOW) | Governed: identity + policy + audit before any authorized claim. |

Default coding profile uses **Mode B** for governed tools. Mode A is available via `KC_PROFILE=advisory` or `advisory=true` on dual-mode `kc_route` — always labeled; never market it as governed.

**Official tool menu (freeze)**

| Tier | Tools | Authorizing? |
| :--- | :--- | :---: |
| **Tier 0 map** | `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related` | No (map only) |
| **Tier 1 governed** | `kc_route` (**dual-mode**), `kc_bundle`, `kc_policy_check` | Yes when Mode B `ALLOW` |
| **Security profile only** | `kc_audit_query`, `kc_audit_verify` | Audit verify — not on coding packs |

- **`kc_route`** — GPS toward a destination. Mode B: `ALLOW` / `DENY_*` with audit receipt; Mode A: labeled `ADVISORY_UNAUTH` tips only.
- **`kc_bundle`** — Share-oriented pointer / intent-manifest under the same gates + fail-closed secret scan.
- **`kc_policy_check`** — Dry-run policy decision + reasons without preferring a full route body.

**Closed decision codes** (no open strings on the wire):  
`ALLOW` · `DENY` · `DENY_IDENTITY` · `DENY_POLICY` · `DENY_AUDIT` · `DENY_FRESHNESS` · `DENY_EVIDENCE` · `ERROR_INVALID_INPUT` · `ERROR_INDEX` · `ADVISORY_UNAUTH`

Then ask: *"search KnoSky for what we decided about authentication"* or *"route me to the auth policy under Mode B."*

**Guarantee ladder (honest claims — DEC-110)** — never claim higher than `knosky doctor` for this install:

| L | Name | Promise |
| :---: | :--- | :--- |
| **L0** | Local map | Index + navigate locally; no KnoSky upload by default |
| **L1** | Share-safe | Fail-closed secret controls before share artifacts |
| **L2** | Governed evaluator | Mode B identity + policy + audit (or safe DENY) |
| **L3** | Swarm domain | Multi-agent coordinator on Mode B (leases/quotas/…) |

Wave 1 ships **L0–L2 paths** and an **L3 coordinator foundation** (local modules + `doctor` claim ceiling only — not “L3 ready at every install”). Do **not** treat marketing copy as “production swarm-safe at every install” until `doctor` reports `l3_ready` for that domain. Windows kernel lockdown is **unsupported/inactive** until packaging proves otherwise — see [LIMITATIONS.md](./LIMITATIONS.md).

**Packs (Wave 1)** — same DEC-108 menu: P0 Hermes · Claude Code · Cursor · Codex CLI · P1 VS Code MCP · Greptile recipe · GHA PR-GPS. Audit tools stay off coding packs.

**See how your code connects.** Select a file in the city to see its **connections** (roads to the files it imports / that import it) and **churn** (recently-changed files glow). Or ask your assistant *"what connects to src/auth.js?"* — file-level structure only, not code analysis.

**3. Get PR navigation comments automatically (GitHub Action — PR-GPS)**

Add this to any workflow that runs on pull requests:

```yaml
- name: Check out the repo (full history so the diff works)
  uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: KnoSky PR-GPS
  uses: SathiaAI/knosky@v0.5.0
  with:
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
```

The action posts (and updates) a single advisory comment on the PR listing which files changed, suggested review starting points, and related tests/docs. It reads file/folder/import structure only — never uploads code bodies — and **never blocks or gates the build**. The `github-token` input defaults to the workflow token; a `fail-on-secret` guard is available for stricter CI setups (see [`action.yml`](./action.yml) for all inputs).

---

## What it is **not** (on purpose)
- **Not a code-RAG engine.** It won't read your whole codebase and answer deep questions. It's a **map and a router** — it tells you *where* things are and hands you (or your AI) the source. (Reach for Cursor/Glean for deep code Q&A.)
- **Not a cloud service.** No upload, no account, nothing leaves your machine. (A hosted option may come later.)
- **Not a copy of your knowledge.** A navigable **index of pointers** — titles, headings, short excerpts that link back to the live file — never your full file contents.

## Privacy & safety
- Runs locally; your source never leaves your machine.
- Indexes pointers + light projections (title, headings, ~200-char excerpt, tags) — **never full file bodies**.
- Skips `.git`, `node_modules`, `secrets/`, `keys/`, `.env*`, plus your `.gitignore`/`.kcignore` (git's own ignore rules apply inside a repo).
- Scrubs common secret/PII patterns and **fails the build closed** if a secret-like value is detected. Build with **`--share-safe`** for a safety report before sharing.
- Generated cities embed your data as inert JSON and escape untrusted file/folder names — opening or sharing a city won't execute injected code.

More: **[PRIVACY.md](./PRIVACY.md)** · **[LIMITATIONS.md](./LIMITATIONS.md)** · **[SECURITY.md](./SECURITY.md)** · **[CHANGELOG.md](./CHANGELOG.md)** · **[How KnoSky compares](./wiki/comparison.md)**

## License & credits
Free to use under the **[Functional Source License (FSL-1.1-MIT)](./LICENSE.md)** — use it freely; you just can't repackage it as a competing product. Converts to MIT two years after each release. "KnoSky" is a trademark of the author.

City artwork is **[Kenney](https://kenney.nl)** (CC0 / public domain) — see [CREDITS.md](./CREDITS.md).
