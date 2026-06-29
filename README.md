# KnoSky

*Your knowledge as a skyline.*

**Turn any repo or folder of docs into a living, explorable city — and give your AI assistant grounded, cited answers from your own source. Runs entirely on your machine. Free.**

> *Born from building [Sathia](https://sathia.ai).*

---

## See it in 10 seconds

Open **[`demo/knosky-demo.html`](./demo/knosky-demo.html)** in your browser (just double-click it — it's a single self-contained file). That's a sample project rendered as a city. Now point it at your own.

---

## The problem
Your project grows faster than anyone can hold in their head. Hundreds of files, decisions, and docs across folders. A file tree tells you what files exist — not what the *system* is. So things get lost, decisions get re-litigated, and your AI assistant confidently makes things up about your own codebase.

## What you get (the outcome)
- **See your whole project in one screen.** Instead of scrolling a file tree, you see the *shape* of everything — which areas are big, how they connect, where the gaps are. New collaborators get oriented in minutes, not weeks.
- **Find anything in seconds.** Search the city — or ask your assistant *"where does auth live / what did we decide about billing"* — and jump straight to the **live file**.
- **Your AI answers from YOUR source, with citations.** Connect it to Claude / Cursor / VS Code / Gemini and your assistant stops guessing about your codebase — it cites the real file, every time.
- **Zero setup tax, zero data risk.** Point it at a folder → a city in under a minute. Deterministic, **$0 tokens** to keep fresh, and **nothing ever leaves your machine.**

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

**2. Connect it to your AI assistant (MCP)**
```bash
cd mcp && npm install && cd ..
# Claude Code:
claude mcp add knosky -e KC_CITY=/abs/path/city-data.json -- node /abs/path/mcp/server.mjs
```
Or add to your Claude Desktop / Cursor / VS Code MCP config:
```json
"knosky": {
  "command": "node",
  "args": ["/abs/path/mcp/server.mjs"],
  "env": { "KC_CITY": "/abs/path/city-data.json" }
}
```
Then ask: *"search KnoSky for what we decided about authentication."* Read-only tools exposed: `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`.

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

More: **[PRIVACY.md](./PRIVACY.md)** · **[LIMITATIONS.md](./LIMITATIONS.md)** · **[SECURITY.md](./SECURITY.md)** · **[CHANGELOG.md](./CHANGELOG.md)**

## License & credits
Free to use under the **[Functional Source License (FSL-1.1-MIT)](./LICENSE.md)** — use it freely; you just can't repackage it as a competing product. Converts to MIT two years after each release. "KnoSky" is a trademark of the author.

City artwork is **[Kenney](https://kenney.nl)** (CC0 / public domain) — see [CREDITS.md](./CREDITS.md).
