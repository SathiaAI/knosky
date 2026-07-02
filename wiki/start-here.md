# Start here — KnoSky in five minutes

> **What you will have when you are done:** an explorable map of any repo or docs folder, plus a local MCP connector so your AI assistant (Claude Code, Cursor, VS Code) can answer questions with cited pointers back to your own source.

## Requirements

- [Node.js](https://nodejs.org) 18 or later (`node --version` to check)
- A local folder or git repo you want to explore

## Option A — one command (recommended)

```bash
npx knosky .
```

That is it. KnoSky indexes the current folder, builds the city, opens it in your browser, prints the MCP config for your AI assistant, and starts the local MCP server. Point it anywhere with `npx knosky /path/to/your/repo`.

Flags: `--no-open` skips the browser launch. `--no-serve` skips the MCP server.

## Option B — clone and run

```bash
git clone https://github.com/SathiaAI/knosky
cd knosky
npm install
node bin/knosky.mjs /path/to/your/repo
```

## Connect your AI assistant (MCP)

After the city is built you can ground your AI assistant in it. KnoSky prints the exact config to paste — here is the manual version:

**Claude Code:**

```bash
claude mcp add knosky -e KC_CITY=/abs/path/city-data.json -- node /abs/path/mcp/server.mjs
```

**Claude Desktop / Cursor / VS Code** — add to your MCP config JSON:

```json
"knosky": {
  "command": "node",
  "args": ["/abs/path/to/knosky/mcp/server.mjs"],
  "env": { "KC_CITY": "/abs/path/city-data.json" }
}
```

Then ask: *"search KnoSky for where authentication is handled."*  
MCP tools exposed: `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`, `kc_route`, `kc_bundle`.

## What the city shows

| Element | What it means |
|---------|---------------|
| District | A top-level folder or category |
| Building | One file — click to open the live source |
| Road | An import or link between files |
| Glow | Recently-changed file (high churn) |

## Common first questions to ask your assistant

- *"Where does authentication live?"*
- *"What does src/core/index.mjs connect to?"*
- *"Summarise what changed in the last sprint."*

## Privacy in thirty seconds

KnoSky is **local-first**. Nothing ever leaves your machine. It indexes pointers and short excerpts (≤ 200 chars) — never your full file bodies. A fail-closed secret scan blocks the build if a credential-like value is detected.

Full details: [PRIVACY.md](../PRIVACY.md) · [SECURITY.md](../SECURITY.md) · [LIMITATIONS.md](../LIMITATIONS.md)

## Next steps

- Explore the [[Route engine]] to navigate a PR's changed files
- See [[PR-GPS]] for automated navigation comments on pull requests
- Read the [[MCP tools reference]] for all available assistant tools
