# Start here — KnoSky in five minutes

> **What you will have when you are done:** a local map of any repo or docs folder, plus a local MCP connector so your AI assistant can navigate with **cited pointers** back to live source — and, when configured for **Mode B**, **governed routes** (identity + policy + audit) instead of unlabeled guesses.

KnoSky is the **enterprise agentic GPS / route-governance protocol**; the city UI is the thin human skin (DEC-105). It is **local-first**, not a hosted multi-tenant SaaS.

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

After the city is built you can ground your AI assistant in it. KnoSky prints the exact config to paste — here is the manual version.

SSOT (must match this page + `mcp/server.mjs`): [`ssot/tool-menu.json`](../ssot/tool-menu.json) · [`ssot/decision-codes.json`](../ssot/decision-codes.json) · [`ssot/ladder-l0-l3.md`](../ssot/ladder-l0-l3.md).

**Claude Code** (coding profile — default packs):

```bash
claude mcp add knosky \
  -e KC_CITY=/abs/path/city-data.json \
  -e KC_PROFILE=coding \
  -- node /abs/path/mcp/server.mjs
```

**Claude Desktop / Cursor / VS Code / Codex** — add to your MCP config JSON:

```json
"knosky": {
  "command": "node",
  "args": ["/abs/path/to/knosky/mcp/server.mjs"],
  "env": {
    "KC_CITY": "/abs/path/city-data.json",
    "KC_PROFILE": "coding"
  }
}
```

| Profile (`KC_PROFILE`) | Audience | Includes |
| :--- | :--- | :--- |
| **coding** (default) | Hermes, Claude Code, Cursor, Codex CLI, VS Code | Tier 0 + Tier 1 |
| **security** | Operators / CI | + `kc_audit_query`, `kc_audit_verify` |
| **advisory** | Explicit non-authorizing explore | Tier 0 (+ labeled Mode A route) |

### Mode A vs Mode B

| Mode | Wire label | Use when |
| :--- | :--- | :--- |
| **Mode A** | `ADVISORY_UNAUTH` | Map tips only — **not** authorized, **not** policy-certified, **not** swarm-safe |
| **Mode B** | `ALLOW` / `DENY_*` (+ receipt on ALLOW) | Identity + policy + audit gate before authorized subgraph |

Coding packs default to **Mode B** for Tier 1 tools. Mode A must stay **explicitly labeled** (`KC_PROFILE=advisory` or `advisory=true` on `kc_route`).

### Official tool menu (DEC-108 freeze)

| Tier | Tools | Authorizing? |
| :--- | :--- | :---: |
| **Tier 0 map** | `kc_search` · `kc_get_node` · `kc_list_categories` · `kc_get_provenance` · `kc_related` | No |
| **Tier 1 governed** | `kc_route` (**dual-mode**) · `kc_bundle` · `kc_policy_check` | Yes on Mode B `ALLOW` |
| **Security only** | `kc_audit_query` · `kc_audit_verify` | Not on coding packs |

- **`kc_route`** — dual-mode GPS: Mode B ALLOW/DENY with receipt, or Mode A `ADVISORY_UNAUTH` tips.
- **`kc_bundle`** — share-oriented pointer / intent-manifest under the same gates + fail-closed secret scan (live on the MCP server).
- **`kc_policy_check`** — dry-run policy decision + reasons without a full route body preference.

**Closed decision codes:**  
`ALLOW` · `DENY` · `DENY_IDENTITY` · `DENY_POLICY` · `DENY_AUDIT` · `DENY_FRESHNESS` · `DENY_EVIDENCE` · `ERROR_INVALID_INPUT` · `ERROR_INDEX` · `ADVISORY_UNAUTH`

Then ask: *"search KnoSky for where authentication is handled"* or *"policy-check then route me to auth under Mode B."*

## Guarantee ladder (do not overclaim)

Never claim a higher level than `knosky doctor` reports for this install ([ladder SSOT](../ssot/ladder-l0-l3.md)):

| L | Name | One-line |
| :---: | :--- | :--- |
| **L0** | Local map | Navigate locally; no KnoSky upload by default |
| **L1** | Share-safe | Fail-closed secret controls on share artifacts |
| **L2** | Governed evaluator | Mode B identity + policy + audit (or safe DENY) |
| **L3** | Swarm domain | Multi-agent coordinator on Mode B |

Public honesty: Wave 1 documents **L3 swarm foundation** (coordinator + claim ceiling). Say **swarm-safe / production multi-agent GPS** only when doctor `l3_ready` is green for that domain. Windows lockdown remains **unsupported/inactive** until packaging proves otherwise — see [LIMITATIONS.md](../LIMITATIONS.md).

## What the city shows

| Element | What it means |
|---------|---------------|
| District | A top-level folder or category |
| Building | One file — click to open the live source |
| Road | An import or link between files |
| Glow | Recently-changed file (high churn) |

City = **skin**. Protocol (map tools + governed route) = **product**.

## Common first questions to ask your assistant

- *"Where does authentication live?"* (Tier 0 map)
- *"What does src/core/index.mjs connect to?"* (map / related)
- *"`kc_policy_check` then `kc_route` me to the billing decision docs"* (Mode B)
- *"Bundle a share-safe pointer set for the auth district"* (`kc_bundle`)

## Privacy & security in thirty seconds

KnoSky is **local-first**. Core path does not require a KnoSky account or always-on telemetry (DEC-114: opt-in counters default **OFF**; never always-on). It indexes **pointers and short projections** — not a body store (DEC-107). Share/export paths fail closed on secret-like values. Mode B receipts are **metadata-only**. KnoSky does **not** claim “zero data risk” — see [PRIVACY.md](../PRIVACY.md) · [SECURITY.md](../SECURITY.md) · [LIMITATIONS.md](../LIMITATIONS.md).

## Wave 1 packs (same menu)

**P0:** Hermes · Claude Code · Cursor · Codex CLI  
**P1:** VS Code MCP · Greptile recipe · GHA PR-GPS  

## Next steps

- Explore the route engine (`kc_route` Mode B) for authorized subgraph navigation
- See [[PR-GPS]] for automated navigation comments on pull requests
- Read the [[MCP tools reference]] (must render `ssot/tool-menu.json`)
- Run `knosky doctor` before claiming L2/L3 in your own docs
