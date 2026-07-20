# KnoSky consumer packs (Wave 1)

Install KnoSky into agent hosts and PR neighbors from **one frozen tool menu**.

| SSOT (source of truth) | Path |
| :--- | :--- |
| Tool menu (DEC-108) | [`ssot/tool-menu.json`](../ssot/tool-menu.json) |
| Decision codes | [`ssot/decision-codes.json`](../ssot/decision-codes.json) |
| Guarantee ladder L0–L3 (DEC-110) | [`ssot/ladder-l0-l3.md`](../ssot/ladder-l0-l3.md) |
| MCP server | [`mcp/server.mjs`](../mcp/server.mjs) |

If README / wiki / site / pack text drifts from those files, **the SSOT wins**. Fix the copy; do not invent extra tools.

---

## Mode A vs Mode B (honesty first)

| | **Mode A — advisory** | **Mode B — governed** |
| :--- | :--- | :--- |
| What it is | Map / navigation tips only | Identity + policy + audit receipt, then `ALLOW` or safe `DENY_*` |
| When | Explicit exploration; `KC_PROFILE=advisory` or `advisory=true` on dual-mode tools | Default for coding/security packs on Tier 1 tools |
| Label | Responses must carry **`ADVISORY_UNAUTH`** (non-authorizing) | Decision codes from `decision-codes.json` |
| You may say | “local map”, “citations”, “where to look” | “governed route”, “policy-checked”, “audit-backed” **when doctor / install is L2 green** |
| You must **not** say | “authorized”, “policy-enforced”, “swarm-safe” | “swarm-safe” unless **L3 ready** (`knosky doctor` / ladder) |

**Available now for packs**

- **Tier 0 map** (Mode A labels): `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`
- **Tier 1 governed** (Mode B with `leaseId`): `kc_route`, `kc_bundle`, `kc_policy_check`
- **Security profile only**: `kc_audit_query`, `kc_audit_verify` — **not** on default coding packs

**Not claimed here:** full multi-agent **swarm-safe** coordination. That is **L3**. Mode B (L2) is the governed front door for route / policy_check / bundle today. Do not market “swarm-safe” until L3 is green.

---

## Pack matrix (DEC-108 / DEC-112)

### P0 — ship first (same launch as P1; execution order only)

| Pack | Folder | Default profile |
| :--- | :--- | :--- |
| Hermes | [`hermes/`](./hermes/) | `coding` |
| Claude Code | [`claude-code/`](./claude-code/) | `coding` |
| Cursor | [`cursor/`](./cursor/) | `coding` |
| Codex CLI | [`codex/`](./codex/) | `coding` |

### P1 — same launch, next in line

| Pack | Folder |
| :--- | :--- |
| VS Code / MCP | [`p1/vscode/`](./p1/vscode/) |
| Greptile recipe | [`p1/greptile-recipe.md`](./p1/greptile-recipe.md) |
| GHA PR-GPS | [`p1/gha-pr-gps.md`](./p1/gha-pr-gps.md) |

Default pack profile = **`coding`**. Coding packs must **not** include audit tools.

---

## Common MCP shape

Every host points stdio MCP at the repo’s `mcp/server.mjs` with at least:

```json
{
  "command": "node",
  "args": ["/ABS/PATH/TO/knosky/mcp/server.mjs"],
  "env": {
    "KC_CITY": "/ABS/PATH/TO/city-data.json",
    "KC_PROFILE": "coding"
  }
}
```

| Env | Required | Values / notes |
| :--- | :---: | :--- |
| `KC_CITY` | yes | Path to city index JSON (`city-data.json` / `city-data.v2.json`) |
| `KC_PROFILE` | no | `coding` (default) · `advisory` · `security` |
| `KC_DOMAIN` | no | Local trust domain root (leases / audit); defaults from domain resolver |
| `KC_ROOT` | no | Repo root for bundle secret scan |

Install MCP deps once: `cd mcp && npm install`.

### Mode B lease (required for authorizing Tier 1 calls)

```bash
node bin/knosky.mjs agent-register --agent my-agent-id --role coder
```

Output includes `leaseId`. Pass that `leaseId` into `kc_route` / `kc_policy_check` / `kc_bundle`. Payload `agentId` alone is never trusted.

Without a valid lease (and not on advisory path) → expect **`DENY_IDENTITY`**.

---

## DEC-108 tools (from SSOT)

### Tier 0 — map (non-authorizing)

| Tool | Summary |
| :--- | :--- |
| `kc_search` | Search map nodes by text/metadata |
| `kc_get_node` | Fetch one node projection by id |
| `kc_list_categories` | List category/district entries |
| `kc_get_provenance` | Provenance pointers (live SoT refs) |
| `kc_related` | Related nodes via map edges |

### Tier 1 — governed (Mode B for ALLOW)

| Tool | Summary |
| :--- | :--- |
| `kc_route` | GPS route; Mode B ALLOW/DENY_* + receipt, or labeled Mode A |
| `kc_bundle` | Share-oriented intent bundle; gates + fail-closed secret scan |
| `kc_policy_check` | Dry-run policy decision without full route body |

### Security profile only

| Tool | Summary |
| :--- | :--- |
| `kc_audit_query` | Query local audit events (metadata-only) |
| `kc_audit_verify` | Verify audit chain / receipt integrity |

Full definitions: [`ssot/tool-menu.json`](../ssot/tool-menu.json).

---

## Coexistence with AGENTS.md / CLAUDE.md

KnoSky packs **add MCP tools and optional skill text**. They do **not** replace:

- repo root **`AGENTS.md`** (or contributor agent guide)
- **`CLAUDE.md`** / Claude project instructions
- other host rules (Cursor rules, Codex `AGENTS.md`, Hermes skills)

**Practice:** keep host instruction files as the product/workflow brain; point them at KnoSky for **map + governed GPS**. Prefer short “how to call KnoSky” sections over duplicating the whole tool menu (menu lives in `ssot/`).

---

## Honesty checklist for pack authors

1. Point MCP at `mcp/server.mjs` + real `KC_CITY`.
2. Document `knosky agent-register` → `leaseId` for Mode B.
3. List tools **only** from `ssot/tool-menu.json` for the pack profile.
4. Never claim **swarm-safe** unless L3 ready; Mode B is OK for route/policy_check/bundle now.
5. Note coexistence with `AGENTS.md` / `CLAUDE.md`.
6. No npm publish required to try packs from a clone.

---

*Wave 1 consumer packs — stubs aligned to DEC-108 SSOT. Not a multi-tenant SaaS surface.*
