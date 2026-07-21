# Codex CLI — install KnoSky MCP (P0)

Wire OpenAI Codex CLI (or compatible host) to KnoSky’s DEC-108 stdio server. Clone-local; no npm publish required for this stub.

## 1. Prerequisites

- Node.js 20+
- knosky checkout with `mcp/server.mjs` and `ssot/`
- City index path for `KC_CITY`

```bash
cd mcp && npm install && cd ..
```

## 2. Point MCP at `mcp/server.mjs`

Codex MCP configuration locations differ by version (global config vs project). Use the same env contract:

```json
{
  "mcp_servers": {
    "knosky": {
      "command": "node",
      "args": ["/ABS/PATH/TO/knosky/mcp/server.mjs"],
      "env": {
        "KC_CITY": "/ABS/PATH/TO/city-data.json",
        "KC_PROFILE": "coding"
      }
    }
  }
}
```

If your Codex build uses `mcpServers` (camelCase) instead of `mcp_servers`, keep the inner `command` / `args` / `env` block identical.

| Env | Required | Notes |
| :--- | :---: | :--- |
| `KC_CITY` | yes | Absolute city JSON path |
| `KC_PROFILE` | no | `coding` (pack default) · `advisory` · `security` |
| `KC_DOMAIN` | no | Local trust domain (leases, audit) |
| `KC_ROOT` | no | Bundle secret-scan root |

## 3. Mode B lease
> **Domain must match MCP:** register into the same domain the server uses (derived from `KC_CITY` unless `KC_DOMAIN` is set). Example: `--domain "$(dirname "$KC_CITY")/.knosky"`.
 (`knosky agent-register`)

```bash
node bin/knosky.mjs agent-register --domain "$(dirname "$KC_CITY")/.knosky" --agent codex-cli --role coder
```

Pass **`leaseId`** on:

- `kc_route`
- `kc_policy_check`
- `kc_bundle`

`agentId` in the tool payload cannot mint identity by itself.

## 4. Tools (coding profile)

SSOT: [`ssot/tool-menu.json`](../../ssot/tool-menu.json)

| Tier | Tools |
| :--- | :--- |
| 0 map (non-authorizing) | `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related` |
| 1 governed | `kc_route`, `kc_bundle`, `kc_policy_check` |
| security only | `kc_audit_query`, `kc_audit_verify` — not on coding packs |

## 5. Mode A vs Mode B

- **Mode A:** exploration / map; label **`ADVISORY_UNAUTH`**. Do not call it governed.
- **Mode B:** **available now** for route, policy_check, bundle when lease + policy + audit open the door.
- **Swarm-safe:** only when **L3** is ready per [`ssot/ladder-l0-l3.md`](../../ssot/ladder-l0-l3.md). This pack does not grant L3 by installation alone.

## 6. Coexistence with AGENTS.md

Codex often reads repo **`AGENTS.md`**. Keep product and coding rules there. Add a small KnoSky section:

```markdown
## KnoSky MCP
Map + Mode B GPS via knosky server. Register lease:
`node bin/knosky.mjs agent-register --domain "$(dirname "$KC_CITY")/.knosky" --agent codex-cli`
Tools: ssot/tool-menu.json. No swarm-safe claim unless L3 doctor green.
```

Same idea if the repo also has **`CLAUDE.md`** — tools are shared; instruction files coexist.

## 7. Verify

```bash
node bin/knosky.mjs doctor
# then from the agent: kc_list_categories, then kc_policy_check with leaseId
```

---

Index: [`../README.md`](../README.md)
