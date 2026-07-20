# Cursor — install KnoSky MCP (P0)

Point Cursor at the same `mcp/server.mjs` menu as other Wave 1 hosts (DEC-108).

## 1. Prerequisites

```bash
cd mcp && npm install && cd ..
```

Need Node 20+, `KC_CITY` city index, absolute paths in MCP config.

## 2. MCP config

Copy [`mcp.json.example`](./mcp.json.example) into your Cursor MCP settings (user or project). Typical locations depend on Cursor version (MCP settings UI or `.cursor/mcp.json`).

```json
{
  "mcpServers": {
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

| Env | Role |
| :--- | :--- |
| `KC_CITY` | **Required** city index |
| `KC_PROFILE` | `coding` · `advisory` · `security` |
| `KC_DOMAIN` | Optional domain for leases/audit |
| `KC_ROOT` | Optional root for `kc_bundle` |

Restart Cursor / reload MCP after edits.

## 3. Mode B lease

```bash
node bin/knosky.mjs agent-register --agent cursor-dev --role coder
```

Feed **`leaseId`** to governed tools. No lease → **`DENY_IDENTITY`** on Mode B path.

## 4. Tools (coding — from SSOT)

[`ssot/tool-menu.json`](../../ssot/tool-menu.json):

- **Map:** `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`
- **Governed:** `kc_route`, `kc_bundle`, `kc_policy_check`
- **Not default:** `kc_audit_*` (security profile only)

## 5. Honesty

| Claim | When OK |
| :--- | :--- |
| Local map / citations | L0+ always (Mode A labels on non-governed) |
| Governed / policy-checked route | Mode B L2 green + real ALLOW path |
| swarm-safe | **L3 ready only** — not from this pack stub alone |
| Mode B route/policy_check/bundle | **Available now** with lease |

## 6. Coexistence

Cursor rules / project docs can sit next to **`AGENTS.md`** or **`CLAUDE.md`**. KnoSky does not replace them. Add a short “use knosky MCP for GPS” note; keep the frozen menu in `ssot/`.

## 7. Doctor

```bash
node bin/knosky.mjs doctor
```

---

Index: [`../README.md`](../README.md)
