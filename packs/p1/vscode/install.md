# VS Code / MCP — KnoSky pack (P1 stub)

Wave 1 P1 host. Same DEC-108 menu as P0; execution order only (not a separate product).

## MCP

```json
{
  "servers": {
    "knosky": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp/server.mjs"],
      "env": {
        "KC_CITY": "${workspaceFolder}/city-data.json",
        "KC_PROFILE": "coding"
      }
    }
  }
}
```

Adjust key names to your VS Code MCP extension (`servers` vs `mcp.servers`). Always: **`node` + `mcp/server.mjs` + `KC_CITY` + optional `KC_PROFILE`**.

Profiles: `coding` | `advisory` | `security`.

## Mode B

```bash
node bin/knosky.mjs agent-register --agent vscode-mcp --role coder
```

Pass `leaseId` to `kc_route` / `kc_policy_check` / `kc_bundle`.

## Tools (coding)

From [`ssot/tool-menu.json`](../../../ssot/tool-menu.json):  
`kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`, `kc_route`, `kc_bundle`, `kc_policy_check`.  
No audit tools on coding. No **swarm-safe** claim unless L3 ready. Mode B path available now for Tier 1.

## Coexistence

Does not replace **`AGENTS.md`** / **`CLAUDE.md`**. Point them at MCP; keep SSOT for the menu.

Full index: [`../../README.md`](../../README.md)
