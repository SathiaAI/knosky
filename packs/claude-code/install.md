# Claude Code — install KnoSky MCP (P0)

Stub pack: one DEC-108 menu, honesty on Mode A/B, no npm publish required.

## 1. Prerequisites

- Node.js 20+
- This knosky tree with `mcp/server.mjs`
- City file for `KC_CITY`

```bash
cd mcp && npm install && cd ..
```

## 2. Add MCP (CLI)

Replace absolute paths:

```bash
claude mcp add knosky \
  -e KC_CITY=/ABS/PATH/TO/city-data.json \
  -e KC_PROFILE=coding \
  -- node /ABS/PATH/TO/knosky/mcp/server.mjs
```

### Equivalent JSON (Desktop / project MCP)

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

| Env | Required | Values |
| :--- | :---: | :--- |
| `KC_CITY` | yes | City index path |
| `KC_PROFILE` | no | `coding` (default) · `advisory` · `security` |
| `KC_DOMAIN` | no | Lease/audit domain root |
| `KC_ROOT` | no | Repo root for bundle scan |

## 3. Mode B lease
> **Domain must match MCP:** register into the same domain the server uses (derived from `KC_CITY` unless `KC_DOMAIN` is set). Example: `--domain "$(dirname "$KC_CITY")/.knosky"`.


```bash
node bin/knosky.mjs agent-register --domain "$(dirname "$KC_CITY")/.knosky" --agent claude-code --role coder
```

Pass **`leaseId`** into `kc_route`, `kc_policy_check`, `kc_bundle`. Payload `agentId` is never authoritative alone.

Missing lease on governed path → **`DENY_IDENTITY`**.

## 4. Tools (coding profile — SSOT)

From [`ssot/tool-menu.json`](../../ssot/tool-menu.json):

| Tier | Tools |
| :--- | :--- |
| Tier 0 map | `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related` |
| Tier 1 governed | `kc_route`, `kc_bundle`, `kc_policy_check` |
| Security only | `kc_audit_query`, `kc_audit_verify` — set `KC_PROFILE=security`; **not** default Claude Code coding pack |

## 5. Mode A vs Mode B

- **Mode A:** map / tips only; must stay labeled **`ADVISORY_UNAUTH`**. Not “authorized.”
- **Mode B:** available **now** for route / policy_check / bundle when identity + policy + audit succeed.
- **Swarm-safe:** claim only if **L3 ready**. Packs must not market L3 from L2 Mode B alone.

Ladder: [`ssot/ladder-l0-l3.md`](../../ssot/ladder-l0-l3.md).

## 6. Coexistence with CLAUDE.md / AGENTS.md

Claude Code project **`CLAUDE.md`** (and optional **`AGENTS.md`**) remain the instruction home for how *your* repo works.

Recommended one-liner in `CLAUDE.md`:

```markdown
## KnoSky
Use knosky MCP for city map + Mode B GPS (`leaseId` from `node bin/knosky.mjs agent-register`).
Tier 0 is non-authorizing. Do not claim swarm-safe unless L3 doctor green.
Tool menu SSOT: ssot/tool-menu.json
```

Do not paste a stale private tool list that diverges from SSOT.

## 7. Try prompts

- “Use kc_search for authentication decisions.”
- “kc_policy_check destination=src/auth with my leaseId.”
- “kc_route to billing policy docs with leaseId; then open the cited live files.”

## 8. Doctor

```bash
node bin/knosky.mjs doctor
```

---

Index: [`../README.md`](../README.md)
