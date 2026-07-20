# Hermes — install KnoSky MCP (P0)

Plain-English stub for pointing Hermes at KnoSky’s DEC-108 menu. No npm publish required.

## 1. Prerequisites

- Node.js 20+ (see root `package.json` engines)
- Clone of this repo (or install layout with `mcp/server.mjs` + `ssot/`)
- A city index JSON (`KC_CITY`)

```bash
# from knosky repo root
cd mcp && npm install && cd ..
# build a city if you do not have one yet (example)
node core/fs-indexer.mjs --root /path/to/your/repo --out /path/to/city-data.json --share-safe
```

## 2. Point MCP at `mcp/server.mjs`

Register a stdio MCP server named `knosky` (Hermes MCP config shape may vary by version — same env contract everywhere):

```json
{
  "knosky": {
    "command": "node",
    "args": ["/ABS/PATH/TO/knosky/mcp/server.mjs"],
    "env": {
      "KC_CITY": "/ABS/PATH/TO/city-data.json",
      "KC_PROFILE": "coding"
    }
  }
}
```

| Env | Notes |
| :--- | :--- |
| `KC_CITY` | **Required.** Absolute path to city index. |
| `KC_PROFILE` | `coding` (default pack) · `advisory` · `security` |
| `KC_DOMAIN` | Optional local trust domain for leases/audit |
| `KC_ROOT` | Optional repo root for `kc_bundle` secret scan |

### Profiles (honest)

- **coding** — Tier 0 + Tier 1. Default for this pack. **No** audit tools.
- **advisory** — map-oriented; Mode A labels required; not governed marketing.
- **security** — coding tools **plus** `kc_audit_query` / `kc_audit_verify`.

## 3. Mode B lease (`agent-register`)

Governed Tier 1 calls need a server-issued lease:

```bash
node bin/knosky.mjs agent-register --agent hermes-local --role coder
```

Use the JSON **`leaseId`** on `kc_route`, `kc_policy_check`, and `kc_bundle`.

Without it (non-advisory): expect **`DENY_IDENTITY`**.

Hint from CLI: *Pass leaseId to kc_route / kc_policy_check / kc_bundle (Mode B).*

## 4. Tools (DEC-108 SSOT — coding)

Source: [`ssot/tool-menu.json`](../../ssot/tool-menu.json).

**Tier 0 map:** `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`

**Tier 1 governed:** `kc_route`, `kc_bundle`, `kc_policy_check`

**Not on coding:** `kc_audit_query`, `kc_audit_verify`

## 5. Skill file

Optional Hermes skill copy: [`SKILL.md`](./SKILL.md). Install into your Hermes skills tree if you use skill packs; MCP still does the real work.

## 6. Mode A vs Mode B

| | A | B |
| :--- | :--- | :--- |
| Use | Labeled map / tips | Authorizing GPS + bundle + policy dry-run |
| Wire | `ADVISORY_UNAUTH` | `ALLOW` / `DENY_*` + receipt |
| Now | Yes | **Yes** for route / policy_check / source-safe bundle |

**Never claim swarm-safe** unless L3 ready (see [`ssot/ladder-l0-l3.md`](../../ssot/ladder-l0-l3.md)). Mode B ≠ swarm coordinator.

## 7. Coexistence

Keep **`AGENTS.md`** / **`CLAUDE.md`** (and Hermes global skills) for workflow. Add a short pointer: “repo map + governed GPS via KnoSky MCP.” Do not fork the tool menu into every instruction file — bind to `ssot/`.

## 8. Sanity check

```bash
node bin/knosky.mjs doctor
```

Claim language must stay ≤ doctor / ladder ceiling. Restart Hermes after MCP config changes.

---

Index: [`../README.md`](../README.md)
