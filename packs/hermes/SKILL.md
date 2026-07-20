---
name: knosky
description: >-
  Local-first KnoSky agentic GPS via MCP — Tier 0 map tools plus Mode B
  governed route/bundle/policy_check (DEC-108). Load when navigating a repo
  city, citing live files, or needing policy-checked routes. Not swarm-safe
  unless L3 doctor green.
---

# KnoSky (Hermes pack)

Use KnoSky as a **map + governed router**, not a body store and not a code-RAG brain. Live files stay source of truth.

## SSOT

- Tool menu: [`../../ssot/tool-menu.json`](../../ssot/tool-menu.json) (DEC-108)
- Ladder: [`../../ssot/ladder-l0-l3.md`](../../ssot/ladder-l0-l3.md) (DEC-110)
- Install: [`install.md`](./install.md)

## Mode A vs Mode B

| Mode | Meaning |
| :--- | :--- |
| **A** | Non-authorizing map / tips. Label **`ADVISORY_UNAUTH`**. Never call it authorized. |
| **B** | Identity (`leaseId`) + policy + audit receipt → `ALLOW` or safe `DENY_*`. |

**Mode B is available now** for `kc_route`, `kc_policy_check`, and `kc_bundle`.

**Do not claim swarm-safe** unless the install’s claim ceiling is **L3**. L2 Mode B ≠ multi-agent swarm coordinator.

## MCP connect (coding profile)

Point Hermes MCP at:

```text
command: node
args:    [<ABS>/mcp/server.mjs]
env:
  KC_CITY:    <ABS path to city-data.json>
  KC_PROFILE: coding          # or advisory | security
```

Optional: `KC_DOMAIN`, `KC_ROOT` (see pack README).

## Mode B lease

Before authorizing Tier 1 calls:

```bash
node bin/knosky.mjs agent-register --agent hermes-local --role coder
```

Pass returned **`leaseId`** into governed tools. Do not trust a bare `agentId` in the payload.

## Tools on this pack (`coding` profile)

From `ssot/tool-menu.json` — **no audit tools**.

### Tier 0 map

| Tool | Use |
| :--- | :--- |
| `kc_search` | Keyword / metadata search over the city index |
| `kc_get_node` | One node by id |
| `kc_list_categories` | Districts / categories |
| `kc_get_provenance` | Citation pointers to live SoT |
| `kc_related` | Neighbor / import edges |

### Tier 1 governed

| Tool | Use |
| :--- | :--- |
| `kc_route` | GPS toward a destination (Mode B default; Mode A if advisory) |
| `kc_bundle` | Share-oriented pointer bundle + fail-closed secret scan |
| `kc_policy_check` | Dry-run allow/deny without full route body |

### Not on coding pack

`kc_audit_query`, `kc_audit_verify` — arithmetic **security** profile only (`KC_PROFILE=security`).

## Suggested flow

1. `kc_search` / `kc_list_categories` — orient (map; non-authorizing).
2. `kc_policy_check` with `leaseId` — will this destination allow?
3. `kc_route` with `leaseId` — get ALLOW path + citations, then **open live files**.
4. `kc_bundle` when you need a share-safe intent manifest under the same gates.

## Coexistence

Hermes skills sit beside, not over, repo **`AGENTS.md`** / **`CLAUDE.md`**. Keep product process in those files; use this skill for KnoSky tool discipline and honesty labels only.

## Claims lint (quick)

- OK: local map, citations, governed route (when Mode B green), Mode A labeled advisory  
- Forbidden without evidence: swarm-safe, zero data risk, authorized from unlabeled advisory MCP  
