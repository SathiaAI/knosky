# Greptile recipe — KnoSky (P1 stub)

**Not** a rebuild of Greptile. Contract/recipe only: how a PR neighbor can call KnoSky map + Mode B checks beside existing review bots.

## Intent

- Give reviewers agentic GPS **context** (where changed files sit; related tests/docs).
- Optional Mode B `kc_policy_check` / `kc_route` under local trust domain — never market as multi-tenant SaaS isolation.
- Reuse DEC-108 tools only ([`ssot/tool-menu.json`](../../ssot/tool-menu.json)).

## Hook sketch

1. Build or load city for the PR head (`KC_CITY`).
2. Optional: `node bin/knosky.mjs agent-register --agent greptile-bot --role reviewer` → `leaseId`.
3. For each changed path: `kc_related` / `kc_get_provenance` (map); `kc_policy_check` if governance required.
4. Post **advisory** review notes with citations to live paths. Do not claim swarm-safe unless L3 doctor green.

## Mode honesty

| Mode | Greptile use |
| :--- | :--- |
| A | Non-authorizing map blurbs; label advisory |
| B | Available **now** for route / policy_check / bundle with lease + policy + audit |

## Coexistence

Greptile stays the reviewer. KnoSky is GPS/policy side-car. Repo **`AGENTS.md`** / PR templates can mention both without merge-conflicting tool lists — SSOT is `ssot/`.

## Out of scope (this stub)

- Shipping a Greptile marketplace app
- Replacing CodeRabbit/Qodo
- Live kube multi-tenant swarm

Index: [`../README.md`](../README.md)
