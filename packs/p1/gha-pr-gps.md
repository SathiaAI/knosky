# GHA PR-GPS — KnoSky (P1 stub)

GitHub Action consumer for **advisory** PR navigation (existing `action.yml` / `knosky ci`). Same launch train as P0 packs; not a second product.

## Quick use

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: KnoSky PR-GPS
  uses: SathiaAI/knosky@v0.5.0   # pin to your verified tag
  with:
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
```

Local parity:

```bash
node bin/knosky.mjs ci --base <sha> --head <sha>
```

## Honesty

- PR-GPS comments are **advisory** navigation — not a required check that blocks builds by default.
- File/import structure map; **not** full body upload.
- Mode B MCP tools (`kc_route` / `kc_policy_check` / `kc_bundle` + `leaseId` from `agent-register`) are the governed agent path; PR-GPS comment bot is a **neighbor surface**, not automatic L3 swarm-safe.
- Do not claim swarm-safe from PR comments alone.

## Tools relationship (DEC-108)

CI surface may emit routes/summaries; agent packs still use SSOT tools:

- Map: `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`
- Governed: `kc_route`, `kc_bundle`, `kc_policy_check`

See [`ssot/tool-menu.json`](../../ssot/tool-menu.json) and repo root action docs.

## Coexistence

Works next to Greptile/CodeRabbit recipes and repo **`AGENTS.md`**. Does not replace human review or host instruction files.

Index: [`../README.md`](../README.md)
