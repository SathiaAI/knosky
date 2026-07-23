# READ_ONLY_GUARANTEE — Map tools (Enterprise Phase 1)

```yaml
---
id: DOC-KS-RO-GUARANTEE
title: KnoSky map tools read-only guarantee
version: 1.0.0
status: active
last_updated: 2026-07-23
dec: DEC-118
fr: FR-KS-ENT-106
---
```

## Plain English

When you connect an assistant to KnoSky **map tools**, those tools are for **finding and citing** knowledge in a local index.  
They are **not** permission to edit your repo, run shell commands, or wander outside the folder you indexed.

**Mode B** tools (`kc_route`, `kc_bundle`, `kc_policy_check`) are a **different column**: identity + policy + audit.  
They may make **allow/deny decisions** and build **pointer bundles**.  
They still are **not** “silent autonomous write-all-your-files.”

---

## Allowed (map / Tier 0)

| Tool | Purpose |
| :--- | :--- |
| `kc_search` | Keyword search with citations |
| `kc_get_node` | One indexed item |
| `kc_list_categories` | District/category list |
| `kc_get_provenance` | Citation / source ref |
| `kc_related` | Related connections |

Annotations: `readOnlyHint: true` on the MCP server.

---

## Forbidden (map surface)

| Action | Expected |
| :--- | ---: |
| Write file | Not offered / denied |
| Delete file | Not offered / denied |
| Run shell commands | Not offered / denied |
| Arbitrary external network body fetch as map search | Not offered |
| Read outside indexed root (path traversal) | **Denied** |
| Treat Mode A map hit as “authorized change” | **No** — still advisory/non-authorizing |

---

## Mode B (separate honesty table)

| Tool | Purpose |
| :--- | :--- |
| `kc_route` | Governed route decision under lease + policy + audit |
| `kc_policy_check` | Policy check only |
| `kc_bundle` | Pointer bundle (share-safe secret scan) |

Requires Mode B setup (`agent-register`, lease).  
Audit receipts land in the local domain.  
**Do not** market Mode B as “just search.”

---

## L3 note

L3 multi-helper coordination is an **early foundation**.  
This RO guarantee document does **not** claim production “swarm-safe fleet everywhere.”

---

## How we prove it

1. Static inspect of `mcp/server.mjs` registrations (`core/ro-guarantee.mjs`)  
2. Path traversal helpers / tests (`assertInsideRoot`)  
3. Enterprise capability matrix written under `.knosky/mcp-capability-matrix.json`  
4. Residual test: `node test/enterprise-phase1.test.mjs`  
5. Existing share-safe + security fixtures in the wider suite  

---

## Enterprise Mode

```bash
node bin/knosky.mjs enterprise . --no-serve
node bin/knosky.mjs doctor
node bin/knosky.mjs audit pack --root .
node bin/knosky.mjs audit verify .knosky/knosky_audit_bundle_...
```

---

*Shipped under GREENLIGHT ENT PHASE 1 / APR-KS-S2-ENT-NEXT.*
