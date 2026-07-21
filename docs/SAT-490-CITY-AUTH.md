# SAT-490 / FR-KS-SEC-001 — City auth claim lattice (C1)

```yaml
---
id: DOC-S3-SAT490
title: SAT-490 city auth disposition for Wave 1 claims
status: residual-complete-for-public-knosky
last_updated: 2026-07-19
---
```

## Finding

**SAT-490** is a **private** Mission Control / Paperclip issue:

- Route: `mc.sathia.ai/city` (hosted board)
- Bugs: missing `assertBoard(req)` — unauthenticated curl returned org-wide index
- Fix area: `SathiaAI/paperclip` (not public `SathiaAI/knosky` MCP)

Public KnoSky (`SathiaAI/knosky`) serves **local** `city.html` / `city-data.json` under the user’s machine (file:// or user-opened artifact). There is **no** public HTTP `/city` API in this repo’s launcher.

## Wave 1 residual disposition (knosky product)

| Claim | Rule |
| :--- | :--- |
| “Public city API is auth-gated” | **N/A** on public knosky — do not claim hosted `/city` |
| Local city HTML | Treat as **directory listing + snippets** (SECURITY.md); share-safe indexer already fail-closed |
| MCP Tier 0 map | Labeled **non-authorizing** / ADVISORY_UNAUTH |
| Mode B ALLOW | Requires identity + policy + audit on MCP/CLI |
| Mission Control city | **Separate paperclip residual** — must keep `assertBoard` forever; regression test lives in paperclip, not knosky |

## Checklist before any “public city” marketing

- [x] Document SAT-490 scope = paperclip board (this file)
- [x] Public knosky surfaces must not imply hosted unauthenticated city API
- [ ] If paperclip `/city` still In Review, **do not** market mc.sathia.ai city as safe until SAT-490 Done
- [x] Mode B MCP does not expose full-city as ALLOW without policy

## Related tasks

- Linear SAT-490 (paperclip)  
- DOC-06 TASK-KS-E-020 / FR-KS-SEC-001  
- KnoSky SECURITY.md / LIMITATIONS.md honesty  
