# Knowledge City — Data Contract v2 (the shared spine)

> Phase 1a deliverable (SAT-385 → build). The one schema both faces (City + MCP) and every source
> (fs/github/board) depend on. Generalizes the fixed-4-district v1 → **N categories**. Pointers +
> projections ONLY — never file bodies (D-146). Council fixes baked in: a serialization **allowlist** + a
> best-effort **denylist scrub**. Proven to represent the current live city losslessly.

## Envelope
```jsonc
{
  "schema_version": "2.0",
  "generated_at": "<ISO8601>",
  "source": { "kind": "fs|github|board|legacy", "ref": "<path/repo>", "rev": "<commit/rev>" },
  "categories": [ { "id": "technical", "label": "Technical", "color": "#4f8cff", "order": 0 } ],
  "node_count": 150,
  "nodes": [ /* Node[] */ ]
}
```
`categories[]` is the **N-category manifest** that replaces the hardcoded 4 districts — the renderer derives
its districts/colors from this, so the board scales to however many categories a source has.

## Node
```jsonc
{
  "id": "decision:D-146",          // stable, source-derived
  "kind": "decision|spec|file|dir|doc|...",
  "title": "Index, not copy",      // projection
  "summary": "<= 200 chars",       // projection (excerpt, never full body)
  "category": "governance",        // category id (was "district")
  "status": "locked",              // optional
  "fact_date": "2026-06-19",       // optional
  "tags": [],                      // optional projection
  "headings": [],                  // optional projection (for nav/search)
  "links": ["decision:D-147"],     // edges to other node ids
  "provenance": { "store": "...", "ref": "...", "source_rev": "...", "fetched_at": "..." },
  "visibility": "internal|public",
  "sensitive": false               // scrub/flag marker
}
```
Required: `id, kind, title, category, links, provenance`. Provenance required: `store, ref`.

## Serialization allowlist (council fix)
Only these node fields may **ever** be written into the index:
`id, kind, title, summary, category, status, fact_date, tags, headings, links, provenance, visibility, sensitive`.
The serializer drops anything else and the validator **fails** on any non-allowlisted field — this is the
structural guard against a file `body` ever leaking into the index.

## PII scrub (best-effort — NOT a security boundary)
Applied to every emitted text projection (title/summary/headings/tags): redact emails, `key|secret|token|password|bearer` assignments, AWS access-key IDs, private-key headers → `[REDACTED]`. The indexer also skips
`.git`, `node_modules`, `secrets/`, `keys/`, `.env*`, `dist/` by default, **plus** the repo's `.gitignore`
and a user `.kcignore`. Honest framing (per council): this reduces accidental leakage; it is not a guarantee,
and the local index is readable by the user's own assistant. First-run note will say so.

## Projection limits
`summary` ≤ 200 chars. No field carries a full file body. Full content is reached only by dereferencing
`provenance` to the live source (which is what keeps the city fresh — "a map, not a copy").

## Proof (this Phase-1a increment)
Adapting the current live city (`golden/city-data.golden.json`) through `adaptLegacy()` → contract v2:
- nodes **150 → 150** (no loss), edges **769 → 769** (no loss)
- categories derived: `product#0, technical#1, governance#2, design#3`
- `validateCity()` → **VALID**; scrub positive+negative tests **pass**
- reference instance written to `golden/city-data.v2.json`

Implementation: `core/contract.mjs` (schema + allowlist + scrub + validator + legacy adapter).
Reproduce: `node core/validate-golden.mjs`.

## Open at G1 (founder call)
None on the schema itself (it's proven). Carry-forward decision (Phase 3, not blocking): the **activation
layer** — council unanimously recommends deferring it to the monetization tier so v1 stays fully offline.
