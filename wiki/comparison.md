# KnoSky vs. alternatives

Where KnoSky fits, and where the other tools fit better.

---

## The one-line framing

KnoSky is a **local map and citation router**, not a code-intelligence engine.
It answers *"where is it?"* — not *"what does it mean semantically?"*.
That focus makes it sharp at orientation and grounding your AI assistant in your own code,
and means it deliberately does not try to replace the tools that do deep analysis.

---

## Head-to-head

| | **KnoSky** | **Cursor / Copilot (embedded RAG)** | **Sourcegraph** | **Grep / ripgrep** | **Glean / Notion AI** |
|---|---|---|---|---|---|
| **Primary job** | Visual map + citation router | In-editor AI completions & chat | Code search & code-intel | Raw text search | Enterprise knowledge search |
| **Where knowledge lives** | Your machine | Your machine (IDE) or cloud | Hosted (cloud or self-hosted) | Your machine | Cloud |
| **Setup** | `npx knosky .` | IDE extension | Deployment + admin | None | Org-wide setup |
| **Cost** | Free, $0 tokens | Subscription | Subscription | Free | Subscription |
| **What it reads** | File names, headings, short excerpts (≤200 chars) | File bodies (full RAG) | File bodies (full index) | Raw file bytes | Docs + code bodies |
| **Sends code externally** | Never — local only | IDE model calls (cloud inference); VS Code extension in local mode only if configured | Yes (cloud) or your infra | Never | Yes |
| **Grounded citations** | Yes — every answer links to the live file | Partial — inline suggestions, no citations | Yes, with code hover | Yes — line numbers | Yes |
| **Visual overview** | Yes — isometric city map | No | Code graph (paid) | No | No |
| **PR navigation** | Yes — PR-GPS action | No | No | No | No |
| **Best for** | Orientation, grounding an AI assistant, PR nav | Daily coding completions | Deep code search at org scale | Quick raw search | Org-wide Q&A over mixed docs |

---

## When to choose KnoSky

- You want to **orient a new collaborator** (or yourself after a break) in a large repo fast.
- You want your Claude / Cursor / VS Code assistant to **cite your actual source files** instead of guessing.
- You care about **local-first privacy**: nothing ever leaves your machine.
- You want an **always-fresh, $0-token index** — no embeddings, no cloud calls.
- You want **PR-GPS**: automatic navigation comments on pull requests.

## When to choose something else

- **Deep code Q&A** over file bodies (semantics, types, call graphs) → Cursor / Copilot, Sourcegraph.
- **Org-wide docs + code search** with SSO and audit logs → Sourcegraph or Glean.
- **Quick raw-text search** in a single repo → ripgrep is faster and needs no setup.

---

## On AI grounding specifically

KnoSky and Cursor/Copilot are **complementary**, not competing.
KnoSky grounds the assistant in *map-level structure* (where things live, what connects to what);
Cursor/Copilot handles in-file completions and full-body reasoning.
Use both: KnoSky for orientation and routing, your IDE for code generation.

---

## Privacy in thirty seconds

| | Code bodies uploaded? | Account required? | Telemetry? |
|---|---|---|---|
| KnoSky | **Never** | No | No |
| Cursor | Yes (cloud inference) | Yes | Optional |
| Sourcegraph (cloud) | Yes | Yes | Yes |
| Glean | Yes | Yes (SSO) | Yes |
| ripgrep | Never | No | No |

Full details: [PRIVACY.md](../PRIVACY.md) · [LIMITATIONS.md](../LIMITATIONS.md)
