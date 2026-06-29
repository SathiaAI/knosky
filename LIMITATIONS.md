# Known limitations

KnoSky is a **map and citation layer**, not a code-intelligence engine. Being clear about the boundary keeps expectations honest.

## What KnoSky is good at

- Orienting you in a repo or docs folder fast: where things live, how areas connect.
- Giving you (and your AI assistant, via the local MCP) **cited pointers** back to the real source.
- A private, always-fresh, $0 index that runs entirely on your machine.

## What KnoSky is not (yet)

- **Not deep code intelligence.** It does not parse call graphs, type information, runtime dependencies, or semantic architecture. It indexes pointers and light projections, not file bodies.
- **Not a full-text / code-RAG search.** It will not answer questions over the *contents* of your files. For deep code Q&A, your AI assistant should read the source it cites (that's what the MCP citations are for) or use a dedicated code-search tool.
- **Not a cloud service.** No sync, no multi-user, no hosted backend.

## Practical notes

- **Ignore matching:** inside a git repo, git's own ignore rules are applied; outside git, a conservative `.gitignore`/`.kcignore` parser is used and may differ from git in edge cases.
- **Large repos:** indexing is capped (default 6000 files, `--max`) to stay fast; very large monorepos may need `--max` raised or extra `.kcignore` entries.
- **Categories:** the default categorizer uses top-level folder names. AI-suggested categories are opt-in and metadata-only.

See also: [README.md](README.md), [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md).
