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

## Network lockdown scope (F0.5)

The OS-level network sandbox (`core/net-lockdown.mjs`, wraps the MCP server / evaluator process) is **network-only by design**, not a general filesystem or process jail:

- On macOS, the `sandbox-exec` profile allows filesystem and process operations (the evaluator needs full read access to your indexed files) and denies only non-loopback outbound/inbound network -- confirmed via PR #60 review (2026-07-05).
- On Windows, there is currently no runtime AppContainer detection -- `knosky doctor` always reports it as inactive. This is safe (nothing in the code claims runtime enforcement on Windows either way: `supported` is always `false`), but real Windows network isolation requires packaging-time AppContainer/WFP configuration, which this tool does not automate.
- On Linux, `unshare --user --net` provides a real kernel-enforced network namespace.

If you depend on this for anything beyond defense-in-depth / `doctor` visibility, treat macOS and Windows as advisory only; Linux's `unshare` path is the one with an actual kernel-enforced guarantee.

See also: [README.md](README.md), [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md).
