# Show HN: KnoSky — turn any repo into an explorable city and ground your AI in it

> Draft for the Show HN post. Copy the **Title** and **Body** sections directly.
> See the Q&A section for anticipated comments.

---

## Title

**Show HN: KnoSky – turn any repo into an explorable city, ground your AI in it (local, free)**

---

## Body

I built KnoSky after hitting the same wall repeatedly on Sathia: the repo had grown large enough that nobody could hold the whole thing in their head, and our AI assistant was confidently making things up about our own codebase.

What I wanted was simple: (1) see the shape of the project in one screen, and (2) give the assistant a cited pointer to the real file instead of a hallucinated one. I couldn't find a tool that did exactly that without uploading our code somewhere, so I built it.

**What it does:**

- Indexes any repo or docs folder into a map — districts (top-level folders), buildings (files), roads (imports). Opens as an interactive city in your browser.
- Exposes a local MCP server so Claude / Cursor / VS Code can answer *"where does auth live?"* and cite the actual file, every time.
- PR-GPS: a GitHub Action that posts a navigation comment on every pull request listing changed files, suggested review starting points, and related tests/docs.

**One command:**

    npx knosky .

That's it. No account, no cloud, no token spend. Runs entirely on your machine.

**What it is not:** not a code-RAG engine, not a full-text search, not an AST analyser. It's a map and a citation router. It tells your AI *where* things are and hands it the source; the AI does the reading.

**Privacy:** indexes pointers and short excerpts (≤200 chars per file) — never full file bodies. Fail-closed secret scan before you share anything. Nothing ever leaves your machine.

Stack: pure Node.js stdlib + MCP SDK + Kenney CC0 city art. FSL-1.1-MIT license (converts to MIT two years after each release).

Repo: https://github.com/SathiaAI/knosky

Happy to answer questions about the design decisions or the MCP wiring.

---

## Anticipated Q&A

**Q: How is this different from Sourcegraph?**
Sourcegraph is a full code-intelligence platform — it indexes bodies, parses call graphs, and runs in the cloud or your infra. KnoSky is a local map layer: no code bodies, no cloud, $0. The two are complementary if you have Sourcegraph; KnoSky is useful if you don't.

**Q: How is it different from Cursor's codebase indexing?**
Cursor indexes full file bodies for in-editor RAG. KnoSky indexes pointers and short excerpts only, stays local, and adds the visual map and PR-GPS. Use both: KnoSky for orientation and routing, Cursor for in-file generation.

**Q: Does it work with large monorepos?**
Yes, with caveats. The default cap is 6000 files (raise with `--max`). Very large monorepos benefit from `.kcignore` entries to focus on the parts you care about. See LIMITATIONS.md.

**Q: What MCP tools does it expose?**
`kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related`, `kc_route`, `kc_bundle`. All read-only, all local, all return cited file pointers.

**Q: Why FSL-1.1-MIT instead of MIT outright?**
FSL prevents someone from taking the exact product and repackaging it as a competing service. It converts to MIT two years after each release, so the code is eventually fully open. Standard approach for bootstrapped open-source products.

**Q: What does "fail-closed secret scan" mean?**
If the indexer finds something that looks like a credential (API key, JWT, PEM block, etc.) in a title/heading/excerpt, the build fails and refuses to write the city file. You can override with `--allow-leaks` if you're sure it's a false positive.

**Q: Can I use it offline / air-gapped?**
Yes. After the initial `npm install` (or `git clone && npm install`) everything runs locally with no network calls. The MCP server is a local stdio process.
