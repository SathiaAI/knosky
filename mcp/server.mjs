// Knowledge City — local stdio MCP server (Phase 2a).
// Read-only retrieval over a local contract-v2 index. No network; data never leaves the machine.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { load, search, getNode, listCategories, getProvenance, getRelated } from "../core/retrieve.mjs";

const CITY = process.env.KC_CITY || process.argv[2];
if (!CITY) { console.error("Knowledge City MCP: set KC_CITY (or pass a path) to a city-data.v2.json"); process.exit(1); }
const ctx = load(CITY);

const server = new McpServer({ name: "knowledge-city", version: "0.4.1" });

server.registerTool("kc_search", {
  title: "Search the Knowledge City",
  description: "Search the indexed knowledge base by keywords. Returns ranked items (title, summary, category) each with a provenance citation (source path + revision) that links back to the live file. Use for 'where does X live / what was decided about Y / how does this connect'. Navigation, not full-text code search.",
  inputSchema: { query: z.string().max(500).describe("keywords"), limit: z.number().int().min(1).max(50).optional().describe("max results (default 10, max 50)"), category: z.string().max(200).optional().describe("restrict to one category id") },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ query, limit, category }) => {
  const hits = search(ctx, String(query).slice(0, 500), { limit: Math.min(Math.max(1, limit || 10), 50), category: category ? String(category).slice(0, 200) : null });
  const text = hits.length
    ? hits.map(h => `- [${h.category}] ${h.title} — ${h.summary || ""}\n  source: ${h.provenance.ref} @ ${h.provenance.source_rev} (id: ${h.id})`).join("\n")
    : "No matches.";
  return { content: [{ type: "text", text }], structuredContent: { results: hits } };
});

server.registerTool("kc_get_node", {
  title: "Get one item",
  description: "Fetch a single indexed item by id (title, summary, category, kind) with its provenance citation.",
  inputSchema: { id: z.string().max(400).describe("node id, e.g. fs:src/index.ts") },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const n = getNode(ctx, id);
  return { content: [{ type: "text", text: n ? JSON.stringify(n, null, 2) : `No item with id ${id}` }], structuredContent: n || {} };
});

server.registerTool("kc_list_categories", {
  title: "List categories",
  description: "List the knowledge categories (city districts) with item counts.",
  inputSchema: {},
  annotations: { readOnlyHint: true },
}, async () => {
  const cats = listCategories(ctx);
  return { content: [{ type: "text", text: cats.map(c => `${c.label} (${c.id}): ${c.count}`).join("\n") }], structuredContent: { categories: cats } };
});

server.registerTool("kc_get_provenance", {
  title: "Get provenance (citation)",
  description: "Get the citation for an item: the live source ref + revision, plus its links to related items.",
  inputSchema: { id: z.string().max(400) },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const p = getProvenance(ctx, id);
  return { content: [{ type: "text", text: p ? JSON.stringify(p, null, 2) : `No item with id ${id}` }], structuredContent: p || {} };
});

server.registerTool("kc_related", {
  title: "Related files (connections)",
  description: "How a file connects to others in this project: which files it imports (out), which files import it (in), and its recent-change (churn) signal. File-level structure with citations, not code analysis.",
  inputSchema: { id: z.string().max(400).describe("node id, e.g. fs:src/auth.js") },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const r = getRelated(ctx, id);
  if (!r) return { content: [{ type: "text", text: "No item with id " + id }], structuredContent: {} };
  const NL = String.fromCharCode(10);
  const lines = [r.title + " (" + id + ")"];
  if (r.churn) lines.push("recent changes: " + r.churn.c + " commit(s), heat " + r.churn.b);
  lines.push("imports (" + r.imports.length + "): " + (r.imports.map(x => x.source || x.id).join(", ") || "none"));
  lines.push("imported by (" + r.importedBy.length + "): " + (r.importedBy.map(x => x.source || x.id).join(", ") || "none"));
  return { content: [{ type: "text", text: lines.join(NL) }], structuredContent: r };
});

await server.connect(new StdioServerTransport());
console.error(`knowledge-city MCP ready — ${ctx.city.node_count} nodes, ${(ctx.city.categories||[]).length} categories`);
