// Knowledge City — local stdio MCP server (Phase 2a).
// Read-only retrieval over a local contract-v2 index. No network; data never leaves the machine.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { load, search, getNode, listCategories, getProvenance } from "../core/retrieve.mjs";

const CITY = process.env.KC_CITY || process.argv[2];
if (!CITY) { console.error("Knowledge City MCP: set KC_CITY (or pass a path) to a city-data.v2.json"); process.exit(1); }
const ctx = load(CITY);

const server = new McpServer({ name: "knowledge-city", version: "0.1.0" });

server.registerTool("kc_search", {
  title: "Search the Knowledge City",
  description: "Search the indexed knowledge base by keywords. Returns ranked items (title, summary, category) each with a provenance citation (source path + revision) that links back to the live file. Use for 'where does X live / what was decided about Y / how does this connect'. Navigation, not full-text code search.",
  inputSchema: { query: z.string().describe("keywords"), limit: z.number().int().optional().describe("max results (default 10)"), category: z.string().optional().describe("restrict to one category id") },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ query, limit, category }) => {
  const hits = search(ctx, query, { limit: limit || 10, category: category || null });
  const text = hits.length
    ? hits.map(h => `- [${h.category}] ${h.title} — ${h.summary || ""}\n  source: ${h.provenance.ref} @ ${h.provenance.source_rev} (id: ${h.id})`).join("\n")
    : "No matches.";
  return { content: [{ type: "text", text }], structuredContent: { results: hits } };
});

server.registerTool("kc_get_node", {
  title: "Get one item",
  description: "Fetch a single indexed item by id (title, summary, category, kind) with its provenance citation.",
  inputSchema: { id: z.string().describe("node id, e.g. fs:src/index.ts") },
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
  inputSchema: { id: z.string() },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const p = getProvenance(ctx, id);
  return { content: [{ type: "text", text: p ? JSON.stringify(p, null, 2) : `No item with id ${id}` }], structuredContent: p || {} };
});

await server.connect(new StdioServerTransport());
console.error(`knowledge-city MCP ready — ${ctx.city.node_count} nodes, ${(ctx.city.categories||[]).length} categories`);
