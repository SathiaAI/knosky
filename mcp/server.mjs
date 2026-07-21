// Knowledge City — local stdio MCP server (Mode B + DEC-108 menu freeze).
// Read-mostly local index. No network; data never leaves the machine by default.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { load, search, getNode, listCategories, getProvenance, getRelated } from "../core/retrieve.mjs";
import { createModeBDoor } from "../core/mode-b.mjs";
import { queryAudit, verifyAuditChain } from "../core/audit-writer.mjs";
import { closedSet } from "../core/decision-codes.mjs";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CITY = process.env.KC_CITY || process.argv[2];
if (!CITY) {
  console.error("Knowledge City MCP: set KC_CITY (or pass a path) to a city-data.v2.json");
  process.exit(1);
}

const PROFILE = (process.env.KC_PROFILE || "coding").toLowerCase(); // coding | security | advisory
const DOMAIN = process.env.KC_DOMAIN || undefined;

let ctx;
try {
  ctx = load(CITY);
} catch (err) {
  console.error("Knowledge City MCP: failed to load city:", err && err.message ? err.message : err);
  process.exit(1);
}

const door = createModeBDoor({
  cityCtx: ctx,
  cityPath: CITY,
  domainRoot: DOMAIN,
  profile: PROFILE,
});

const HERE = dirname(fileURLToPath(import.meta.url));
const SSOT_MENU = join(HERE, "..", "ssot", "tool-menu.json");
let menuVersion = "1.0.0";
try {
  menuVersion = JSON.parse(readFileSync(SSOT_MENU, "utf8")).version || menuVersion;
} catch {
  /* optional */
}

const server = new McpServer({ name: "knosky", version: "0.7.0-modeb" });

function textResult(obj) {
  const text = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  return { content: [{ type: "text", text }], structuredContent: typeof obj === "object" ? obj : { text } };
}

function modeALabel() {
  return PROFILE === "advisory"
    ? " [Mode A advisory — non-authorizing]"
    : " [Tier 0 map — non-authorizing unless combined with Mode B tools]";
}

// --- Tier 0 map tools (non-authorizing) ---

server.registerTool("kc_search", {
  title: "Search the Knowledge City",
  description:
    "Search the indexed knowledge base by keywords. Returns ranked items with provenance citations." +
    modeALabel() +
    " Navigation, not full-text code search. Not a Mode B authorization.",
  inputSchema: {
    query: z.string().max(500).describe("keywords"),
    limit: z.number().int().min(1).max(50).optional().describe("max results (default 10, max 50)"),
    category: z.string().max(200).optional().describe("restrict to one category id"),
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ query, limit, category }) => {
  const hits = search(ctx, String(query).slice(0, 500), {
    limit: Math.min(Math.max(1, limit || 10), 50),
    category: category ? String(category).slice(0, 200) : null,
  });
  const text = hits.length
    ? hits
        .map(
          (h) =>
            `- [${h.category}] ${h.title} — ${h.summary || ""}\n  source: ${h.provenance.ref} @ ${h.provenance.source_rev} (id: ${h.id})`,
        )
        .join("\n")
    : "No matches.";
  return {
    content: [{ type: "text", text: text + "\n\n(decision_code hint: ADVISORY_UNAUTH / non-authorizing map)" }],
    structuredContent: { results: hits, decision_code: "ADVISORY_UNAUTH", mode: "A", authorizing: false },
  };
});

server.registerTool("kc_get_node", {
  title: "Get one item",
  description: "Fetch a single indexed item by id with provenance." + modeALabel(),
  inputSchema: { id: z.string().max(400).describe("node id, e.g. fs:src/index.ts") },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const n = getNode(ctx, id);
  return textResult(
    n
      ? { ...n, decision_code: "ADVISORY_UNAUTH", mode: "A", authorizing: false }
      : { error: `No item with id ${id}`, decision_code: "ERROR_INVALID_INPUT" },
  );
});

server.registerTool("kc_list_categories", {
  title: "List categories",
  description: "List knowledge categories (city districts) with item counts." + modeALabel(),
  inputSchema: {},
  annotations: { readOnlyHint: true },
}, async () => {
  const cats = listCategories(ctx);
  return {
    content: [{ type: "text", text: cats.map((c) => `${c.label} (${c.id}): ${c.count}`).join("\n") }],
    structuredContent: { categories: cats, decision_code: "ADVISORY_UNAUTH", mode: "A", authorizing: false },
  };
});

server.registerTool("kc_get_provenance", {
  title: "Get provenance (citation)",
  description: "Citation for an item: live source ref + revision + links." + modeALabel(),
  inputSchema: { id: z.string().max(400) },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const p = getProvenance(ctx, id);
  return textResult(
    p
      ? { ...p, decision_code: "ADVISORY_UNAUTH", mode: "A", authorizing: false }
      : { error: `No item with id ${id}`, decision_code: "ERROR_INVALID_INPUT" },
  );
});

server.registerTool("kc_related", {
  title: "Related files (connections)",
  description: "Imports / importers / churn for a file." + modeALabel(),
  inputSchema: { id: z.string().max(400).describe("node id, e.g. fs:src/auth.js") },
  annotations: { readOnlyHint: true },
}, async ({ id }) => {
  const r = getRelated(ctx, id);
  if (!r) return textResult({ error: "No item with id " + id, decision_code: "ERROR_INVALID_INPUT" });
  const NL = String.fromCharCode(10);
  const lines = [r.title + " (" + id + ")"];
  if (r.churn) lines.push("recent changes: " + r.churn.c + " commit(s), heat " + r.churn.b);
  lines.push("imports (" + r.imports.length + "): " + (r.imports.map((x) => x.source || x.id).join(", ") || "none"));
  lines.push(
    "imported by (" + r.importedBy.length + "): " + (r.importedBy.map((x) => x.source || x.id).join(", ") || "none"),
  );
  return {
    content: [{ type: "text", text: lines.join(NL) }],
    structuredContent: { ...r, decision_code: "ADVISORY_UNAUTH", mode: "A", authorizing: false },
  };
});

// --- Tier 1 governed tools ---

const leaseFields = {
  leaseId: z.string().max(200).optional().describe("Server-issued lease id (Mode B). Required when KC_PROFILE!=advisory."),
  agentId: z
    .string()
    .max(200)
    .optional()
    .describe("Optional agent id claim — NEVER trusted alone; must match lease record"),
  advisory: z.boolean().optional().describe("Force Mode A ADVISORY_UNAUTH path"),
};

server.registerTool("kc_route", {
  title: "Route to a destination (agent GPS)",
  description:
    "Mode B (default coding profile): identity + policy + audit receipt then ALLOW authorized subgraph or DENY_*. " +
    "Mode A when profile=advisory or advisory=true: ADVISORY_UNAUTH labeled tips only. " +
    "Structural navigation with citations; does not replace reading live files. Decision codes: " +
    closedSet().join(", "),
  inputSchema: {
    destination: z.string().max(400).describe("navigation target — file:, folder:, or keywords"),
    limit: z.number().int().min(1).max(20).optional().describe("max route entries (default 8)"),
    ...leaseFields,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ destination, limit, leaseId, agentId, advisory }) => {
  const env = door.handle({
    tool: "route",
    destination,
    limit,
    leaseId,
    agentId: agentId ?? null,
    advisory: !!advisory,
  });
  return textResult(env);
});

server.registerTool("kc_bundle", {
  title: "Build intent bundle (share-safe pointers)",
  description:
    "Mode B: package a small pointer bundle (intent-manifest) under identity+policy+audit; fail-closed secret scan. " +
    "Not available as authorizing in pure advisory profile.",
  inputSchema: {
    destination: z.string().max(400).optional().describe("optional GPS destination used to pick node ids"),
    nodeIds: z.array(z.string().max(400)).optional().describe("explicit node ids to include"),
    root: z.string().max(1000).optional().describe("repo root for secret scan / sha256"),
    ...leaseFields,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ destination, nodeIds, root, leaseId, agentId, advisory }) => {
  const env = door.handle({
    tool: "bundle",
    destination,
    nodeIds,
    root: root || process.env.KC_ROOT || null,
    leaseId,
    agentId: agentId ?? null,
    advisory: !!advisory,
  });
  return textResult(env);
});

server.registerTool("kc_policy_check", {
  title: "Dry-run policy check",
  description: "Mode B: would this destination be allowed for the bound agent? Returns decision codes without full route body preference.",
  inputSchema: {
    destination: z.string().max(400),
    ...leaseFields,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ destination, leaseId, agentId, advisory }) => {
  const env = door.handle({
    tool: "policy_check",
    destination,
    leaseId,
    agentId: agentId ?? null,
    advisory: !!advisory,
  });
  return textResult(env);
});

// --- Security profile only ---
if (PROFILE === "security") {
  server.registerTool("kc_audit_query", {
    title: "Query local audit receipts",
    description: "Security profile only. Metadata-only audit events for this local trust domain.",
    inputSchema: {
      limit: z.number().int().min(1).max(200).optional(),
      agent_id: z.string().max(200).optional(),
    },
    annotations: { readOnlyHint: true },
  }, async ({ limit, agent_id }) => {
    const rows = queryAudit(door.domainRoot, { limit, agent_id });
    return textResult({ events: rows, domain: door.domainRoot });
  });

  server.registerTool("kc_audit_verify", {
    title: "Verify audit chain",
    description: "Security profile only. Verify hash chain of local audit ledger.",
    inputSchema: {},
    annotations: { readOnlyHint: true },
  }, async () => {
    return textResult(verifyAuditChain(door.domainRoot));
  });
}

await server.connect(new StdioServerTransport());
console.error(
  `knosky MCP ready — profile=${PROFILE} ssot=${menuVersion} nodes=${ctx.city.node_count} domain=${door.domainRoot}`,
);
