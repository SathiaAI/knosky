// KC retrieval lib (Phase 2a) — the shared seam both the MCP and the City read.
// Navigation-scoped (where/what/how-connected + citations), NOT code-RAG. Pure, no deps.
import fs from 'node:fs';

export function load(cityPath) {
  const city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
  const byId = new Map((city.nodes || []).map(n => [n.id, n]));
  return { city, byId };
}
const tok = (s) => (String(s || '').toLowerCase().match(/[a-z0-9]+/g) || []);

function fmt(n, score) {
  return { id: n.id, title: n.title, summary: n.summary, category: n.category, kind: n.kind, score, provenance: n.provenance };
}

// search: token scoring over title/headings/summary/tags/category. Returns ranked hits w/ provenance (citations).
export function search(ctx, q, { limit = 10, category = null } = {}) {
  const qt = [...new Set(tok(q))];
  if (!qt.length) return [];
  const out = [];
  for (const n of ctx.city.nodes) {
    if (category && n.category !== category) continue;
    const title = new Set(tok(n.title)), heads = new Set(tok((n.headings || []).join(' ')));
    const summ = new Set(tok(n.summary)), tags = new Set((n.tags || []).map(x => String(x).toLowerCase()));
    const cat = new Set(tok(n.category));
    let score = 0;
    for (const t of qt) {
      if (title.has(t)) score += 5;
      if (heads.has(t)) score += 3;
      if (summ.has(t)) score += 2;
      if (tags.has(t)) score += 2;
      if (cat.has(t)) score += 1;
    }
    if (score > 0) out.push({ n, score });
  }
  out.sort((a, b) => b.score - a.score || String(a.n.id).localeCompare(String(b.n.id)));
  return out.slice(0, limit).map(r => fmt(r.n, r.score));
}

export function getNode(ctx, id) { const n = ctx.byId.get(id); return n ? fmt(n, null) : null; }

export function listCategories(ctx) {
  const counts = {};
  for (const n of ctx.city.nodes) counts[n.category] = (counts[n.category] || 0) + 1;
  return (ctx.city.categories || []).map(c => ({ ...c, count: counts[c.id] || 0 }));
}

// provenance = the citation: where the live source is + what it links to.
export function getProvenance(ctx, id) {
  const n = ctx.byId.get(id);
  if (!n) return null;
  return { id, title: n.title, provenance: n.provenance, links: n.links || [] };
}

// related = file connections (D-155): out-edges (imports) + in-edges (imported-by) + churn signal. File-level only.
export function getRelated(ctx, id) {
  const n = ctx.byId.get(id);
  if (!n) return null;
  const ref = (m) => ({ id: m.id, title: m.title, source: m.provenance && m.provenance.ref });
  const imports = (n.links || []).map(tid => ctx.byId.get(tid)).filter(Boolean).map(ref);
  const importedBy = ctx.city.nodes.filter(m => (m.links || []).includes(id)).map(ref);
  return { id, title: n.title, churn: n.churn || null, imports, importedBy };
}
