// KnoSky destination parser (KSV2-R2) — extended prefix set for kc_route.
// Pure Node stdlib + internal imports only. ESM. No new deps.
import { search } from './retrieve.mjs';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a single node by id "fs:<rest>" OR by provenance.ref === <rest>.
 * Also accepts a fully-qualified id (already has "fs:" prefix).
 * @param {object} ctx
 * @param {string} idOrRef
 * @returns {object|null}
 */
function resolveOne(ctx, idOrRef) {
  // Try constructing the canonical node id
  const byConstructed = ctx.byId.get('fs:' + idOrRef);
  if (byConstructed) return byConstructed;
  // Try the raw string as-is (already fully qualified, e.g. "fs:src/a.js")
  const byRaw = ctx.byId.get(idOrRef);
  if (byRaw) return byRaw;
  // Fallback: linear scan for provenance.ref match
  return ctx.city.nodes.find(n => n.provenance && n.provenance.ref === idOrRef) || null;
}

// ---------------------------------------------------------------------------
// parseDestination — main export
// ---------------------------------------------------------------------------

/**
 * Resolve the destination string to an initial set of matching nodes.
 * Returns { matched: Node[], matchStrength: 'direct'|'folder'|'district'|'edges'|'chain'|'keyword' }
 *
 * Supported prefixes (ALL metadata-only, no filesystem access):
 *   file:<idOrRef>   — node by id "fs:<rest>" OR by provenance.ref === rest; 'direct'
 *   folder:<prefix>  — nodes whose provenance.ref starts with prefix; 'folder'
 *   district:<name>  — nodes whose category equals name (case-insensitive) or
 *                      whose category label matches; 'district'
 *   importsOf:<idOrRef> — out-edge targets of that node (node.links through ctx.byId); 'edges'
 *   depChainTo:<idOrRef> — nodes that TRANSITIVELY import/reach the target via
 *                          reverse-edge BFS; bounded (max depth 6, max 500 visited,
 *                          visited-set prevents cycles); 'chain'
 *   <anything else>  — keyword fallback via search(); 'keyword'
 *
 * @param {object} ctx         — retrieve context {city:{nodes,categories}, byId:Map}
 * @param {string} destination
 * @param {number} limit       — passed through to keyword search
 * @returns {{ matched: object[], matchStrength: string }}
 */
export function parseDestination(ctx, destination, limit) {
  const dest = String(destination || '').trim();

  // ------------------------------------------------------------------
  // file:<idOrRef>
  // ------------------------------------------------------------------
  if (dest.startsWith('file:')) {
    const rest = dest.slice('file:'.length);
    const node = resolveOne(ctx, rest);
    return { matched: node ? [node] : [], matchStrength: 'direct' };
  }

  // ------------------------------------------------------------------
  // folder:<prefix>
  // ------------------------------------------------------------------
  if (dest.startsWith('folder:')) {
    const rest = dest.slice('folder:'.length);
    // Normalise: ensure trailing slash for prefix match (unless rest already ends with /)
    const prefix = rest.endsWith('/') ? rest : rest + '/';
    const matched = ctx.city.nodes.filter(n => {
      const ref = n.provenance && n.provenance.ref;
      return typeof ref === 'string' && (ref.startsWith(prefix) || ref === rest);
    });
    return { matched, matchStrength: 'folder' };
  }

  // ------------------------------------------------------------------
  // district:<name>
  // ------------------------------------------------------------------
  if (dest.startsWith('district:')) {
    const name = dest.slice('district:'.length).toLowerCase();
    // Build label->id map from city.categories
    const labelToId = new Map();
    for (const cat of (ctx.city.categories || [])) {
      if (cat.label) labelToId.set(String(cat.label).toLowerCase(), String(cat.id).toLowerCase());
    }
    const resolvedCatId = labelToId.get(name) || null;
    const matched = ctx.city.nodes.filter(n => {
      const cat = String(n.category || '').toLowerCase();
      return cat === name || (resolvedCatId !== null && cat === resolvedCatId);
    });
    return { matched, matchStrength: 'district' };
  }

  // ------------------------------------------------------------------
  // importsOf:<idOrRef>
  // ------------------------------------------------------------------
  if (dest.startsWith('importsOf:')) {
    const rest = dest.slice('importsOf:'.length);
    const node = resolveOne(ctx, rest);
    if (!node) return { matched: [], matchStrength: 'edges' };
    const matched = (node.links || []).map(tid => ctx.byId.get(tid)).filter(Boolean);
    return { matched, matchStrength: 'edges' };
  }

  // ------------------------------------------------------------------
  // depChainTo:<idOrRef>
  // Bounded reverse-edge BFS: finds all nodes that transitively import the target.
  // Safety invariants:
  //   - visited Set prevents revisiting nodes (handles cycles A→B→A)
  //   - max depth 6 per BFS level
  //   - hard cap of 500 nodes visited (includes the target seed)
  // ------------------------------------------------------------------
  if (dest.startsWith('depChainTo:')) {
    const rest = dest.slice('depChainTo:'.length);
    const target = resolveOne(ctx, rest);
    if (!target) return { matched: [], matchStrength: 'chain' };
    const targetId = target.id;

    // Build reverse-edge index: nodeId -> Set<callerId>
    // (which nodes have this id in their links)
    const importedBy = new Map();
    for (const n of ctx.city.nodes) {
      for (const link of (n.links || [])) {
        if (!importedBy.has(link)) importedBy.set(link, new Set());
        importedBy.get(link).add(n.id);
      }
    }

    // BFS — each queue entry carries { id, depth }
    const visited = new Set();
    visited.add(targetId);
    const queue = [{ id: targetId, depth: 0 }];

    while (queue.length > 0 && visited.size < 500) {
      const { id, depth } = queue.shift();
      if (depth >= 6) continue;
      const parents = importedBy.get(id);
      if (!parents) continue;
      for (const pid of parents) {
        if (!visited.has(pid)) {
          visited.add(pid);
          queue.push({ id: pid, depth: depth + 1 });
          if (visited.size >= 500) break;
        }
      }
    }

    // Return callers of target, not the target itself
    visited.delete(targetId);
    const matched = [...visited].map(id => ctx.byId.get(id)).filter(Boolean);
    return { matched, matchStrength: 'chain' };
  }

  // ------------------------------------------------------------------
  // no recognized prefix — keyword fallback
  // ------------------------------------------------------------------
  const hits = search(ctx, dest, { limit });
  const matched = hits.map(h => ctx.byId.get(h.id)).filter(Boolean);
  return { matched, matchStrength: 'keyword' };
}
