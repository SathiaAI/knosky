// Cross-repo graph utilities (SAT-448): edge detection, boundary extraction, and rendering metadata.
// Pure logic — no filesystem access, no new deps. Works on the in-memory city/byId structures
// produced by retrieve.load() or any equivalent.
//
// A node's *repo* identity is determined by provenance.repo when present, falling back to
// provenance.store (e.g. "fs", "gh:owner/repo") so existing city data stays fully compatible —
// single-repo graphs have no cross-repo edges because every node shares the same store value.

// ---------------------------------------------------------------------------
// repoOf
// ---------------------------------------------------------------------------

/**
 * Return the repository identity of a node.
 * Preference order:
 *   1. node.provenance.repo  — explicit multi-repo label (new field, optional)
 *   2. node.provenance.store — always present; used as the identity when repo is absent
 *      (works correctly for single-repo graphs: all nodes share one store → no cross edges)
 *
 * Returns null if provenance is absent or malformed.
 *
 * @param {object} node
 * @returns {string|null}
 */
export function repoOf(node) {
  if (!node || typeof node !== 'object') return null;
  const prov = node.provenance;
  if (!prov || typeof prov !== 'object') return null;
  if (typeof prov.repo === 'string' && prov.repo.length > 0) return prov.repo;
  if (typeof prov.store === 'string' && prov.store.length > 0) return prov.store;
  return null;
}

// ---------------------------------------------------------------------------
// isCrossRepoEdge
// ---------------------------------------------------------------------------

/**
 * Return true when the edge (fromId → toId) crosses a repo boundary.
 * An edge is cross-repo when repoOf(fromNode) !== repoOf(toNode) AND both are non-null.
 * Edges where either endpoint is missing or has no repo identity are treated as same-repo
 * (conservative: no false positives).
 *
 * @param {Map<string, object>} byId   — node map from retrieve.load()
 * @param {string}              fromId
 * @param {string}              toId
 * @returns {boolean}
 */
export function isCrossRepoEdge(byId, fromId, toId) {
  const src = byId.get(fromId);
  const dst = byId.get(toId);
  if (!src || !dst) return false;
  const r1 = repoOf(src);
  const r2 = repoOf(dst);
  if (r1 === null || r2 === null) return false;
  return r1 !== r2;
}

// ---------------------------------------------------------------------------
// getCrossRepoEdges
// ---------------------------------------------------------------------------

/**
 * Walk every node's `links` array and return all edges that cross a repo boundary.
 *
 * @param {object} ctx  — { city: { nodes: [] }, byId: Map }
 * @returns {Array<{ from: string, to: string, fromRepo: string, toRepo: string }>}
 */
export function getCrossRepoEdges(ctx) {
  const edges = [];
  for (const node of (ctx.city.nodes || [])) {
    if (!Array.isArray(node.links)) continue;
    const fromRepo = repoOf(node);
    if (fromRepo === null) continue;
    for (const toId of node.links) {
      const dst = ctx.byId.get(toId);
      if (!dst) continue;
      const toRepo = repoOf(dst);
      if (toRepo === null) continue;
      if (fromRepo !== toRepo) {
        edges.push({ from: node.id, to: toId, fromRepo, toRepo });
      }
    }
  }
  return edges;
}

// ---------------------------------------------------------------------------
// getRepoBoundaries
// ---------------------------------------------------------------------------

/**
 * Return a summary of every distinct repo present in the graph and its node membership.
 *
 * @param {object} ctx  — { city: { nodes: [] }, byId: Map }
 * @returns {Array<{ repo: string, nodeIds: string[], count: number }>}
 *            Sorted by count desc, then repo asc.
 */
export function getRepoBoundaries(ctx) {
  /** @type {Map<string, string[]>} */
  const byRepo = new Map();
  for (const node of (ctx.city.nodes || [])) {
    const r = repoOf(node);
    if (r === null) continue;
    if (!byRepo.has(r)) byRepo.set(r, []);
    byRepo.get(r).push(node.id);
  }
  return [...byRepo.entries()]
    .map(([repo, nodeIds]) => ({ repo, nodeIds, count: nodeIds.length }))
    .sort((a, b) => b.count - a.count || String(a.repo).localeCompare(String(b.repo)));
}
