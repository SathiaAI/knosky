// KnoSky route engine (KSV2-R1) — structural destination -> ranked advisory route.
// Pure Node stdlib + internal imports only. ESM. No new deps.
import { search, getRelated } from './retrieve.mjs';
import { makeRouteDoc, validateRouteDoc } from './schema.mjs';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Guard: a path from provenance.ref should never be absolute or contain "..".
 * Returns true when the path is safe to include in output.
 * @param {string|undefined} ref
 * @returns {boolean}
 */
function isSafeRef(ref) {
  if (!ref || typeof ref !== 'string') return false;
  if (ref.startsWith('/')) return false;
  if (/^[A-Za-z]:[\\\/]/.test(ref)) return false;
  if (ref.split(/[/\\]/).some(seg => seg === '..')) return false;
  return true;
}

/**
 * Return the node's provenance.ref, or null if missing/unsafe.
 * @param {object} node
 * @returns {string|null}
 */
function safeRef(node) {
  const ref = node.provenance && node.provenance.ref;
  return isSafeRef(ref) ? ref : null;
}

/**
 * Return true when node looks like a test file.
 * @param {object} node
 */
function isTest(node) {
  const ref = safeRef(node) || '';
  const cat = String(node.category || '').toLowerCase();
  return (
    cat === 'test' ||
    /\/test\//.test(ref) ||
    /\.test\./.test(ref) ||
    /\.spec\./.test(ref) ||
    /\/test\//.test(node.id || '')
  );
}

/**
 * Return true when node looks like a docs file.
 * @param {object} node
 */
function isDoc(node) {
  const ref = safeRef(node) || '';
  const cat = String(node.category || '').toLowerCase();
  return (
    cat === 'docs' ||
    cat === 'documentation' ||
    ref.endsWith('.md') ||
    ref.endsWith('.rst') ||
    ref.endsWith('.txt')
  );
}

// ---------------------------------------------------------------------------
// Destination parser (R1 set)
// ---------------------------------------------------------------------------

/**
 * Resolve the destination string to an initial set of matching nodes.
 * Returns { matched: Node[], matchStrength: 'direct'|'folder'|'keyword' }
 *
 * @param {object} ctx    — retrieve context {city, byId}
 * @param {string} destination
 * @param {number} limit
 */
function parseDestination(ctx, destination, limit) {
  const dest = String(destination || '').trim();

  // prefix: file:<path> — match by id "fs:<rest>" OR by provenance.ref === <rest>
  if (dest.startsWith('file:')) {
    const rest = dest.slice('file:'.length);
    const byNodeId = ctx.byId.get('fs:' + rest);
    if (byNodeId) return { matched: [byNodeId], matchStrength: 'direct' };
    // fallback: scan provenance.ref
    const byRef = ctx.city.nodes.find(n => n.provenance && n.provenance.ref === rest);
    if (byRef) return { matched: [byRef], matchStrength: 'direct' };
    return { matched: [], matchStrength: 'direct' };
  }

  // prefix: folder:<path> — all nodes whose provenance.ref starts with <rest>
  if (dest.startsWith('folder:')) {
    const rest = dest.slice('folder:'.length);
    // normalise: ensure trailing slash for prefix match unless rest already ends with /
    const prefix = rest.endsWith('/') ? rest : rest + '/';
    const matched = ctx.city.nodes.filter(n => {
      const ref = n.provenance && n.provenance.ref;
      return typeof ref === 'string' && (ref.startsWith(prefix) || ref === rest);
    });
    return { matched, matchStrength: 'folder' };
  }

  // no prefix — keyword fallback via search
  const hits = search(ctx, dest, { limit });
  const matched = hits.map(h => ctx.byId.get(h.id)).filter(Boolean);
  return { matched, matchStrength: 'keyword' };
}

// ---------------------------------------------------------------------------
// kcRoute — main export
// ---------------------------------------------------------------------------

/**
 * Build a ranked, advisory, metadata-only route doc.
 *
 * @param {object} ctx         — retrieve context from load()
 * @param {string} destination — navigation target string
 * @param {object} [opts]
 * @param {number} [opts.limit=8] — max route entries
 * @returns {object} route doc (passes validateRouteDoc)
 */
export function kcRoute(ctx, destination, { limit = 8 } = {}) {
  const clampedLimit = Math.max(1, Math.min(20, limit));
  const { matched, matchStrength } = parseDestination(ctx, destination, clampedLimit);

  // Collect direct-match ids for scoring
  const directIds = new Set(matched.map(n => n.id));

  // Expand to 1-hop neighbours via getRelated (imports + importedBy); de-dupe by id
  const candidateMap = new Map();
  for (const n of matched) {
    candidateMap.set(n.id, n);
  }

  for (const n of matched) {
    const rel = getRelated(ctx, n.id);
    if (!rel) continue;
    for (const imp of rel.imports.concat(rel.importedBy)) {
      if (!candidateMap.has(imp.id)) {
        const full = ctx.byId.get(imp.id);
        if (full) candidateMap.set(imp.id, full);
      }
    }
  }

  // Score candidates
  const caveats = [];
  const seenChurnCaveat = false;
  const scored = [];

  for (const [id, node] of candidateMap) {
    let score = 0;
    const reasons = [];

    if (directIds.has(id)) {
      score += 5;
      reasons.push('destination match');
    }

    // imported-by / import-proximity: node imports a direct-match OR is imported by a direct-match
    const rel = getRelated(ctx, id);
    if (rel) {
      const importsDirectMatch = rel.imports.some(m => directIds.has(m.id));
      const importedByDirectMatch = rel.importedBy.some(m => directIds.has(m.id));
      if (importsDirectMatch || importedByDirectMatch) {
        score += 2;
        reasons.push(importsDirectMatch ? 'imports destination' : 'imported by destination');
      }
    }

    // churn signal
    if (node.churn && typeof node.churn === 'object' && node.churn.c > 0) {
      score += 1;
      reasons.push('recently changed');
    } else if (typeof node.churn === 'number' && node.churn > 0) {
      score += 1;
      reasons.push('recently changed');
    }

    scored.push({ id, node, score, reason: reasons.join('; ') || 'neighbourhood match' });
  }

  // Sort: score desc, then id asc
  scored.sort((a, b) => b.score - a.score || String(a.id).localeCompare(String(b.id)));

  // Build caveats
  // — churn caveat for any high-churn file in the top results
  const topCandidates = scored.slice(0, clampedLimit + 5); // check a bit beyond route
  for (const s of topCandidates) {
    const churn = s.node.churn;
    const hasChurn = (churn && typeof churn === 'object' && churn.c > 0) ||
                     (typeof churn === 'number' && churn > 0);
    if (hasChurn) {
      caveats.push('recently changed: ' + (s.node.provenance && s.node.provenance.ref || s.id) + ' has high churn — verify before acting');
      break; // one caveat entry is sufficient
    }
  }

  // — coverage unknown caveat when a candidate lacks coverage data
  const hasCoverageGap = scored.some(s => s.node.coverage === undefined || s.node.coverage === null);
  if (hasCoverageGap) {
    caveats.push('coverage unknown: one or more nodes lack coverage overlay data');
  }

  // — mandatory advisory caveat (always present)
  caveats.push('advisory route — verify before acting; KnoSky does not read code meaning');

  // — staleness caveat when source_rev is present
  const source_rev = ctx.city.source_rev || null;
  if (source_rev) {
    caveats.push('route is based on rev ' + source_rev + ' and may be stale');
  }

  // Slice into route + alternates
  const routeEntries = scored.slice(0, clampedLimit);
  const alternateEntries = scored.slice(clampedLimit, clampedLimit + 5);

  function toEntry(s) {
    const path = safeRef(s.node) || s.id;
    return { path, id: s.id, reason: s.reason, score: s.score };
  }

  const route = routeEntries.map(toEntry).filter(e => isSafeRef(e.path) || !e.path.startsWith('/'));
  const alternates = alternateEntries.map(toEntry).filter(e => isSafeRef(e.path) || !e.path.startsWith('/'));

  // Confidence: direct match -> linear by top score; folder -> mid; keyword-only -> lower
  let confidence = 0;
  if (routeEntries.length > 0) {
    const topScore = routeEntries[0].score;
    if (matchStrength === 'direct') {
      // direct hit scores at least 5; normalise to ~0.9 max
      confidence = Math.min(0.95, topScore / 10);
    } else if (matchStrength === 'folder') {
      confidence = Math.min(0.75, topScore / 10);
    } else {
      // keyword — lower ceiling
      confidence = Math.min(0.6, topScore / 20);
    }
    confidence = Math.max(0, Math.min(1, confidence));
  }

  // Classify tests / docs from all candidates
  const tests = [];
  const docs = [];
  for (const [, node] of candidateMap) {
    const ref = safeRef(node);
    if (!ref) continue;
    if (isTest(node)) tests.push({ path: ref, id: node.id });
    else if (isDoc(node)) docs.push({ path: ref, id: node.id });
  }

  const doc = makeRouteDoc({
    destination,
    route,
    alternates,
    caveats,
    confidence,
    source_rev,
  });

  // Attach tests + docs (extra fields beyond the base envelope — schema.validateRouteDoc does not reject them)
  doc.tests = tests;
  doc.docs = docs;

  // Invariant: doc MUST pass validateRouteDoc
  const validation = validateRouteDoc(doc);
  if (!validation.ok) {
    throw new Error('kcRoute produced an invalid route doc: ' + validation.errors.join('; '));
  }

  return doc;
}
