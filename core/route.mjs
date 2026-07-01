// KnoSky route engine (KSV2-R1/R2/R3) — structural destination -> ranked advisory route.
// Pure Node stdlib + internal imports only. ESM. No new deps.
import { getRelated } from './retrieve.mjs';
import { makeRouteDoc, validateRouteDoc } from './schema.mjs';
import { parseDestination } from './destination.mjs';

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

/**
 * Tokenise a string into lowercase alphanumeric tokens, stripping any "word:" prefix.
 * @param {string} str
 * @returns {Set<string>}
 */
function tokenise(str) {
  const stripped = String(str || '').replace(/^\w+:/, '');
  return new Set((stripped.toLowerCase().match(/[a-z0-9]+/g) || []));
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
 * @param {number} [opts.limit=8]    — max route entries
 * @param {object} [opts.overlays]   — optional overlay map from readOverlays():
 *                                     { '<relpath>': { coverage?: number(0..100), test?: 'pass'|'fail' } }
 *                                     Absence means coverage is unknown — the coverage-unknown caveat fires.
 * @returns {object} route doc (passes validateRouteDoc)
 */
export function kcRoute(ctx, destination, { limit = 8, overlays } = {}) {
  const clampedLimit = Math.max(1, Math.min(20, limit));
  const { matched, matchStrength } = parseDestination(ctx, destination, clampedLimit);

  // Collect direct-match ids + categories for scoring
  const directIds = new Set(matched.map(n => n.id));
  const directCategories = new Set(
    matched.map(n => String(n.category || '').toLowerCase()).filter(Boolean),
  );

  // Destination keyword tokens (strip any "word:" prefix)
  const destTokens = tokenise(destination);

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
  const lowCoverageCaveats = [];
  const scored = [];

  for (const [id, node] of candidateMap) {
    let score = 0;
    const reasons = [];

    // Signal 1: destination match (+5)
    if (directIds.has(id)) {
      score += 5;
      reasons.push('destination');
    }

    // Signal 2: import proximity (+2)
    const rel = getRelated(ctx, id);
    if (rel) {
      const importsDirectMatch = rel.imports.some(m => directIds.has(m.id));
      const importedByDirectMatch = rel.importedBy.some(m => directIds.has(m.id));
      if (importsDirectMatch || importedByDirectMatch) {
        score += 2;
        reasons.push(importsDirectMatch ? 'imports destination' : 'imported by destination');
      }
    }

    // Signal 3: same district (+1.5) — shares category with a direct match but is not itself a direct match
    if (!directIds.has(id) && directCategories.size > 0) {
      const cat = String(node.category || '').toLowerCase();
      if (cat && directCategories.has(cat)) {
        score += 1.5;
        reasons.push('same district');
      }
    }

    // Signal 4: keyword overlap (+1, capped once)
    if (destTokens.size > 0) {
      const candidateText = [node.title || '', ...(node.headings || [])].join(' ');
      const candidateTokens = tokenise(candidateText);
      const hasOverlap = [...destTokens].some(t => candidateTokens.has(t));
      if (hasOverlap) {
        score += 1;
        reasons.push('name/heading match');
      }
    }

    // Signal 5: recently changed (+1)
    if (node.churn && typeof node.churn === 'object' && node.churn.c > 0) {
      score += 1;
      reasons.push('recently changed');
    } else if (typeof node.churn === 'number' && node.churn > 0) {
      score += 1;
      reasons.push('recently changed');
    }

    // Signal 6: low coverage (+0.5 if overlays provided and coverage < 50)
    if (overlays !== undefined && overlays !== null) {
      const ref = safeRef(node);
      if (ref) {
        const overlay = overlays[ref];
        if (overlay && typeof overlay.coverage === 'number') {
          if (overlay.coverage < 50) {
            score += 0.5;
            lowCoverageCaveats.push(
              'low coverage: ' + ref + ' (' + Math.round(overlay.coverage) + '%) — extra review advised',
            );
          }
          // coverage >= 50: no change, no penalty
        }
      }
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

  // — low-coverage caveats (one per underperforming file, from signal 6)
  for (const c of lowCoverageCaveats) {
    caveats.push(c);
  }

  // — coverage unknown caveat: only when overlays were NOT provided
  if (overlays === undefined || overlays === null) {
    const hasCoverageGap = scored.some(s => s.node.coverage === undefined || s.node.coverage === null);
    if (hasCoverageGap) {
      caveats.push('coverage unknown: one or more nodes lack coverage overlay data');
    }
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

  // Defense in depth: only isSafeRef() gates output (the previous `|| !path.startsWith('/')`
  // clause was a bug — any path lacking a leading '/' but containing '..' would pass through
  // it unfiltered; validateRouteDoc() catches that downstream today, but this filter should
  // not have been able to let it through in the first place).
  const route = routeEntries.map(toEntry).filter(e => isSafeRef(e.path));
  const alternates = alternateEntries.map(toEntry).filter(e => isSafeRef(e.path));

  // Confidence: direct -> ~0.95 ceiling; folder/district/edges/chain -> ~0.75; keyword -> ~0.6
  let confidence = 0;
  if (routeEntries.length > 0) {
    const topScore = routeEntries[0].score;
    if (matchStrength === 'direct') {
      // direct hit scores at least 5; normalise to ~0.95 max
      confidence = Math.min(0.95, topScore / 10);
    } else if (matchStrength === 'folder' || matchStrength === 'district' ||
               matchStrength === 'edges' || matchStrength === 'chain') {
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
