// KnoSky authorization ground-truth oracle (SAT-450).
// Independent re-derivation of expected authorization outcomes for differential
// fuzzing against kcRoute and kcBundle.  Shares NO code paths with those modules;
// divergence between oracle and system output signals a correctness bug.
//
// Import contract (independence boundary):
//   - findSecrets from ./contract.mjs — raw pattern spec that is the shared ground
//     truth for both oracle and system.  The oracle applies it directly to known
//     content strings; kcBundle applies it via its own file-read path.  Any
//     disagreement exposes a file-read, scan, or aggregation bug in the system.
//   - Nothing else from core/ is imported.
// Pure Node stdlib, ESM — no external dependencies.

import { findSecrets } from './contract.mjs';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Return true when a path string is safe (relative, no "..", no absolute).
 * @param {string} p
 * @returns {boolean}
 */
function isSafePath(p) {
  if (typeof p !== 'string') return false;
  if (p.startsWith('/')) return false;
  if (/^[A-Za-z]:[\\\/]/.test(p)) return false;
  if (p.split(/[/\\]/).includes('..')) return false;
  return true;
}

/**
 * Naive, independent node lookup — re-implements destination resolution without
 * importing parseDestination or any other routing module.
 *
 * Returns { matched: Node[], certain: boolean }:
 *   certain === true  → oracle is confident about the match set (all prefix-typed
 *                        destinations where the answer is structurally determined)
 *   certain === false → keyword fallback or bounded-BFS ambiguity; oracle cannot
 *                        safely predict the exact system result
 *
 * @param {object[]} nodes
 * @param {string}   destination
 * @returns {{ matched: object[], certain: boolean }}
 */
function naiveLookup(nodes, destination) {
  const dest = String(destination || '').trim();

  // An empty graph is always a certain miss, regardless of destination type.
  if (nodes.length === 0) return { matched: [], certain: true };

  const byId = new Map(nodes.map(n => [n.id, n]));

  // ------------------------------------------------------------------
  // file:<idOrRef>
  // ------------------------------------------------------------------
  if (dest.startsWith('file:')) {
    const rest = dest.slice(5);
    const matched = nodes.filter(n =>
      n.id === 'fs:' + rest ||
      n.id === rest ||
      (n.provenance && n.provenance.ref === rest),
    );
    return { matched, certain: true };
  }

  // ------------------------------------------------------------------
  // folder:<prefix>
  // ------------------------------------------------------------------
  if (dest.startsWith('folder:')) {
    const rest = dest.slice(7);
    const prefix = rest.endsWith('/') ? rest : rest + '/';
    const matched = nodes.filter(n => {
      const ref = n.provenance && n.provenance.ref;
      return typeof ref === 'string' && (ref.startsWith(prefix) || ref === rest);
    });
    return { matched, certain: true };
  }

  // ------------------------------------------------------------------
  // district:<name>
  // ------------------------------------------------------------------
  if (dest.startsWith('district:')) {
    const name = dest.slice(9).toLowerCase();
    const matched = nodes.filter(n =>
      String(n.category || '').toLowerCase() === name,
    );
    return { matched, certain: true };
  }

  // ------------------------------------------------------------------
  // importsOf:<idOrRef>
  // ------------------------------------------------------------------
  if (dest.startsWith('importsOf:')) {
    const rest = dest.slice(10);
    const node = nodes.find(n =>
      n.id === 'fs:' + rest ||
      n.id === rest ||
      (n.provenance && n.provenance.ref === rest),
    );
    if (!node) return { matched: [], certain: true };
    const matched = (node.links || []).map(l => byId.get(l)).filter(Boolean);
    return { matched, certain: true };
  }

  // ------------------------------------------------------------------
  // depChainTo:<idOrRef>
  // Oracle only checks for the existence of ANY direct caller; if none
  // exist then no transitive chain can exist either (monotonicity).
  // If direct callers exist the oracle cannot replicate the full BFS
  // without re-implementing destination.mjs, so it marks certain=false.
  // ------------------------------------------------------------------
  if (dest.startsWith('depChainTo:')) {
    const rest = dest.slice(11);
    const target = nodes.find(n =>
      n.id === 'fs:' + rest ||
      n.id === rest ||
      (n.provenance && n.provenance.ref === rest),
    );
    if (!target) return { matched: [], certain: true };
    const hasDirectCaller = nodes.some(n =>
      n.id !== target.id && (n.links || []).includes(target.id),
    );
    if (!hasDirectCaller) return { matched: [], certain: true };
    // Direct callers exist — oracle marks uncertain to avoid false alarms
    return { matched: [target], certain: false };
  }

  // ------------------------------------------------------------------
  // keyword fallback — oracle cannot confidently predict system result
  // (system uses tf-idf-like scoring not replicated here)
  // ------------------------------------------------------------------
  const tokens = (dest.toLowerCase().match(/[a-z0-9]+/g) || []);
  if (!tokens.length) return { matched: [], certain: true };
  return { matched: [], certain: false };
}

// ---------------------------------------------------------------------------
// oracleRouteDecision — expected authorization properties for a route request
// ---------------------------------------------------------------------------

/**
 * Compute the expected authorization invariants for a (ctx, destination) pair.
 * The oracle makes only assertions it can guarantee independently of kcRoute.
 *
 * @param {object} ctx
 * @param {string} destination
 * @returns {{
 *   advisory: true,
 *   protocol: string,
 *   artifactType: string,
 *   confidenceLo: number,
 *   confidenceHi: number,
 *   expectEmptyRoute: boolean,     — true iff oracle is CERTAIN no nodes match
 *   expectZeroConfidence: boolean, — same condition
 *   noBadPaths: true,
 * }}
 */
export function oracleRouteDecision(ctx, destination) {
  const nodes = (ctx && ctx.city && ctx.city.nodes) || [];
  const { matched, certain } = naiveLookup(nodes, destination);

  return {
    advisory: true,
    protocol: '1.0',
    artifactType: 'route',
    confidenceLo: 0,
    confidenceHi: 1,
    // Only enforce empty-route / zero-confidence when the oracle is certain.
    // This prevents false positives from keyword scoring or multi-hop chains.
    expectEmptyRoute: certain && matched.length === 0,
    expectZeroConfidence: certain && matched.length === 0,
    noBadPaths: true,
  };
}

// ---------------------------------------------------------------------------
// verifyRouteDoc — check a route doc against oracle expectations
// ---------------------------------------------------------------------------

/**
 * Verify a route document against the oracle's expected authorization properties.
 * Returns every deviation found — the caller decides whether to fail.
 *
 * @param {object} doc           — route doc produced by kcRoute
 * @param {object} expectations  — from oracleRouteDecision
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function verifyRouteDoc(doc, expectations) {
  const v = [];

  if (doc.advisory !== expectations.advisory) {
    v.push(`advisory: oracle=${expectations.advisory}, system=${doc.advisory}`);
  }
  if (doc.knosky_protocol !== expectations.protocol) {
    v.push(`knosky_protocol: oracle="${expectations.protocol}", system=${JSON.stringify(doc.knosky_protocol)}`);
  }
  if (doc.artifact_type !== expectations.artifactType) {
    v.push(`artifact_type: oracle="${expectations.artifactType}", system=${JSON.stringify(doc.artifact_type)}`);
  }

  const conf = doc.confidence;
  if (typeof conf !== 'number' || !Number.isFinite(conf) ||
      conf < expectations.confidenceLo || conf > expectations.confidenceHi) {
    v.push(`confidence out of [${expectations.confidenceLo},${expectations.confidenceHi}]: ${conf}`);
  }

  if (expectations.expectEmptyRoute && Array.isArray(doc.route) && doc.route.length > 0) {
    v.push(`expected empty route (oracle: no matching nodes), got ${doc.route.length} entries`);
  }
  if (expectations.expectZeroConfidence && typeof conf === 'number' && conf !== 0) {
    v.push(`expected confidence=0 (oracle: no matching nodes), got ${conf}`);
  }

  if (expectations.noBadPaths) {
    const allPaths = [
      ...(Array.isArray(doc.route)      ? doc.route.map(e => (typeof e === 'string' ? e : e && e.path)) : []),
      ...(Array.isArray(doc.alternates) ? doc.alternates.map(e => (typeof e === 'string' ? e : e && e.path)) : []),
    ].filter(p => typeof p === 'string');
    for (const p of allPaths) {
      if (!isSafePath(p)) {
        v.push(`unsafe path in route output: ${JSON.stringify(p)}`);
      }
    }
  }

  return { ok: v.length === 0, violations: v };
}

// ---------------------------------------------------------------------------
// oracleScanDecision — expected secret-scan outcome for known file contents
// ---------------------------------------------------------------------------

/**
 * Compute the expected secret_scan result given an array of { ref, content } entries.
 * Applies findSecrets independently to each entry's content and aggregates.
 * Does NOT use kcBundle — disagreements with the system expose scan/read bugs.
 *
 * @param {Array<{ ref: string, content: string }>} fileEntries
 * @returns {{ status: 'clean'|'blocked', totalMatches: number }}
 */
export function oracleScanDecision(fileEntries) {
  let totalMatches = 0;
  let anyBlocked = false;
  for (const { content } of (fileEntries || [])) {
    const hits = findSecrets(String(content || ''));
    if (hits.length > 0) {
      anyBlocked = true;
      for (const [, count] of hits) totalMatches += count;
    }
  }
  return {
    status: anyBlocked ? 'blocked' : 'clean',
    totalMatches,
  };
}

// ---------------------------------------------------------------------------
// verifyScanDecision — check a manifest's secret_scan against oracle
// ---------------------------------------------------------------------------

/**
 * Verify an intent-manifest's secret_scan field against the oracle's expectation.
 *
 * @param {object} manifest     — from kcBundle
 * @param {object} oracleResult — from oracleScanDecision
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function verifyScanDecision(manifest, oracleResult) {
  const v = [];
  if (!manifest || typeof manifest !== 'object') {
    v.push('manifest is not an object');
    return { ok: false, violations: v };
  }
  if (manifest.advisory !== true) {
    v.push(`manifest advisory must be true, got ${manifest.advisory}`);
  }
  if (!manifest.secret_scan || typeof manifest.secret_scan !== 'object') {
    v.push('manifest secret_scan is missing or not an object');
    return { ok: false, violations: v };
  }
  if (manifest.secret_scan.status !== oracleResult.status) {
    v.push(
      `secret_scan.status: oracle="${oracleResult.status}", ` +
      `system="${manifest.secret_scan.status}"`,
    );
  }
  return { ok: v.length === 0, violations: v };
}
