// KnoSky adversarial tile/subgraph probing tests (SAT-454).
// Threat model: an agent operating against a multi-repo (or single-repo) KnoSky
// context attempts direct tile/subgraph access to nodes it should not be able to
// reach — foreign-repo namespaces, dangling cross-repo links, path-traversal via
// repo-code prefixes, and route-path safety across repo boundaries.
//
// All tests are pure in-memory (no filesystem, no git). The fixture builds a
// minimal two-repo graph so behaviours are unambiguous.
//
// Run: node test/cross-repo-tile-probe.mjs

import { parseDestination } from '../core/destination.mjs';
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';
import { getCrossRepoEdges, getRepoBoundaries, isCrossRepoEdge, repoOf } from '../core/cross-repo.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Two-repo graph: repo-1 has two nodes, one of which links to repo-2.
// repo-2 has one node (the link target) and one node that repo-1 never touches.
// The "secret" node in repo-2 is never reachable from repo-1 via explicit links.
const REPO_1 = 'org/repo-1';
const REPO_2 = 'org/repo-2';

function n(id, repo, links = []) {
  const ref = id.replace(/^[^:]+:/, '');   // strip the "r1:" / "r2:" prefix
  return {
    id,
    kind: 'file',
    title: id,
    category: 'code',
    headings: [],
    tags: [],
    links,
    churn: null,
    provenance: { store: 'git', ref, repo },
  };
}

// repo-1 nodes
const nR1A  = n('r1:src/a.js',      REPO_1, ['r1:src/c.js', 'r2:lib/b.js']); // crosses into repo-2
const nR1C  = n('r1:src/c.js',      REPO_1, []);
// repo-2 nodes
const nR2B  = n('r2:lib/b.js',      REPO_2, []);              // the only node R1 links to
const nR2S  = n('r2:secret/key.js', REPO_2, []);              // never linked from R1

const allNodes = [nR1A, nR1C, nR2B, nR2S];
const multiRepoCtx = {
  city: {
    nodes: allNodes,
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    source_rev: 'deadbeef',
  },
  byId: new Map(allNodes.map(nd => [nd.id, nd])),
};

// Single-repo context — only R1 nodes; cross-repo IDs are absent from byId
const r1Nodes = [nR1A, nR1C];
const singleRepoCtx = {
  city: {
    nodes: r1Nodes,
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    source_rev: null,
  },
  byId: new Map(r1Nodes.map(nd => [nd.id, nd])),
};

// Minimal single-repo context with NO cross-repo links at all (clean isolation baseline)
const cleanNodes = [
  {
    id: 'fs:src/auth.js', kind: 'file', title: 'Auth', category: 'code',
    headings: [], tags: [], links: ['fs:src/utils.js'],
    churn: null, provenance: { store: 'fs', ref: 'src/auth.js' },
  },
  {
    id: 'fs:src/utils.js', kind: 'file', title: 'Utils', category: 'code',
    headings: [], tags: [], links: [],
    churn: null, provenance: { store: 'fs', ref: 'src/utils.js' },
  },
];
const cleanCtx = {
  city: {
    nodes: cleanNodes,
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    source_rev: null,
  },
  byId: new Map(cleanNodes.map(nd => [nd.id, nd])),
};

// ===========================================================================
// SECTION 1 — Direct tile probing: single-repo context
// An agent holds a single-repo context.  Any probe targeting a cross-repo
// namespace (r2:, cg:, etc.) must resolve to zero nodes — those tiles simply
// don't exist in the context.
// ===========================================================================
console.log('\n--- 1. Direct tile probing (single-repo context) ---');

// (1a) file: with a foreign-namespace id → no match
{
  for (const dest of [
    'file:r2:lib/b.js',
    'file:r2:secret/key.js',
    'file:cg:tools/cache/controller.go',
    'file:k8s:plugin/pkg/auth/authorizer/rbac/rbac.go',
  ]) {
    const { matched } = parseDestination(cleanCtx, dest, 10);
    ok(`(1a) file: foreign-namespace tile "${dest}" in single-repo ctx → 0 matches`,
      matched.length === 0, `got ${matched.length}`);
  }
}

// (1b) depChainTo: with a foreign-namespace target → no match
//      The target node does not exist in byId; BFS terminates immediately.
{
  for (const dest of [
    'depChainTo:r2:lib/b.js',
    'depChainTo:cg:tools/cache/controller.go',
  ]) {
    const { matched, matchStrength } = parseDestination(cleanCtx, dest, 10);
    ok(`(1b) depChainTo: foreign-namespace target "${dest}" → 0 matches`,
      matched.length === 0, `got ${matched.length}`);
    ok(`(1b) depChainTo: matchStrength is still "chain"`, matchStrength === 'chain');
  }
}

// (1c) importsOf: a node with dangling cross-repo links returns nothing for those links
//      Because the targets are absent from byId, importsOf silently drops them.
{
  // nR1A has a link to r2:lib/b.js; build a context where r2:lib/b.js is NOT present
  const r1Only = {
    city: { nodes: [nR1A, nR1C], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[nR1A.id, nR1A], [nR1C.id, nR1C]]),
  };
  const { matched } = parseDestination(r1Only, 'importsOf:r1:src/a.js', 10);
  // r1:src/a.js links to both r1:src/c.js (present) and r2:lib/b.js (absent)
  ok('(1c) importsOf: present same-repo link is returned', matched.some(nd => nd.id === 'r1:src/c.js'));
  ok('(1c) importsOf: dangling cross-repo link is silently dropped (not in byId)',
    !matched.some(nd => nd.id === 'r2:lib/b.js'),
    matched.map(nd => nd.id).join(', '));
}

// (1d) folder: probe with a foreign-repo path prefix returns nothing
//      provenance.ref values are repo-relative (no "r2:" prefix), so "r2:lib" matches nothing.
{
  const { matched: m1 } = parseDestination(cleanCtx, 'folder:r2:', 10);
  ok('(1d) folder: with r2: prefix in single-repo ctx → 0 matches', m1.length === 0);
  const { matched: m2 } = parseDestination(cleanCtx, 'folder:cg:tools', 10);
  ok('(1d) folder: with cg: prefix in single-repo ctx → 0 matches', m2.length === 0);
}

// (1e) district: search returns only nodes from the active context —
//      if a foreign repo shares a category name, absent nodes don't appear.
{
  const { matched } = parseDestination(cleanCtx, 'district:code', 10);
  ok('(1e) district: search returns only present context nodes', matched.length === cleanNodes.length);
  const allFromCtx = matched.every(nd => cleanCtx.byId.has(nd.id));
  ok('(1e) district: every returned node is in single-repo ctx', allFromCtx);
}

// ===========================================================================
// SECTION 2 — Route path safety
// The kcRoute engine must not leak foreign-node IDs into route/alternates even
// when the focus node carries a dangling cross-repo link.
// ===========================================================================
console.log('\n--- 2. Route path safety ---');

// (2a) kcRoute for a node whose links include a dangling cross-repo ref:
//      the foreign node id must not appear in route[] or alternates[].
{
  const r1Only = {
    city: { nodes: [nR1A, nR1C], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[nR1A.id, nR1A], [nR1C.id, nR1C]]),
  };
  let doc = null, threw = false;
  try { doc = kcRoute(r1Only, 'file:r1:src/a.js'); } catch { threw = true; }
  ok('(2a) kcRoute with dangling cross-repo link does not throw', !threw);
  if (doc) {
    const foreignIds = [...(doc.route || []), ...(doc.alternates || [])]
      .filter(e => typeof e.id === 'string' && e.id.startsWith('r2:'));
    ok('(2a) no r2: ids in route[] or alternates[]', foreignIds.length === 0,
      foreignIds.map(e => e.id).join(', '));
    ok('(2a) route doc is valid', validateRouteDoc(doc).ok === true);
    ok('(2a) advisory is true', doc.advisory === true);
  }
}

// (2b) Route paths must be relative — no absolute, no .., no URL schemes
{
  const doc = kcRoute(multiRepoCtx, 'file:r1:src/a.js');
  const allPaths = [
    ...(doc.route      || []).map(e => e.path),
    ...(doc.alternates || []).map(e => e.path),
    ...(doc.tests      || []).map(e => e.path),
    ...(doc.docs       || []).map(e => e.path),
  ].filter(p => typeof p === 'string');
  const badPaths = allPaths.filter(p =>
    p.startsWith('/') ||
    /^[A-Za-z]:[\\\/]/.test(p) ||
    p.split(/[/\\]/).some(s => s === '..') ||
    /^[a-z]+:\/\//.test(p),
  );
  ok('(2b) all route paths are relative (no absolute, no .., no URL schemes)',
    badPaths.length === 0, JSON.stringify(badPaths));
}

// (2c) kcRoute for the node in multi-repo context — the cross-repo target
//      r2:lib/b.js IS present in byId, so it can appear in route, but
//      the unreachable/unlinked node r2:secret/key.js must NOT appear.
{
  const doc = kcRoute(multiRepoCtx, 'file:r1:src/a.js');
  const routeIds = new Set([...(doc.route||[]), ...(doc.alternates||[])].map(e=>e.id));
  ok('(2c) linked cross-repo node (r2:lib/b.js) may appear in multi-repo route',
    routeIds.has('r2:lib/b.js') || true); // informational — we only enforce the negative
  ok('(2c) unlinked/unreachable cross-repo node (r2:secret/key.js) absent from route',
    !routeIds.has('r2:secret/key.js'),
    JSON.stringify([...routeIds]));
}

// ===========================================================================
// SECTION 3 — Path traversal via cross-repo namespace
// Using ".." segments inside a repo-namespaced destination (file:r2:../../etc)
// must never match any node and must never throw.
// ===========================================================================
console.log('\n--- 3. Path traversal via cross-repo namespace ---');

// (3a) file: with "../../etc/passwd" disguised in a repo-code namespace
{
  const traversalDestinations = [
    'file:r1:../../etc/passwd',
    'file:r2:../../etc/shadow',
    'file:cg:../../../.env',
    'file:r2:../secret/key.js',   // exists in multi-repo ctx as 'r2:secret/key.js', but traversal path won't resolve
  ];
  for (const dest of traversalDestinations) {
    let threw = false, result = null;
    try { result = parseDestination(multiRepoCtx, dest, 10); } catch { threw = true; }
    ok(`(3a) parseDestination does not throw on "${dest}"`, !threw);
    if (result) {
      ok(`(3a) traversal destination "${dest}" resolves to 0 matches`, result.matched.length === 0,
        `got ${result.matched.length}`);
    }
  }
}

// (3b) Traversal destination through kcRoute — no throw, no bad paths
{
  for (const dest of ['file:r2:../../etc/passwd', 'depChainTo:r1:../../.env']) {
    let threw = false, doc = null;
    try { doc = kcRoute(multiRepoCtx, dest); } catch { threw = true; }
    ok(`(3b) kcRoute does not throw on hostile dest "${dest}"`, !threw);
    if (doc) {
      ok(`(3b) route doc for "${dest}" is valid`, validateRouteDoc(doc).ok === true);
      const allPaths = [...(doc.route||[]), ...(doc.alternates||[])].map(e=>e.path);
      const hasDotDot = allPaths.some(p => p.split(/[/\\]/).includes('..'));
      ok(`(3b) no ".." segments in route output for "${dest}"`, !hasDotDot, JSON.stringify(allPaths));
    }
  }
}

// (3c) Keyword destinations that look like path traversal strings — no crash
{
  const keywordTraversals = [
    '../../etc/passwd',
    '/etc/shadow',
    '../secret.js',
    'r2:lib/b.js',   // keyword fallback (no recognized prefix works as keyword)
    'C:\\Windows\\System32',
  ];
  for (const dest of keywordTraversals) {
    let threw = false, doc = null;
    try { doc = kcRoute(cleanCtx, dest); } catch { threw = true; }
    ok(`(3c) kcRoute keyword-fallback on "${dest.slice(0,30)}" does not throw`, !threw);
    if (doc) {
      ok(`(3c) advisory is true for keyword-fallback on "${dest.slice(0,30)}"`, doc.advisory === true);
      const allPaths = [...(doc.route||[]), ...(doc.alternates||[])].map(e=>e.path);
      const badPaths = allPaths.filter(p => p.startsWith('/') || p.split(/[/\\]/).includes('..'));
      ok(`(3c) no bad paths in output for "${dest.slice(0,30)}"`, badPaths.length === 0);
    }
  }
}

// ===========================================================================
// SECTION 4 — Cross-repo subgraph boundaries (multi-repo context)
// Validates that the boundary utilities correctly isolate and report repos.
// ===========================================================================
console.log('\n--- 4. Cross-repo subgraph boundaries ---');

// (4a) depChainTo in multi-repo context: only nodes that actually link to the
//      target are returned; the target's own repo doesn't self-include.
{
  // r2:lib/b.js is the target — only r1:src/a.js links to it
  const { matched, matchStrength } = parseDestination(multiRepoCtx, 'depChainTo:r2:lib/b.js', 20);
  const ids = matched.map(nd => nd.id);
  ok('(4a) depChainTo r2:lib/b.js: r1:src/a.js (direct caller) is present',
    ids.includes('r1:src/a.js'), ids.join(', '));
  ok('(4a) depChainTo r2:lib/b.js: target repo node r2:secret/key.js is NOT in callers',
    !ids.includes('r2:secret/key.js'), ids.join(', '));
  ok('(4a) depChainTo r2:lib/b.js: target itself (r2:lib/b.js) excluded from callers',
    !ids.includes('r2:lib/b.js'), ids.join(', '));
  ok('(4a) matchStrength is "chain"', matchStrength === 'chain');
}

// (4b) getCrossRepoEdges detects every repo boundary crossing
{
  const edges = getCrossRepoEdges(multiRepoCtx);
  // r1:src/a.js → r2:lib/b.js is the only cross-repo link in the fixture
  ok('(4b) exactly one cross-repo edge in fixture graph', edges.length === 1,
    JSON.stringify(edges));
  ok('(4b) edge origin is r1:src/a.js', edges[0]?.from === 'r1:src/a.js');
  ok('(4b) edge destination is r2:lib/b.js', edges[0]?.to === 'r2:lib/b.js');
  ok('(4b) fromRepo is org/repo-1', edges[0]?.fromRepo === REPO_1);
  ok('(4b) toRepo is org/repo-2', edges[0]?.toRepo === REPO_2);

  // Consistent with isCrossRepoEdge
  ok('(4b) isCrossRepoEdge agrees with getCrossRepoEdges result',
    isCrossRepoEdge(multiRepoCtx.byId, edges[0].from, edges[0].to) === true);

  // The intra-repo link r1:src/a.js → r1:src/c.js is NOT a cross-repo edge
  const hasSameRepoEdge = edges.some(e => e.from === 'r1:src/a.js' && e.to === 'r1:src/c.js');
  ok('(4b) same-repo edge (r1→r1) absent from getCrossRepoEdges result', !hasSameRepoEdge);
}

// (4c) getRepoBoundaries partitions nodes by repo without mixing
{
  const bounds = getRepoBoundaries(multiRepoCtx);
  ok('(4c) exactly two repos in fixture graph', bounds.length === 2,
    bounds.map(b => b.repo).join(', '));

  const r1Bound = bounds.find(b => b.repo === REPO_1);
  const r2Bound = bounds.find(b => b.repo === REPO_2);
  ok('(4c) org/repo-1 boundary present', r1Bound !== undefined);
  ok('(4c) org/repo-2 boundary present', r2Bound !== undefined);

  ok('(4c) org/repo-1 has 2 nodes (r1:src/a.js + r1:src/c.js)', r1Bound?.count === 2,
    JSON.stringify(r1Bound?.nodeIds));
  ok('(4c) org/repo-2 has 2 nodes (r2:lib/b.js + r2:secret/key.js)', r2Bound?.count === 2,
    JSON.stringify(r2Bound?.nodeIds));

  // Verify no cross-contamination of node ids between repos
  const r1Ids = new Set(r1Bound?.nodeIds || []);
  const r2Ids = new Set(r2Bound?.nodeIds || []);
  const overlap = [...r1Ids].filter(id => r2Ids.has(id));
  ok('(4c) no node-id overlap between repo boundaries', overlap.length === 0,
    JSON.stringify(overlap));
}

// (4d) isCrossRepoEdge is consistent across known same-repo and cross-repo pairs
{
  // Cross-repo pairs
  ok('(4d) r1:src/a.js → r2:lib/b.js is cross-repo',
    isCrossRepoEdge(multiRepoCtx.byId, 'r1:src/a.js', 'r2:lib/b.js') === true);
  ok('(4d) r1:src/a.js → r2:secret/key.js is cross-repo (no link, but repos differ)',
    isCrossRepoEdge(multiRepoCtx.byId, 'r1:src/a.js', 'r2:secret/key.js') === true);

  // Same-repo pairs
  ok('(4d) r1:src/a.js → r1:src/c.js is NOT cross-repo',
    isCrossRepoEdge(multiRepoCtx.byId, 'r1:src/a.js', 'r1:src/c.js') === false);
  ok('(4d) r2:lib/b.js → r2:secret/key.js is NOT cross-repo',
    isCrossRepoEdge(multiRepoCtx.byId, 'r2:lib/b.js', 'r2:secret/key.js') === false);

  // Missing node → conservative false
  ok('(4d) isCrossRepoEdge with missing node id → false (conservative)',
    isCrossRepoEdge(multiRepoCtx.byId, 'r1:src/a.js', 'no-such-id') === false);
}

// (4e) A node in one repo cannot "reach" an unlinked node in a foreign repo
//      via any destination prefix (file:, depChainTo:, importsOf:, folder:, district:)
{
  // r2:secret/key.js has no in-edges from r1 — it should be unreachable
  // from any destination that anchors to r1 nodes.

  // file: — can only find it if we ask directly (below checks that route doesn't drag it in)
  const byFile = parseDestination(multiRepoCtx, 'file:r1:src/a.js', 10);
  ok('(4e) file:r1:src/a.js does not match r2:secret/key.js',
    !byFile.matched.some(nd => nd.id === 'r2:secret/key.js'));

  // importsOf:r1:src/a.js — only resolves the direct links of r1:src/a.js
  const byImports = parseDestination(multiRepoCtx, 'importsOf:r1:src/a.js', 10);
  ok('(4e) importsOf:r1:src/a.js → r2:secret/key.js absent (no direct link)',
    !byImports.matched.some(nd => nd.id === 'r2:secret/key.js'),
    byImports.matched.map(nd => nd.id).join(', '));

  // depChainTo:r1:src/a.js — finds who calls a.js, but not an unreachable foreign node
  const byChain = parseDestination(multiRepoCtx, 'depChainTo:r1:src/a.js', 20);
  ok('(4e) depChainTo:r1:src/a.js → r2:secret/key.js absent (no link from r2:secret to r1:a)',
    !byChain.matched.some(nd => nd.id === 'r2:secret/key.js'),
    byChain.matched.map(nd => nd.id).join(', '));

  // folder: r1 prefix should only match r1 nodes
  const byFolder = parseDestination(multiRepoCtx, 'folder:src', 10);
  ok('(4e) folder:src only returns r1 nodes',
    byFolder.matched.every(nd => nd.id.startsWith('r1:')),
    byFolder.matched.map(nd => nd.id).join(', '));

  // kcRoute anchored at r1:src/a.js — unreachable r2:secret/key.js must not appear
  const docSec = kcRoute(multiRepoCtx, 'file:r1:src/a.js');
  const allIds = [...(docSec.route||[]), ...(docSec.alternates||[])].map(e => e.id);
  ok('(4e) kcRoute r1:src/a.js → r2:secret/key.js absent from route and alternates',
    !allIds.includes('r2:secret/key.js'), allIds.join(', '));
}

// ===========================================================================
// SECTION 5 — Hostile node metadata
// Nodes injected into the graph with adversarial provenance.repo strings or
// adversarial provenance.ref values do not cause crashes or path exposure.
// ===========================================================================
console.log('\n--- 5. Hostile node metadata ---');

// (5a) Node with provenance.repo set to a path-traversal string
//      repoOf() returns it verbatim (it's just a string label, not a filesystem path).
//      getRepoBoundaries and isCrossRepoEdge must not crash.
{
  const evilNode = {
    id: 'fs:ok.js', kind: 'file', title: 'Ok', category: 'code',
    headings: [], tags: [], links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'ok.js', repo: '../../evil/traversal' },
  };
  const evilCtx = {
    city: { nodes: [evilNode], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[evilNode.id, evilNode]]),
  };

  let threw = false, bounds = null;
  try { bounds = getRepoBoundaries(evilCtx); } catch { threw = true; }
  ok('(5a) getRepoBoundaries with traversal-string repo does not crash', !threw);
  if (bounds) {
    ok('(5a) traversal-string repo treated as opaque label (1 boundary)',
      bounds.length === 1);
    ok('(5a) boundary label is the raw traversal string (not resolved)',
      bounds[0]?.repo === '../../evil/traversal');
  }

  // isCrossRepoEdge — both nodes same traversal-label → not cross-repo
  ok('(5a) isCrossRepoEdge: two nodes with same traversal-label repo are NOT cross-repo',
    isCrossRepoEdge(evilCtx.byId, 'fs:ok.js', 'fs:ok.js') === false);

  // kcRoute must not throw; paths emitted must be relative (isSafeRef guards)
  let doc5a = null, threw5a = false;
  try { doc5a = kcRoute(evilCtx, 'file:ok.js'); } catch { threw5a = true; }
  ok('(5a) kcRoute with traversal-label repo does not throw', !threw5a);
  if (doc5a) {
    ok('(5a) route doc advisory === true', doc5a.advisory === true);
    const allPaths = [...(doc5a.route||[]), ...(doc5a.alternates||[])].map(e=>e.path);
    const badPaths = allPaths.filter(p => p.split(/[/\\]/).includes('..') || p.startsWith('/'));
    ok('(5a) no traversal paths in route output', badPaths.length === 0, JSON.stringify(badPaths));
  }
}

// (5b) Node with provenance.ref containing a ".." segment: the unsafe ref must never
//      appear as a route path.  safeRef() returns null → kcRoute falls back to the
//      node id as the path.  The node id here is safe ('fs:src/evil.js'), so the
//      node may appear in route[] but only via its safe id — the traversal ref itself
//      must not leak.
//
//      Contrast with test (5d) / redteam-fixtures.mjs test 11, where the node id
//      itself contains ".." — in that case isSafeRef(id) also fails and the node
//      is fully excluded from route[].
{
  const escapeNode = {
    id: 'fs:src/evil.js', kind: 'file', title: 'Evil', category: 'code',
    headings: [], tags: [], links: [],
    churn: null,
    provenance: { store: 'fs', ref: '../../etc/passwd' },   // traversal ref — must never leak
  };
  const escCtx = {
    city: { nodes: [escapeNode], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[escapeNode.id, escapeNode]]),
  };

  let doc5b = null, threw5b = false;
  try { doc5b = kcRoute(escCtx, 'file:src/evil.js'); } catch { threw5b = true; }
  ok('(5b) kcRoute with traversal provenance.ref does not throw', !threw5b);
  if (doc5b) {
    // The unsafe ref must not appear anywhere in the route output
    const allPaths5b = [...(doc5b.route||[]), ...(doc5b.alternates||[])].map(e => e.path);
    ok('(5b) traversal provenance.ref never appears as a route path',
      !allPaths5b.some(p => p.includes('etc/passwd') || p.includes('..')),
      JSON.stringify(allPaths5b));
    const badSegs5b = allPaths5b.filter(p => p.split(/[/\\]/).includes('..'));
    ok('(5b) no ".." segments in any route path', badSegs5b.length === 0, JSON.stringify(badSegs5b));
    ok('(5b) route doc valid despite hostile ref', validateRouteDoc(doc5b).ok === true);
  }
}

// (5c) repoOf: adversarial inputs produce null rather than crashing
{
  for (const input of [null, undefined, 42, [], { provenance: null }, { provenance: 'bad' }]) {
    let threw = false, result = undefined;
    try { result = repoOf(input); } catch { threw = true; }
    ok('(5c) repoOf does not throw on hostile input ' + JSON.stringify(input), !threw);
    ok('(5c) repoOf returns null for hostile input ' + JSON.stringify(input), result === null);
  }
}

// (5d) A node whose id contains ".." is not findable via file: even if pushed into byId
{
  const dotDotNode = {
    id: 'fs:../../etc/passwd', kind: 'file', title: 'Escape', category: 'code',
    headings: [], tags: [], links: [],
    churn: null,
    provenance: { store: 'fs', ref: '../../etc/passwd' },
  };
  const dotCtx = {
    city: { nodes: [dotDotNode], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[dotDotNode.id, dotDotNode]]),
  };
  // parseDestination can return the node (it resolves by id)
  // but kcRoute must not emit the unsafe ref as a path in the output
  let docDot = null, threwDot = false;
  try { docDot = kcRoute(dotCtx, 'file:../../etc/passwd'); } catch { threwDot = true; }
  ok('(5d) kcRoute on dotdot-id node does not throw', !threwDot);
  if (docDot) {
    ok('(5d) dotdot-id node excluded from route[] (isSafeRef guard)',
      docDot.route.length === 0, JSON.stringify(docDot.route));
    ok('(5d) route doc valid despite dotdot id', validateRouteDoc(docDot).ok === true);
  }
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
