// Cross-repo graph utilities tests (SAT-448). Run: node test/cross-repo.test.mjs
import { repoOf, isCrossRepoEdge, getCrossRepoEdges, getRepoBoundaries } from '../core/cross-repo.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeNode(id, store, repo, links = []) {
  return {
    id,
    kind: 'file',
    title: id,
    category: 'code',
    links,
    provenance: repo !== undefined
      ? { store, ref: id, repo }
      : { store, ref: id },
  };
}

// ---------------------------------------------------------------------------
// (a) repoOf — provenance.repo takes precedence over provenance.store
// ---------------------------------------------------------------------------
{
  const n = makeNode('id', 'fs', 'org/repo-a');
  ok('(a) repoOf returns provenance.repo when set', repoOf(n) === 'org/repo-a', repoOf(n));
}
{
  const n = makeNode('id', 'fs'); // no provenance.repo
  ok('(a) repoOf falls back to provenance.store when repo absent', repoOf(n) === 'fs', repoOf(n));
}
{
  ok('(a) repoOf returns null for null input', repoOf(null) === null);
  ok('(a) repoOf returns null when provenance absent', repoOf({ id: 'x' }) === null);
  ok('(a) repoOf returns null when provenance is not an object', repoOf({ provenance: 'bad' }) === null);
}
{
  const n = { id: 'z', provenance: { store: '', repo: '' } };
  ok('(a) repoOf returns null when store is empty string', repoOf(n) === null);
}

// ---------------------------------------------------------------------------
// (b) isCrossRepoEdge — different repos → true; same repo → false
// ---------------------------------------------------------------------------

{
  const nA = makeNode('fs:a', 'fs', 'org/repo-a');
  const nB = makeNode('fs:b', 'fs', 'org/repo-b');
  const byId = new Map([[nA.id, nA], [nB.id, nB]]);
  ok('(b) different repos → cross-repo edge', isCrossRepoEdge(byId, nA.id, nB.id) === true);
  ok('(b) same repos → not cross-repo', isCrossRepoEdge(byId, nA.id, nA.id) === false);
}
{
  // single-repo graph: both nodes share the same store (no explicit repo field)
  const nA = makeNode('fs:src/auth.js', 'fs');
  const nB = makeNode('fs:src/utils.js', 'fs');
  const byId = new Map([[nA.id, nA], [nB.id, nB]]);
  ok('(b) single-repo graph: same store → not cross-repo', isCrossRepoEdge(byId, nA.id, nB.id) === false);
}
{
  // missing node → conservative false
  const nA = makeNode('fs:x', 'fs', 'org/a');
  const byId = new Map([[nA.id, nA]]);
  ok('(b) missing dst node → false (conservative)', isCrossRepoEdge(byId, nA.id, 'no-such-id') === false);
  ok('(b) missing src node → false (conservative)', isCrossRepoEdge(byId, 'no-such-id', nA.id) === false);
}
{
  // node with no provenance → false
  const nA = makeNode('fs:x', 'fs', 'org/a');
  const nB = { id: 'y', kind: 'file', title: 'y', category: 'code', links: [] }; // no provenance
  const byId = new Map([[nA.id, nA], [nB.id, nB]]);
  ok('(b) node without provenance → false (conservative)', isCrossRepoEdge(byId, nA.id, nB.id) === false);
}

// ---------------------------------------------------------------------------
// (c) getCrossRepoEdges — returns all and only cross-repo edges
// ---------------------------------------------------------------------------

{
  const nA = makeNode('A', 'fs', 'org/repo-a', ['B', 'C']);
  const nB = makeNode('B', 'fs', 'org/repo-b', []); // cross target
  const nC = makeNode('C', 'fs', 'org/repo-a', []); // same-repo target
  const ctx = {
    city: { nodes: [nA, nB, nC] },
    byId: new Map([[nA.id, nA], [nB.id, nB], [nC.id, nC]]),
  };
  const edges = getCrossRepoEdges(ctx);
  ok('(c) exactly one cross-repo edge detected', edges.length === 1, JSON.stringify(edges));
  ok('(c) edge from is A', edges[0]?.from === 'A');
  ok('(c) edge to is B', edges[0]?.to === 'B');
  ok('(c) fromRepo is org/repo-a', edges[0]?.fromRepo === 'org/repo-a');
  ok('(c) toRepo is org/repo-b', edges[0]?.toRepo === 'org/repo-b');
}
{
  // no cross-repo edges in single-repo graph
  const nA = makeNode('A', 'fs', undefined, ['B']);
  const nB = makeNode('B', 'fs');
  const ctx = {
    city: { nodes: [nA, nB] },
    byId: new Map([[nA.id, nA], [nB.id, nB]]),
  };
  const edges = getCrossRepoEdges(ctx);
  ok('(c) single-repo graph → zero cross-repo edges', edges.length === 0, JSON.stringify(edges));
}
{
  // empty graph returns []
  const ctx = { city: { nodes: [] }, byId: new Map() };
  ok('(c) empty graph → []', getCrossRepoEdges(ctx).length === 0);
}
{
  // bidirectional cross-repo links are both reported
  const nA = makeNode('A', 'fs', 'r1', ['B']);
  const nB = makeNode('B', 'fs', 'r2', ['A']);
  const ctx = {
    city: { nodes: [nA, nB] },
    byId: new Map([[nA.id, nA], [nB.id, nB]]),
  };
  const edges = getCrossRepoEdges(ctx);
  ok('(c) bidirectional cross-repo → 2 edges', edges.length === 2, JSON.stringify(edges));
}

// ---------------------------------------------------------------------------
// (d) getRepoBoundaries — correct grouping, count, and sort order
// ---------------------------------------------------------------------------

{
  const nodes = [
    makeNode('a1', 'fs', 'org/repo-a'),
    makeNode('a2', 'fs', 'org/repo-a'),
    makeNode('a3', 'fs', 'org/repo-a'),
    makeNode('b1', 'fs', 'org/repo-b'),
    makeNode('b2', 'fs', 'org/repo-b'),
  ];
  const ctx = {
    city: { nodes },
    byId: new Map(nodes.map(n => [n.id, n])),
  };
  const bounds = getRepoBoundaries(ctx);
  ok('(d) two distinct repos found', bounds.length === 2, JSON.stringify(bounds.map(b => b.repo)));
  ok('(d) first entry is repo-a (largest)', bounds[0]?.repo === 'org/repo-a');
  ok('(d) repo-a count is 3', bounds[0]?.count === 3);
  ok('(d) second entry is repo-b', bounds[1]?.repo === 'org/repo-b');
  ok('(d) repo-b count is 2', bounds[1]?.count === 2);
  ok('(d) nodeIds length matches count', bounds[0]?.nodeIds.length === 3 && bounds[1]?.nodeIds.length === 2);
  ok('(d) repo-a nodeIds contains a1', bounds[0]?.nodeIds.includes('a1'));
}
{
  // nodes without provenance are excluded from boundaries
  const nGood = makeNode('good', 'fs', 'org/r');
  const nBad = { id: 'bad', kind: 'file', title: 'b', category: 'code', links: [] };
  const ctx = {
    city: { nodes: [nGood, nBad] },
    byId: new Map([[nGood.id, nGood], [nBad.id, nBad]]),
  };
  const bounds = getRepoBoundaries(ctx);
  ok('(d) nodes without provenance excluded from boundaries', bounds.length === 1);
  ok('(d) only the provenance-bearing node counted', bounds[0]?.count === 1);
}
{
  // store-based identity (no explicit repo field): all same-store nodes form one boundary
  const nodes = [makeNode('x', 'gh:org/r'), makeNode('y', 'gh:org/r')];
  const ctx = {
    city: { nodes },
    byId: new Map(nodes.map(n => [n.id, n])),
  };
  const bounds = getRepoBoundaries(ctx);
  ok('(d) store-based identity: one boundary for two nodes sharing store', bounds.length === 1);
  ok('(d) store-based boundary repo is the store value', bounds[0]?.repo === 'gh:org/r');
  ok('(d) count is 2', bounds[0]?.count === 2);
}
{
  ok('(d) empty graph → []', getRepoBoundaries({ city: { nodes: [] }, byId: new Map() }).length === 0);
}

// ---------------------------------------------------------------------------
// (e) round-trip: getCrossRepoEdges is consistent with isCrossRepoEdge
// ---------------------------------------------------------------------------

{
  const nA = makeNode('A', 'fs', 'repo-1', ['B', 'C']);
  const nB = makeNode('B', 'fs', 'repo-2', []);
  const nC = makeNode('C', 'fs', 'repo-1', []);
  const byId = new Map([[nA.id, nA], [nB.id, nB], [nC.id, nC]]);
  const ctx = { city: { nodes: [nA, nB, nC] }, byId };

  const edges = getCrossRepoEdges(ctx);
  for (const e of edges) {
    ok(`(e) getCrossRepoEdges result consistent with isCrossRepoEdge (${e.from}→${e.to})`,
       isCrossRepoEdge(byId, e.from, e.to) === true);
  }
  // No cross edge for A→C
  const nonCross = [{ from: 'A', to: 'C' }];
  for (const e of nonCross) {
    ok(`(e) same-repo edge not in getCrossRepoEdges result (${e.from}→${e.to})`,
       !edges.some(x => x.from === e.from && x.to === e.to));
    ok(`(e) isCrossRepoEdge agrees (${e.from}→${e.to})`,
       isCrossRepoEdge(byId, e.from, e.to) === false);
  }
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
