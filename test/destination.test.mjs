// Destination parser tests (KSV2-R2). Run: node test/destination.test.mjs
import { parseDestination } from '../core/destination.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Small in-memory ctx with a cyclic import (A -> B -> A) and other nodes.
// ---------------------------------------------------------------------------

const nodes = [
  {
    id: 'fs:src/a.js',
    kind: 'file',
    title: 'Module A',
    summary: 'module a summary',
    category: 'code',
    headings: [],
    tags: [],
    links: ['fs:src/b.js'], // A imports B
    provenance: { store: 'fs', ref: 'src/a.js' },
  },
  {
    id: 'fs:src/b.js',
    kind: 'file',
    title: 'Module B',
    summary: 'module b summary',
    category: 'code',
    headings: [],
    tags: [],
    links: ['fs:src/a.js'], // B imports A  — cycle!
    provenance: { store: 'fs', ref: 'src/b.js' },
  },
  {
    id: 'fs:src/c.js',
    kind: 'file',
    title: 'Module C',
    summary: 'module c summary',
    category: 'code',
    headings: [],
    tags: [],
    links: ['fs:src/a.js'], // C imports A
    provenance: { store: 'fs', ref: 'src/c.js' },
  },
  {
    id: 'fs:lib/util.js',
    kind: 'file',
    title: 'Utility lib',
    summary: 'shared utility helpers',
    category: 'util',
    headings: [],
    tags: ['util'],
    links: [],
    provenance: { store: 'fs', ref: 'lib/util.js' },
  },
  {
    id: 'fs:docs/readme.md',
    kind: 'file',
    title: 'Readme',
    summary: 'project documentation',
    category: 'docs',
    headings: [],
    tags: ['docs'],
    links: [],
    provenance: { store: 'fs', ref: 'docs/readme.md' },
  },
];

const byId = new Map(nodes.map(n => [n.id, n]));
const ctx = {
  city: {
    nodes,
    categories: [
      { id: 'code', label: 'Code' },
      { id: 'util', label: 'Utilities' },
      { id: 'docs', label: 'Documentation' },
    ],
  },
  byId,
};

// ---------------------------------------------------------------------------
// (1) file: by id suffix
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'file:src/a.js', 10);
  ok('(1) file: by id suffix — one result', matched.length === 1, String(matched.length));
  ok('(1) file: by id suffix — correct node', matched[0] && matched[0].id === 'fs:src/a.js');
  ok('(1) file: matchStrength is direct', matchStrength === 'direct', matchStrength);
}

// ---------------------------------------------------------------------------
// (2) file: by provenance.ref (same result via ref match)
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'file:lib/util.js', 10);
  ok('(2) file: by provenance.ref — one result', matched.length === 1, String(matched.length));
  ok('(2) file: by provenance.ref — correct node', matched[0] && matched[0].id === 'fs:lib/util.js');
  ok('(2) file: by provenance.ref — matchStrength direct', matchStrength === 'direct', matchStrength);
}

// ---------------------------------------------------------------------------
// (3) file: unknown path returns empty matched + matchStrength 'direct'
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'file:no/such.js', 10);
  ok('(3) file: unknown returns empty matched', matched.length === 0, String(matched.length));
  ok('(3) file: unknown matchStrength is direct', matchStrength === 'direct', matchStrength);
}

// ---------------------------------------------------------------------------
// (4) folder: prefix match
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'folder:src', 10);
  const ids = matched.map(n => n.id).sort();
  ok('(4) folder:src returns 3 nodes', matched.length === 3, String(matched.length));
  ok('(4) folder:src includes a.js', ids.includes('fs:src/a.js'));
  ok('(4) folder:src includes b.js', ids.includes('fs:src/b.js'));
  ok('(4) folder:src includes c.js', ids.includes('fs:src/c.js'));
  ok('(4) folder: matchStrength is folder', matchStrength === 'folder', matchStrength);
}

// ---------------------------------------------------------------------------
// (5) district: by category id (case-insensitive)
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'district:code', 10);
  const ids = matched.map(n => n.id).sort();
  ok('(5) district:code returns 3 nodes', matched.length === 3, String(matched.length));
  ok('(5) district:code has a.js', ids.includes('fs:src/a.js'));
  ok('(5) district: matchStrength is district', matchStrength === 'district', matchStrength);
}

// district: by category label
{
  const { matched, matchStrength } = parseDestination(ctx, 'district:utilities', 10);
  const ids = matched.map(n => n.id);
  ok('(5b) district:Utilities (label) returns util node', ids.includes('fs:lib/util.js'), ids.join(','));
  ok('(5b) district:utilities matchStrength is district', matchStrength === 'district', matchStrength);
}

// district: case-insensitive id check (uppercase input)
{
  const { matched } = parseDestination(ctx, 'district:CODE', 10);
  ok('(5c) district:CODE (uppercase) still returns 3 nodes', matched.length === 3, String(matched.length));
}

// ---------------------------------------------------------------------------
// (6) importsOf: out-edge targets
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'importsOf:src/a.js', 10);
  // a.js -> b.js
  const ids = matched.map(n => n.id);
  ok('(6) importsOf:src/a.js returns b.js', ids.includes('fs:src/b.js'), ids.join(','));
  ok('(6) importsOf: matchStrength is edges', matchStrength === 'edges', matchStrength);
}

{
  // a node with no imports
  const { matched } = parseDestination(ctx, 'importsOf:lib/util.js', 10);
  ok('(6b) importsOf on node with no links returns empty', matched.length === 0, String(matched.length));
}

{
  // unknown id
  const { matched, matchStrength } = parseDestination(ctx, 'importsOf:no/such.js', 10);
  ok('(6c) importsOf unknown node returns empty', matched.length === 0, String(matched.length));
  ok('(6c) importsOf unknown matchStrength is edges', matchStrength === 'edges', matchStrength);
}

// ---------------------------------------------------------------------------
// (7) depChainTo: reverse-edge BFS — who reaches target?
// ---------------------------------------------------------------------------
{
  // depChainTo:src/a.js — B imports A directly, C imports A directly.
  // A also imports B which imports A (cycle), but A is the target so it is
  // excluded from results.
  const { matched, matchStrength } = parseDestination(ctx, 'depChainTo:src/a.js', 10);
  const ids = matched.map(n => n.id).sort();
  ok('(7) depChainTo:a.js includes b.js (direct importer)', ids.includes('fs:src/b.js'), ids.join(','));
  ok('(7) depChainTo:a.js includes c.js (direct importer)', ids.includes('fs:src/c.js'), ids.join(','));
  // a.js itself must NOT be in the result
  ok('(7) depChainTo:a.js does not include a.js itself', !ids.includes('fs:src/a.js'), ids.join(','));
  ok('(7) depChainTo: matchStrength is chain', matchStrength === 'chain', matchStrength);
}

{
  // depChainTo on a node with no importers
  const { matched } = parseDestination(ctx, 'depChainTo:docs/readme.md', 10);
  ok('(7b) depChainTo on un-imported node returns empty', matched.length === 0, String(matched.length));
}

{
  // depChainTo unknown
  const { matched, matchStrength } = parseDestination(ctx, 'depChainTo:no/such.js', 10);
  ok('(7c) depChainTo unknown returns empty', matched.length === 0, String(matched.length));
  ok('(7c) depChainTo unknown matchStrength is chain', matchStrength === 'chain', matchStrength);
}

// ---------------------------------------------------------------------------
// (8) depChainTo terminates on cyclic graph — must not hang / infinite-loop.
// We test this by constructing an explicit cycle and calling with a generous
// timeout guard via the bounded visitor set.
// ---------------------------------------------------------------------------
{
  // The ctx already has A->B->A.  Verify depChainTo:src/b.js also terminates.
  const start = Date.now();
  const { matched } = parseDestination(ctx, 'depChainTo:src/b.js', 10);
  const elapsed = Date.now() - start;
  ok('(8) depChainTo on cyclic graph terminates quickly (< 200ms)', elapsed < 200, elapsed + 'ms');
  // a.js imports b.js, so a.js is a direct importer of b.js. b.js also imports a.js.
  // Due to the BFS visiting a.js and then seeing b.js already visited, it stops.
  const ids = matched.map(n => n.id);
  ok('(8) depChainTo:b.js includes a.js (importer of b)', ids.includes('fs:src/a.js'), ids.join(','));
}

// ---------------------------------------------------------------------------
// (9) no prefix — keyword fallback
// ---------------------------------------------------------------------------
{
  const { matched, matchStrength } = parseDestination(ctx, 'utility', 10);
  // "utility" tokens match lib/util.js (title: 'Utility lib', tags: ['util'])
  ok('(9) keyword fallback returns some nodes', matched.length > 0, String(matched.length));
  ok('(9) keyword matchStrength is keyword', matchStrength === 'keyword', matchStrength);
}

{
  const { matchStrength } = parseDestination(ctx, 'documentation readme', 10);
  ok('(9b) keyword fallback matchStrength is keyword', matchStrength === 'keyword', matchStrength);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
