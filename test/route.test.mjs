// KnoSky route engine tests. Run: node test/route.test.mjs
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Build a small in-memory ctx with ~4 nodes + links + churn + provenance.ref
// ---------------------------------------------------------------------------

const nodes = [
  {
    id: 'fs:src/auth.js',
    kind: 'file',
    title: 'Auth module',
    summary: 'Handles authentication and tokens',
    category: 'code',
    headings: ['login', 'logout'],
    tags: ['auth', 'security'],
    links: ['fs:src/utils.js'],
    churn: { c: 12, b: 0.9 }, // high churn
    provenance: { store: 'fs', ref: 'src/auth.js', source_rev: 'abc123' },
  },
  {
    id: 'fs:src/utils.js',
    kind: 'file',
    title: 'Utility helpers',
    summary: 'Shared utility functions',
    category: 'code',
    headings: ['formatDate', 'slugify'],
    tags: ['utils'],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'src/utils.js', source_rev: 'abc123' },
  },
  {
    id: 'fs:test/auth.test.js',
    kind: 'file',
    title: 'Auth tests',
    summary: 'Test suite for the auth module',
    category: 'test',
    headings: ['describe auth'],
    tags: ['test', 'auth'],
    links: ['fs:src/auth.js'],
    churn: null,
    provenance: { store: 'fs', ref: 'test/auth.test.js', source_rev: 'abc123' },
  },
  {
    id: 'fs:docs/auth.md',
    kind: 'file',
    title: 'Auth docs',
    summary: 'Documentation for authentication flows',
    category: 'docs',
    headings: ['overview', 'API reference'],
    tags: ['docs', 'auth'],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'docs/auth.md', source_rev: 'abc123' },
  },
];

const byId = new Map(nodes.map(n => [n.id, n]));
const ctx = {
  city: {
    nodes,
    categories: [
      { id: 'code', label: 'Code' },
      { id: 'test', label: 'Tests' },
      { id: 'docs', label: 'Docs' },
    ],
    source_rev: 'abc123',
  },
  byId,
};

// ---------------------------------------------------------------------------
// Helper: validate path invariants across all path arrays in a doc
// ---------------------------------------------------------------------------
function allPathsRelative(doc) {
  const arrays = [
    ...(doc.route || []),
    ...(doc.alternates || []),
    ...(doc.tests || []),
    ...(doc.docs || []),
  ];
  for (const entry of arrays) {
    const p = typeof entry === 'string' ? entry : (entry && entry.path);
    if (!p || typeof p !== 'string') continue;
    if (p.startsWith('/')) return false;
    if (/^[A-Za-z]:[\\\/]/.test(p)) return false;
    if (p.split(/[/\\]/).some(s => s === '..')) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// (a) file: destination → route doc passes validateRouteDoc with non-empty route
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  const result = validateRouteDoc(doc);
  ok('(a) file: destination passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('(a) file: destination has non-empty route', Array.isArray(doc.route) && doc.route.length > 0);
}

// ---------------------------------------------------------------------------
// (b) every route/alternates/tests/docs path is relative (no leading /, no ..)
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  ok('(b) all paths in doc are relative', allPathsRelative(doc));
}

// ---------------------------------------------------------------------------
// (c) confidence is in [0, 1]
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  ok('(c) confidence is a number', typeof doc.confidence === 'number');
  ok('(c) confidence >= 0', doc.confidence >= 0);
  ok('(c) confidence <= 1', doc.confidence <= 1);
}

// ---------------------------------------------------------------------------
// (d) advisory === true and at least one caveat present
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  ok('(d) advisory is true', doc.advisory === true);
  ok('(d) at least one caveat present', Array.isArray(doc.caveats) && doc.caveats.length > 0);
}

// ---------------------------------------------------------------------------
// (e) high-churn top file yields a "recently changed" caveat
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js'); // src/auth.js has churn {c:12, b:0.9}
  const hasChurnCaveat = doc.caveats.some(c => c.includes('recently changed'));
  ok('(e) high-churn node -> "recently changed" caveat present', hasChurnCaveat, JSON.stringify(doc.caveats));
}

// ---------------------------------------------------------------------------
// (f) folder: destination returns a valid doc
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'folder:src');
  const result = validateRouteDoc(doc);
  ok('(f) folder: destination passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('(f) folder: has non-empty route', Array.isArray(doc.route) && doc.route.length > 0);
  ok('(f) folder: all paths relative', allPathsRelative(doc));
}

// (f cont.) keyword fallback returns a valid doc
{
  const doc = kcRoute(ctx, 'auth');
  const result = validateRouteDoc(doc);
  ok('(f) keyword fallback passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('(f) keyword fallback has non-empty route', Array.isArray(doc.route) && doc.route.length > 0);
  ok('(f) keyword fallback all paths relative', allPathsRelative(doc));
  ok('(f) keyword fallback confidence in [0,1]', typeof doc.confidence === 'number' && doc.confidence >= 0 && doc.confidence <= 1);
}

// ---------------------------------------------------------------------------
// Additional: doc includes tests + docs arrays (well-formed)
// ---------------------------------------------------------------------------
{
  // file:src/auth.js — test node is a 1-hop neighbour (imports auth.js)
  const fileDoc = kcRoute(ctx, 'file:src/auth.js');
  ok('tests array present', Array.isArray(fileDoc.tests));
  ok('docs array present', Array.isArray(fileDoc.docs));
  const testPaths = (fileDoc.tests || []).map(e => e.path);
  ok('test/auth.test.js appears in tests', testPaths.includes('test/auth.test.js'));

  // keyword 'auth' — pulls in all four nodes including the docs/.md one
  const kwDoc = kcRoute(ctx, 'auth');
  const docPaths = (kwDoc.docs || []).map(e => e.path);
  ok('docs/auth.md appears in docs (keyword query)', docPaths.includes('docs/auth.md'));
}

// ---------------------------------------------------------------------------
// Additional: mandatory advisory caveat always includes "advisory route" text
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'auth'); // keyword
  const hasAdvisory = doc.caveats.some(c => c.includes('advisory route'));
  ok('mandatory advisory caveat always present', hasAdvisory, JSON.stringify(doc.caveats));
}

// ---------------------------------------------------------------------------
// Additional: source_rev caveat present when city.source_rev is set
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'auth');
  const hasRevCaveat = doc.caveats.some(c => c.includes('rev') && c.includes('abc123'));
  ok('source_rev caveat present when source_rev in city', hasRevCaveat, JSON.stringify(doc.caveats));
}

// ---------------------------------------------------------------------------
// Additional: file: for unknown path still returns a valid (possibly empty) doc
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:no/such/file.js');
  const result = validateRouteDoc(doc);
  ok('file: unknown path produces valid doc', result.ok === true, JSON.stringify(result.errors));
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
