// KnoSky route ranking tests (SAT-431 / KSV2-R3). Run: node test/ranking.test.mjs
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Small in-memory ctx with nodes across two districts
//
// Layout:
//   auth.js      — category 'code', destination target
//   utils.js     — category 'code' (same district as auth; imported by auth)
//   dashboard.js — category 'code' (same district as auth; unrelated to auth)
//   report.js    — category 'data' (different district; unrelated to auth)
//   auth.test.js — category 'test'
// ---------------------------------------------------------------------------

const nodes = [
  {
    id: 'fs:src/auth.js',
    kind: 'file',
    title: 'Auth module',
    summary: 'Authentication and token management',
    category: 'code',
    headings: ['login', 'logout', 'refresh'],
    tags: ['auth'],
    // imports utils.js (same district) AND report.js (different district) so both
    // become 1-hop neighbours; same-district signal makes utils.js outscore report.js
    links: ['fs:src/utils.js', 'fs:src/dashboard.js', 'fs:src/report.js'],
    churn: null,
    provenance: { store: 'fs', ref: 'src/auth.js' },
  },
  {
    id: 'fs:src/utils.js',
    kind: 'file',
    title: 'Utility helpers',
    summary: 'Shared utilities',
    category: 'code',
    headings: ['slugify', 'formatDate'],
    tags: [],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'src/utils.js' },
  },
  {
    id: 'fs:src/dashboard.js',
    kind: 'file',
    title: 'Dashboard view',
    summary: 'Renders the main dashboard',
    category: 'code',
    headings: ['render', 'widgets'],
    tags: [],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'src/dashboard.js' },
  },
  {
    id: 'fs:src/report.js',
    kind: 'file',
    title: 'Report generator',
    summary: 'Generates data reports',
    category: 'data',
    headings: ['generate'],
    tags: [],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'src/report.js' },
  },
  {
    id: 'fs:test/auth.test.js',
    kind: 'file',
    title: 'Auth tests',
    summary: 'Tests for auth module',
    category: 'test',
    headings: ['login spec'],
    tags: ['test'],
    links: ['fs:src/auth.js'],
    churn: null,
    provenance: { store: 'fs', ref: 'test/auth.test.js' },
  },
];

const byId = new Map(nodes.map(n => [n.id, n]));
const ctx = {
  city: {
    nodes,
    categories: [
      { id: 'code', label: 'Code' },
      { id: 'data', label: 'Data' },
      { id: 'test', label: 'Test' },
    ],
  },
  byId,
};

// ---------------------------------------------------------------------------
// (a) same-district candidate outranks an unrelated neighbour
//
// Route to folder:src — all src/* nodes are direct matches (folder).
// dashboard.js is in category 'code' — same district as auth.js.
// report.js is in category 'data' — different district.
// When we route to district:data the only direct match is report.js;
// dashboard.js (code) should outscore report.js neighbors via same-district.
// Simpler: route to file:src/auth.js and look at the expanded neighbours:
//   utils.js  — imported by auth.js (+2 import-proximity) + same district code (+1.5) = 3.5
//   dashboard.js — same district code (+1.5) only
//   report.js — no proximity, different district = 0
// So dashboard.js (1.5) must outrank report.js (0).
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  const ranks = Object.fromEntries(doc.route.map((e, i) => [e.path, i]));
  const dashboardRank = ranks['src/dashboard.js'];
  const reportRank = ranks['src/report.js'];

  // dashboard.js should appear before report.js (or report.js absent entirely)
  const sameDistrictWins =
    dashboardRank !== undefined &&
    (reportRank === undefined || dashboardRank < reportRank);

  ok('(a) same-district candidate outranks unrelated neighbour', sameDistrictWins,
    JSON.stringify({ dashboard: dashboardRank, report: reportRank }));
}

// ---------------------------------------------------------------------------
// (b) title/heading keyword match adds "name/heading match" to a candidate's reason
//
// Route to keyword "login" — auth.js has "login" in its headings.
// The auth.js route entry should include "name/heading match" in reasons.
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'login');
  const authEntry = doc.route.find(e => e.path === 'src/auth.js');

  ok('(b) auth.js found in keyword route "login"', authEntry !== undefined,
    JSON.stringify(doc.route.map(e => e.path)));
  ok('(b) auth.js reason includes "name/heading match"',
    authEntry && authEntry.reason.includes('name/heading match'),
    authEntry ? authEntry.reason : '(no entry)');
}

// ---------------------------------------------------------------------------
// (c) overlays map with <50% coverage adds the "low coverage" caveat AND score bump
//
// Route to file:src/auth.js with overlays indicating src/utils.js has 30% coverage.
// utils.js is a 1-hop neighbour (imported by auth.js) so it appears in candidates.
// Expected: caveats includes "low coverage: src/utils.js (30%)",
//           and utils.js score is higher than without overlays.
// ---------------------------------------------------------------------------
{
  const overlays = {
    'src/utils.js': { coverage: 30 },
  };

  const docWithOverlay = kcRoute(ctx, 'file:src/auth.js', { overlays });
  const docNoOverlay   = kcRoute(ctx, 'file:src/auth.js');

  const lowCaveat = docWithOverlay.caveats.find(c => c.includes('low coverage') && c.includes('src/utils.js'));
  ok('(c) low-coverage caveat present when coverage < 50', lowCaveat !== undefined,
    JSON.stringify(docWithOverlay.caveats));

  const utilsWithOverlay = [...docWithOverlay.route, ...(docWithOverlay.alternates || [])].find(e => e.path === 'src/utils.js');
  const utilsNoOverlay   = [...docNoOverlay.route,   ...(docNoOverlay.alternates   || [])].find(e => e.path === 'src/utils.js');
  ok('(c) low-coverage file score is higher with overlay',
    utilsWithOverlay && utilsNoOverlay && utilsWithOverlay.score > utilsNoOverlay.score,
    JSON.stringify({ with: utilsWithOverlay && utilsWithOverlay.score, without: utilsNoOverlay && utilsNoOverlay.score }));
}

// ---------------------------------------------------------------------------
// (d) top result's reason is a non-empty explainable string
// ---------------------------------------------------------------------------
{
  const doc = kcRoute(ctx, 'file:src/auth.js');
  const top = doc.route[0];
  ok('(d) top result is present', top !== undefined);
  ok('(d) top result reason is a non-empty string',
    top && typeof top.reason === 'string' && top.reason.length > 0,
    top ? JSON.stringify(top.reason) : '');
}

// ---------------------------------------------------------------------------
// (e) doc passes validateRouteDoc
// ---------------------------------------------------------------------------
{
  const overlays = { 'src/utils.js': { coverage: 25 } };
  const doc = kcRoute(ctx, 'file:src/auth.js', { overlays });
  const result = validateRouteDoc(doc);
  ok('(e) doc with overlays passes validateRouteDoc', result.ok === true,
    JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
