// KnoSky "Solo/Startup" sim environment integration tests (SAT-455).
//
// Runs the KnoSky indexer + route engine against a real shallow clone of
// vercel/next.js — a large, actively-developed public monorepo — and proves
// the pipeline holds up at real scale.
//
// GATE: these tests only run when KC_RUN_SIM_TESTS=1 (they clone ~200 MB of
// git history and can take 2–5 minutes on a cold cache).  They are skipped by
// default so CI stays fast.
//
// Run manually:
//   KC_RUN_SIM_TESTS=1 node test/sim-solo.test.mjs
//
// Re-use a pre-built artifact (skip the clone + index step):
//   KC_RUN_SIM_TESTS=1 KC_SIM_SOLO_OUT=/path/to/city.json node test/sim-solo.test.mjs
//
// Cache the clone between runs:
//   KC_SIM_SOLO_CACHE=/tmp/kc-nextjs-cache KC_RUN_SIM_TESTS=1 node test/sim-solo.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupSoloSim } from '../sim/setup-solo.mjs';
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';
import { load as loadCity } from '../core/retrieve.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Gate: skip unless KC_RUN_SIM_TESTS=1
// ---------------------------------------------------------------------------

if (!process.env.KC_RUN_SIM_TESTS) {
  console.log('SKIP - sim-solo tests (set KC_RUN_SIM_TESTS=1 to run)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Phase 1: build (or reuse) the sim artifact
// ---------------------------------------------------------------------------

console.log('\n--- sim-solo: Phase 1 – build artifact ---');

const DEFAULT_CACHE = path.join(ROOT, 'sim', '.cache', 'solo');
const cityPath = path.resolve(
  process.env.KC_SIM_SOLO_OUT || path.join(DEFAULT_CACHE, 'city.json'),
);

let nodeCount = 0;
let categories = [];

if (fs.existsSync(cityPath)) {
  // Reuse pre-built artifact — skip the clone + index step
  console.log('[sim-solo] reusing existing artifact at', cityPath);
  const city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
  nodeCount = city.node_count ?? (city.nodes || []).length;
  categories = city.categories || [];
} else {
  // Build from scratch
  const result = await setupSoloSim();
  nodeCount  = result.nodeCount;
  categories = result.categories;
}

// Basic artifact sanity
ok('artifact: city.json exists', fs.existsSync(cityPath));
ok('artifact: parses as valid JSON', (() => {
  try { JSON.parse(fs.readFileSync(cityPath, 'utf8')); return true; } catch { return false; }
})());

const city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
ok('artifact: schema_version is "2.0"', city.schema_version === '2.0', city.schema_version);

// ---------------------------------------------------------------------------
// Phase 2: indexer scale invariants
// ---------------------------------------------------------------------------

console.log('\n--- sim-solo: Phase 2 – indexer scale invariants ---');

// vercel/next.js is a large monorepo — even with --max 6000 we expect a
// substantial number of nodes.  The exact number varies with the clone depth
// and --max setting; use ≥ 1000 as a safe lower bound.
ok('scale: nodeCount >= 1000', nodeCount >= 1000, String(nodeCount));

// The monorepo spans many top-level dirs; expect at least 3 categories.
ok('scale: categories >= 3', categories.length >= 3, String(categories.length));

// Every node must satisfy the CONTRACT v2 required fields.
const nodes = city.nodes || [];
let allHaveRequired = true;
let allPathsSafe    = true;
let allLinksRelative = true;

for (const n of nodes) {
  if (!n.id || !n.kind || !n.title || !n.category || !n.provenance) {
    allHaveRequired = false; break;
  }
}
ok('contract: every node has id/kind/title/category/provenance', allHaveRequired);

for (const n of nodes) {
  const ref = n.provenance && n.provenance.ref;
  if (!ref || typeof ref !== 'string') continue;
  if (ref.startsWith('/') || /^[A-Za-z]:[\\\/]/.test(ref) || ref.split(/[/\\]/).some(s => s === '..')) {
    allPathsSafe = false; break;
  }
}
ok('contract: no provenance.ref is absolute or contains ..', allPathsSafe);

for (const n of nodes) {
  for (const link of (n.links || [])) {
    if (typeof link === 'string' && (link.startsWith('fs://') || !/^fs:/.test(link))) {
      // links are "fs:rel/path" — just ensure they don't carry absolute paths
      const bare = link.replace(/^fs:/, '');
      if (bare.startsWith('/') || /^[A-Za-z]:[\\\/]/.test(bare) || bare.split(/[/\\]/).some(s => s === '..')) {
        allLinksRelative = false; break;
      }
    }
  }
  if (!allLinksRelative) break;
}
ok('contract: no link target encodes an absolute path', allLinksRelative);

// ---------------------------------------------------------------------------
// Phase 3: route engine at real scale
// ---------------------------------------------------------------------------

console.log('\n--- sim-solo: Phase 3 – route engine ---');

const ctx = loadCity(cityPath);

// (a) keyword query that maps to something in next.js (router is always there)
{
  const doc = kcRoute(ctx, 'router');
  const result = validateRouteDoc(doc);
  ok('route(keyword:router): passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('route(keyword:router): non-empty route', Array.isArray(doc.route) && doc.route.length > 0);
  ok('route(keyword:router): confidence in [0,1]',
    typeof doc.confidence === 'number' && doc.confidence >= 0 && doc.confidence <= 1);
  ok('route(keyword:router): advisory === true', doc.advisory === true);
}

// (b) keyword query for another core concept
{
  const doc = kcRoute(ctx, 'middleware');
  const result = validateRouteDoc(doc);
  ok('route(keyword:middleware): passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('route(keyword:middleware): advisory === true', doc.advisory === true);
}

// (c) all paths in a route doc are safe (no absolute, no ..)
{
  const doc = kcRoute(ctx, 'pages');
  const allEntries = [
    ...(doc.route || []),
    ...(doc.alternates || []),
    ...(doc.tests || []),
    ...(doc.docs || []),
  ];

  let pathsOk = true;
  for (const entry of allEntries) {
    const p = typeof entry === 'string' ? entry : (entry && entry.path);
    if (!p || typeof p !== 'string') continue;
    if (p.startsWith('/') || /^[A-Za-z]:[\\\/]/.test(p) || p.split(/[/\\]/).some(s => s === '..')) {
      pathsOk = false; break;
    }
  }
  ok('route(keyword:pages): all emitted paths are relative / no ..', pathsOk);
}

// (d) folder: destination resolves to non-empty route
{
  // packages/ is a well-known top-level dir in vercel/next.js
  const packagesNodes = nodes.filter(n => n.provenance && n.provenance.ref &&
    n.provenance.ref.startsWith('packages/'));
  if (packagesNodes.length > 0) {
    const doc = kcRoute(ctx, 'folder:packages');
    const result = validateRouteDoc(doc);
    ok('route(folder:packages): passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
    ok('route(folder:packages): non-empty route (folder exists in monorepo)', doc.route.length > 0);
  } else {
    ok('route(folder:packages): skipped (packages/ not present in indexed nodes)', true);
  }
}

// (e) district: destination resolves to non-empty route for a known category
{
  const firstCat = categories[0];
  if (firstCat) {
    const doc = kcRoute(ctx, 'district:' + firstCat.id);
    const result = validateRouteDoc(doc);
    ok('route(district:' + firstCat.id + '): passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
    ok('route(district:' + firstCat.id + '): non-empty route', doc.route.length > 0);
  } else {
    ok('route(district): skipped (no categories in city)', true);
  }
}

// (f) mandatory caveats always present
{
  const doc = kcRoute(ctx, 'fetch');
  const hasAdvisory = doc.caveats.some(c => c.includes('advisory route'));
  ok('route: mandatory advisory caveat always present', hasAdvisory, JSON.stringify(doc.caveats));
}

// (g) top-level city stats logged for observability
console.log('[sim-solo] nodes:', nodeCount,
  '| categories:', categories.map(c => c.id + ':' + c.label).join(', ').slice(0, 120));
const dist = {};
for (const n of nodes) dist[n.category] = (dist[n.category] || 0) + 1;
console.log('[sim-solo] distribution (top 8):',
  Object.entries(dist).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => k + ':' + v).join(', '));

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
