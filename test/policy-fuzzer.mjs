// KnoSky policy-fuzzer (SAT-457). Run: node test/policy-fuzzer.mjs
// Covers four threat categories feeding SAT-437's adversarial red-team suite:
//   1. Authorization-correctness — advisory/confidence/route invariants never grant real access
//   2. Trust-root / key-state    — secret patterns, scan results, and protocol version cannot be forged
//   3. Graph-state               — malformed node graphs (cycles, dangling links, dupes) cannot crash or corrupt
//   4. Clock/ledger manipulation — generated_at, expiry, source_rev fields cannot be weaponised
//
// Follows repo conventions: pure Node stdlib, ESM, no framework, same ok() harness as siblings.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeRouteDoc, validateRouteDoc, makeIntentManifest, validateIntentManifest, PROTOCOL_VERSION } from '../core/schema.mjs';
import { validateCity, findSecrets, scrubText, serializeNode, SECRET_PATTERNS } from '../core/contract.mjs';
import { validateConfig, DEFAULTS } from '../core/config.mjs';
import { kcRoute } from '../core/route.mjs';
import { kcBundle } from '../core/bundle.mjs';
import { parseDestination } from '../core/destination.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-policy-fuzz-')); }

// ---------------------------------------------------------------------------
// Shared in-memory graph used by several routing / graph-state tests.
//
//   admin/rbac.js   ─ 'privilege' category (sensitive namespace)
//   user/profile.js ─ 'code' category
//   shared/utils.js ─ 'code' category, imported by both others
// ---------------------------------------------------------------------------
const graphNodes = [
  {
    id: 'fs:admin/rbac.js',
    kind: 'file',
    title: 'RBAC policy',
    summary: 'Role-based access-control rules',
    category: 'privilege',
    headings: ['isAdmin', 'checkRole'],
    tags: ['auth', 'rbac'],
    links: ['fs:shared/utils.js'],
    churn: null,
    provenance: { store: 'fs', ref: 'admin/rbac.js' },
  },
  {
    id: 'fs:user/profile.js',
    kind: 'file',
    title: 'User profile',
    summary: 'User data management',
    category: 'code',
    headings: ['getProfile', 'updateProfile'],
    tags: ['user'],
    links: ['fs:shared/utils.js'],
    churn: null,
    provenance: { store: 'fs', ref: 'user/profile.js' },
  },
  {
    id: 'fs:shared/utils.js',
    kind: 'file',
    title: 'Shared utilities',
    summary: 'Common helper functions',
    category: 'code',
    headings: ['log', 'validate'],
    tags: ['utils'],
    links: [],
    churn: null,
    provenance: { store: 'fs', ref: 'shared/utils.js' },
  },
];
const graphById = new Map(graphNodes.map(n => [n.id, n]));
const graphCtx = {
  city: {
    nodes: graphNodes,
    categories: [
      { id: 'privilege', label: 'Privilege', order: 0 },
      { id: 'code', label: 'Code', order: 1 },
    ],
    source_rev: 'deadbeef',
  },
  byId: graphById,
};

// ===========================================================================
// SECTION 1 — Authorization-correctness
// ===========================================================================
console.log('\n--- 1. Authorization-correctness ---');

// (1a) Every route doc produced by kcRoute has advisory === true.
//      The system is advisory-only; a route doc must never claim to grant access.
{
  const destinations = [
    'file:admin/rbac.js',
    'folder:admin',
    'district:privilege',
    'importsOf:admin/rbac.js',
    'depChainTo:shared/utils.js',
    'rbac',          // keyword fallback
    'checkRole',     // keyword matching a heading in the admin node
  ];
  for (const dest of destinations) {
    const doc = kcRoute(graphCtx, dest);
    ok(`(1a) advisory === true for destination "${dest}"`, doc.advisory === true);
  }
}

// (1b) Confidence is always in [0, 1] for any destination — including hostile inputs.
{
  const hostileDestinations = [
    '',                       // empty string
    ':',                      // bare colon
    'file:',                  // empty suffix
    'folder:',
    'district:',
    'importsOf:',
    'depChainTo:',
    '../etc/passwd',          // traversal as keyword
    '/absolute/path',         // absolute as keyword
    'a'.repeat(2000),         // very long keyword
    '\x00\x01\x02',           // control characters
    '{}[]<>"\'"',             // shell metacharacters
  ];
  for (const dest of hostileDestinations) {
    let threw = false, doc = null;
    try { doc = kcRoute(graphCtx, dest); } catch { threw = true; }
    ok(`(1b) kcRoute does not throw on hostile dest "${dest.slice(0, 40)}"`, !threw);
    if (doc) {
      ok(`(1b) confidence in [0,1] for dest "${dest.slice(0, 40)}"`,
        typeof doc.confidence === 'number' && doc.confidence >= 0 && doc.confidence <= 1);
    }
  }
}

// (1c) Mandatory advisory caveat always present (regardless of destination type).
{
  const doc1 = kcRoute(graphCtx, 'file:admin/rbac.js');
  const doc2 = kcRoute(graphCtx, 'district:privilege');
  const doc3 = kcRoute(graphCtx, 'rbac');
  ok('(1c) advisory caveat in file: route',
    doc1.caveats.some(c => c.includes('advisory route')));
  ok('(1c) advisory caveat in district: route',
    doc2.caveats.some(c => c.includes('advisory route')));
  ok('(1c) advisory caveat in keyword route',
    doc3.caveats.some(c => c.includes('advisory route')));
}

// (1d) Route for an unknown (non-existent) file returns a valid doc with empty route
//      and confidence === 0.  Zero-confidence is the authorization-correctness floor.
{
  const doc = kcRoute(graphCtx, 'file:no/such/privilege.js');
  const result = validateRouteDoc(doc);
  ok('(1d) unknown file -> empty route', doc.route.length === 0);
  ok('(1d) unknown file -> confidence === 0', doc.confidence === 0);
  ok('(1d) unknown file -> advisory === true', doc.advisory === true);
  ok('(1d) unknown file -> valid route doc', result.ok === true, JSON.stringify(result.errors));
}

// (1e) Route paths are always relative (no leading /, no .., no Windows drives).
//      This ensures a route doc cannot be leveraged to suggest absolute system paths.
{
  const doc = kcRoute(graphCtx, 'district:privilege');
  const allPaths = [
    ...(doc.route      || []).map(e => (typeof e === 'string' ? e : e.path)),
    ...(doc.alternates || []).map(e => (typeof e === 'string' ? e : e.path)),
    ...(doc.tests      || []).map(e => (typeof e === 'string' ? e : e.path)),
    ...(doc.docs       || []).map(e => (typeof e === 'string' ? e : e.path)),
  ].filter(p => typeof p === 'string');

  const hasAbsolute   = allPaths.some(p => p.startsWith('/') || /^[A-Za-z]:[\\\/]/.test(p));
  const hasDotDot     = allPaths.some(p => p.split(/[/\\]/).includes('..'));
  ok('(1e) no absolute paths in route doc', !hasAbsolute, JSON.stringify(allPaths));
  ok('(1e) no ".." segments in route doc', !hasDotDot, JSON.stringify(allPaths));
}

// (1f) schema.validateRouteDoc rejects advisory === false (no matter what else is set).
{
  const doc = makeRouteDoc({ destination: 'admin/rbac.js', confidence: 0.9 });
  doc.advisory = false;
  const result = validateRouteDoc(doc);
  ok('(1f) advisory=false rejected by validateRouteDoc', result.ok === false);
  ok('(1f) error mentions advisory', result.errors.some(e => e.includes('advisory')),
    JSON.stringify(result.errors));
}

// (1g) validateRouteDoc rejects confidence outside [0, 1].
{
  const cases = [
    [1.001, 'slightly over 1'],
    [-0.001, 'slightly under 0'],
    [Infinity, 'Infinity'],
    [-Infinity, '-Infinity'],
    [NaN, 'NaN'],
    ['high', 'string'],
    [null, 'null'],
  ];
  for (const [conf, label] of cases) {
    const doc = makeRouteDoc({ destination: 'x', confidence: conf });
    const result = validateRouteDoc(doc);
    ok(`(1g) confidence "${label}" rejected`, result.ok === false,
      JSON.stringify(result.errors));
  }
}

// ===========================================================================
// SECTION 2 — Trust-root / key-state
// ===========================================================================
console.log('\n--- 2. Trust-root / key-state ---');

// (2a) Protocol version injection: any knosky_protocol != "1.0" is rejected.
{
  const routeVersions = ['', '0.9', '1', '1.1', '2.0', '1.0.0', null, 42, true];
  for (const v of routeVersions) {
    const doc = makeRouteDoc({ destination: 'x' });
    doc.knosky_protocol = v;
    const res = validateRouteDoc(doc);
    ok(`(2a) route doc protocol "${v}" rejected (not "1.0")`, res.ok === false,
      JSON.stringify(res.errors));
  }
  const manifestVersions = ['', '0.9', '2.0', null];
  for (const v of manifestVersions) {
    const m = makeIntentManifest({ secret_scan: { status: 'clean' } });
    m.knosky_protocol = v;
    const res = validateIntentManifest(m);
    ok(`(2a) manifest protocol "${v}" rejected (not "1.0")`, res.ok === false,
      JSON.stringify(res.errors));
  }
}

// (2b) artifact_type cannot be cross-injected between route and intent-manifest.
{
  const route = makeRouteDoc({ destination: 'x' });
  route.artifact_type = 'intent-manifest';
  ok('(2b) route doc with artifact_type="intent-manifest" rejected by validateRouteDoc',
    validateRouteDoc(route).ok === false);

  const manifest = makeIntentManifest({ secret_scan: { status: 'clean' } });
  manifest.artifact_type = 'route';
  ok('(2b) manifest with artifact_type="route" rejected by validateIntentManifest',
    validateIntentManifest(manifest).ok === false);
}

// (2c) secret_scan.status cannot be forged to a synthetic value.
//      Only "clean" and "blocked" are valid; anything else is a structural error.
{
  const forgedStatuses = ['approved', 'ok', 'pass', 'CLEAN', 'BLOCKED', '', null, 0, true];
  for (const s of forgedStatuses) {
    const m = makeIntentManifest({ secret_scan: { status: s } });
    const res = validateIntentManifest(m);
    ok(`(2c) secret_scan.status="${JSON.stringify(s)}" rejected`, res.ok === false,
      JSON.stringify(res.errors));
  }
}

// (2d) secret_scan result reported by kcBundle cannot be overridden by an attacker-controlled
//      node whose provenance.ref points to a file that contains a known secret pattern.
//      Even if the node is mixed with clean nodes, the entire bundle is BLOCKED.
{
  const tmpSec = tmp();
  const FAKE_AWS = 'AKIAIOSFODNN7EXAMPLE';
  const FAKE_OAI = 'sk-AAAAAAAAAAAAAAAAAAAAB'; // 20-char body matches \bsk-[A-Za-z0-9]{20,}\b

  fs.writeFileSync(path.join(tmpSec, 'secret.js'), `const a = "${FAKE_AWS}";\n`);
  fs.writeFileSync(path.join(tmpSec, 'openai.js'), `const b = "${FAKE_OAI}";\n`);
  fs.writeFileSync(path.join(tmpSec, 'clean.js'), '// nothing here\n');

  const nSecret = { id: 'fs:secret.js', kind: 'file', title: 'Sec', category: 'code', links: [], provenance: { store: 'fs', ref: 'secret.js' } };
  const nOpenai = { id: 'fs:openai.js', kind: 'file', title: 'Oai', category: 'code', links: [], provenance: { store: 'fs', ref: 'openai.js' } };
  const nClean  = { id: 'fs:clean.js',  kind: 'file', title: 'Cln', category: 'code', links: [], provenance: { store: 'fs', ref: 'clean.js'  } };

  const ctxSec = {
    city: { nodes: [nSecret, nOpenai, nClean] },
    byId: new Map([[nSecret.id, nSecret], [nOpenai.id, nOpenai], [nClean.id, nClean]]),
  };

  // All three in one bundle — blocked because of the two secret files
  const m1 = kcBundle(ctxSec, [nSecret.id, nClean.id, nOpenai.id], { root: tmpSec });
  ok('(2d) mixed-bundle with AWS key is BLOCKED', m1.secret_scan.status === 'blocked',
    JSON.stringify(m1.secret_scan));
  ok('(2d) serialized manifest does not contain AWS key', !JSON.stringify(m1).includes(FAKE_AWS));
  ok('(2d) serialized manifest does not contain OAI key', !JSON.stringify(m1).includes(FAKE_OAI));

  // Clean-only bundle is still clean
  const m2 = kcBundle(ctxSec, [nClean.id], { root: tmpSec });
  ok('(2d) clean-only bundle is CLEAN', m2.secret_scan.status === 'clean');

  fs.rmSync(tmpSec, { recursive: true, force: true });
}

// (2e) findSecrets: on-boundary pattern checks — first failing then first passing case
//      for the two most common key families (AWS access key, OpenAI key).
{
  // AWS access key: AKIA + exactly 16 alphanumeric chars
  const awsShort = 'AKIAIOSFODNN7EXAMPL';   // 15 chars after AKIA — must NOT match
  const awsExact = 'AKIAIOSFODNN7EXAMPLE';  // 16 chars — MUST match
  ok('(2e) AWS key one-char-short: NOT detected', findSecrets(awsShort).length === 0,
    JSON.stringify(findSecrets(awsShort)));
  ok('(2e) AWS key at exact minimum: detected', findSecrets(awsExact).length > 0,
    JSON.stringify(findSecrets(awsExact)));

  // OpenAI key: sk- + at least 20 alphanumeric chars
  const oaiShort = 'sk-AAAAAAAAAAAAAAAAAAA';    // 19 A's — must NOT match
  const oaiExact = 'sk-AAAAAAAAAAAAAAAAAAAAB';  // 20+ chars — MUST match
  ok('(2e) OAI key one-char-short: NOT detected', findSecrets(oaiShort).length === 0,
    JSON.stringify(findSecrets(oaiShort)));
  ok('(2e) OAI key at minimum: detected', findSecrets(oaiExact).length > 0,
    JSON.stringify(findSecrets(oaiExact)));
}

// (2f) scrubText redacts secrets and PII from serialized projections.
//      A title or summary that slips through to a route doc must have been scrubbed.
{
  const FAKE_GHP = 'ghp_AAAAAAAAAAAAAAAAAAAA'; // matches /\bgh[posru]_[A-Za-z0-9]{20,}\b/
  const rawTitle = `Config ${FAKE_GHP} and admin@example.com`;
  const scrubbed = scrubText(rawTitle);
  ok('(2f) github token scrubbed from title', !scrubbed.includes(FAKE_GHP),
    JSON.stringify(scrubbed));
  ok('(2f) email scrubbed from title', !/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(scrubbed),
    JSON.stringify(scrubbed));
  ok('(2f) scrubText returns [REDACTED] placeholder', scrubbed.includes('[REDACTED]'),
    JSON.stringify(scrubbed));
}

// (2g) serializeNode drops non-allowlisted fields — a "body" carry cannot leak content.
{
  const maliciousNode = {
    id: 'fs:admin/rbac.js',
    kind: 'file',
    title: 'RBAC',
    category: 'privilege',
    links: [],
    provenance: { store: 'fs', ref: 'admin/rbac.js' },
    // Non-allowlisted fields that could carry sensitive content:
    body: 'SECRET_BODY_CONTENT AKIAIOSFODNN7EXAMPLE',
    raw: 'const adminToken = "ghp_AAAAAAAAAAAAAAAAAAAA";',
    exec: 'rm -rf /',
    __proto__: {},
  };
  const serialized = serializeNode(maliciousNode);
  ok('(2g) body field not in serialized node', !('body' in serialized));
  ok('(2g) raw field not in serialized node', !('raw' in serialized));
  ok('(2g) exec field not in serialized node', !('exec' in serialized));
  ok('(2g) id/kind/title/links/provenance preserved', serialized.id && serialized.kind && serialized.title);
}

// (2h) Config fail-closed: telemetry is always false, fail_on_secret always true by default.
//      An attacker cannot rely on missing-config → permissive defaults.
{
  const cfg = { ...DEFAULTS };
  ok('(2h) DEFAULTS.telemetry is false', cfg.telemetry === false);
  ok('(2h) DEFAULTS.fail_on_secret is true', cfg.fail_on_secret === true);
  ok('(2h) DEFAULTS.absolute_paths is false', cfg.absolute_paths === false);
  ok('(2h) DEFAULTS.allow_excerpts is false', cfg.allow_excerpts === false);
}

// (2i) Config validation rejects attempts to turn off fail_on_secret via type confusion.
//      The field must be a boolean — strings, ints, null are rejected.
{
  const badValues = ['false', 0, null, undefined, 'no'];
  for (const v of badValues) {
    const cfg = { ...DEFAULTS, fail_on_secret: v };
    const res = validateConfig(cfg);
    ok(`(2i) fail_on_secret="${JSON.stringify(v)}" rejected by validateConfig`, res.ok === false,
      JSON.stringify(res.errors));
  }
}

// ===========================================================================
// SECTION 3 — Graph-state
// ===========================================================================
console.log('\n--- 3. Graph-state ---');

// (3a) Cyclic import graph: kcRoute and parseDestination terminate without hang.
//      A→B→C→A with D→A for good measure.
{
  const mkN = (id, links) => ({
    id, kind: 'file', title: id, category: 'code', links,
    provenance: { store: 'fs', ref: id.replace(/^fs:/, '') },
  });
  const cA = mkN('fs:cycle/a.js', ['fs:cycle/b.js']);
  const cB = mkN('fs:cycle/b.js', ['fs:cycle/c.js']);
  const cC = mkN('fs:cycle/c.js', ['fs:cycle/a.js']); // creates A→B→C→A loop
  const cD = mkN('fs:cycle/d.js', ['fs:cycle/a.js']);
  const cycNodes = [cA, cB, cC, cD];
  const cycCtx = {
    city: { nodes: cycNodes, categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map(cycNodes.map(n => [n.id, n])),
  };

  const start = Date.now();
  let cyclicDoc = null, cycleThrew = false;
  try { cyclicDoc = kcRoute(cycCtx, 'file:cycle/a.js'); } catch { cycleThrew = true; }
  const elapsed = Date.now() - start;
  ok('(3a) kcRoute on cyclic graph does not throw', !cycleThrew);
  ok('(3a) kcRoute on cyclic graph terminates quickly (<3s)', elapsed < 3000, `(${elapsed}ms)`);
  if (cyclicDoc) {
    ok('(3a) cyclic route doc is valid', validateRouteDoc(cyclicDoc).ok === true);
    const cycleRes = validateRouteDoc(cyclicDoc);
    ok('(3a) cyclic route doc passes schema validation', cycleRes.ok === true,
      JSON.stringify(cycleRes.errors));
  }

  const startBFS = Date.now();
  let bfsResult = null, bfsThrew = false;
  try { bfsResult = parseDestination(cycCtx, 'depChainTo:cycle/a.js', 20); } catch { bfsThrew = true; }
  ok('(3a) depChainTo on cyclic graph does not throw', !bfsThrew);
  ok('(3a) depChainTo on cyclic graph terminates', bfsResult !== null);
  ok('(3a) depChainTo result is bounded (< 500 nodes)', !bfsResult || bfsResult.matched.length < 500);
  ok('(3a) depChainTo on cyclic graph finishes quickly (<3s)', (Date.now() - startBFS) < 3000);
}

// (3b) Dangling-link graph: node links that point to non-existent node ids must not crash
//      kcRoute or kcBundle, and dangling edges must not appear in the manifest.
{
  const ghost = {
    id: 'fs:ghost.js', kind: 'file', title: 'Ghost', category: 'code',
    links: ['fs:nonexistent-a.js', 'fs:nonexistent-b.js'],
    provenance: { store: 'fs', ref: 'ghost.js' },
  };
  const ghostCtx = {
    city: { nodes: [ghost], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[ghost.id, ghost]]),
  };

  let ghostDoc = null, ghostThrew = false;
  try { ghostDoc = kcRoute(ghostCtx, 'file:ghost.js'); } catch { ghostThrew = true; }
  ok('(3b) kcRoute on dangling-link node does not throw', !ghostThrew);
  if (ghostDoc) {
    ok('(3b) dangling-link route doc is valid', validateRouteDoc(ghostDoc).ok === true);
  }

  const bundle = kcBundle(ghostCtx, ['fs:ghost.js'], { root: undefined });
  ok('(3b) kcBundle on dangling-link node does not throw', true); // reaching here = no throw
  ok('(3b) dangling edges excluded from manifest (target not in bundle)',
    bundle.edges.length === 0);
  ok('(3b) dangling-link manifest is valid', validateIntentManifest(bundle).ok === true);
}

// (3c) Duplicate node ids in the city envelope are caught by validateCity.
{
  const dupCity = {
    schema_version: '2.0',
    generated_at: new Date().toISOString(),
    source: { kind: 'fs', ref: '.', rev: 'HEAD' },
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    nodes: [
      { id: 'fs:dup.js', kind: 'file', title: 'Dup1', category: 'code', links: [], provenance: { store: 'fs', ref: 'dup.js' } },
      { id: 'fs:dup.js', kind: 'file', title: 'Dup2', category: 'code', links: [], provenance: { store: 'fs', ref: 'dup.js' } },
    ],
    node_count: 2,
  };
  const res = validateCity(dupCity);
  ok('(3c) duplicate node id rejected by validateCity', res.ok === false);
  ok('(3c) error mentions the duplicate id', res.errors.some(e => e.includes('fs:dup.js')),
    JSON.stringify(res.errors));
}

// (3d) Node referencing a non-existent category is rejected by validateCity.
{
  const badCatCity = {
    schema_version: '2.0',
    generated_at: new Date().toISOString(),
    source: { kind: 'fs', ref: '.', rev: 'HEAD' },
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    nodes: [
      { id: 'fs:x.js', kind: 'file', title: 'X', category: 'nonexistent', links: [], provenance: { store: 'fs', ref: 'x.js' } },
    ],
    node_count: 1,
  };
  const res = validateCity(badCatCity);
  ok('(3d) node with unknown category rejected by validateCity', res.ok === false);
  ok('(3d) error mentions the offending category', res.errors.some(e => e.includes('nonexistent')),
    JSON.stringify(res.errors));
}

// (3e) Extremely large candidate set: route engine stays bounded (no OOM/hang).
//      200 nodes all connected to a hub — tests the expand-to-1-hop-neighbours path.
{
  const hub = {
    id: 'fs:hub.js', kind: 'file', title: 'Hub', category: 'code',
    links: Array.from({ length: 200 }, (_, i) => `fs:leaf${i}.js`),
    churn: null, provenance: { store: 'fs', ref: 'hub.js' },
  };
  const leaves = Array.from({ length: 200 }, (_, i) => ({
    id: `fs:leaf${i}.js`, kind: 'file', title: `Leaf ${i}`, category: 'code',
    links: [], churn: null, provenance: { store: 'fs', ref: `leaf${i}.js` },
  }));
  const bigNodes = [hub, ...leaves];
  const bigCtx = {
    city: { nodes: bigNodes, categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map(bigNodes.map(n => [n.id, n])),
  };

  const start = Date.now();
  let bigDoc = null, bigThrew = false;
  try { bigDoc = kcRoute(bigCtx, 'file:hub.js', { limit: 8 }); } catch { bigThrew = true; }
  ok('(3e) large-candidate-set: kcRoute does not throw', !bigThrew);
  ok('(3e) large-candidate-set: kcRoute terminates quickly (<3s)', (Date.now() - start) < 3000);
  if (bigDoc) {
    ok('(3e) large-candidate-set: route capped at limit (≤ 8)', bigDoc.route.length <= 8);
    ok('(3e) large-candidate-set: route doc is valid', validateRouteDoc(bigDoc).ok === true);
  }
}

// (3f) Node with non-allowlisted fields in the city graph — validateCity must flag them.
{
  const extraFieldCity = {
    schema_version: '2.0',
    generated_at: new Date().toISOString(),
    source: { kind: 'fs', ref: '.', rev: 'HEAD' },
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    nodes: [
      {
        id: 'fs:extra.js', kind: 'file', title: 'Extra', category: 'code',
        links: [], provenance: { store: 'fs', ref: 'extra.js' },
        body: 'full source here',     // explicitly banned
        secret: 'sk-AAAAAAAAAAAAAAAAAAAAB',
      },
    ],
    node_count: 1,
  };
  const res = validateCity(extraFieldCity);
  ok('(3f) city with non-allowlisted node fields is invalid', res.ok === false);
  ok('(3f) error mentions the extra field', res.errors.some(e => e.includes('body') || e.includes('secret')),
    JSON.stringify(res.errors));
}

// ===========================================================================
// SECTION 4 — Clock/ledger manipulation
// ===========================================================================
console.log('\n--- 4. Clock/ledger manipulation ---');

// (4a) generated_at: kcRoute always produces an ISO-8601 string.
//      An attacker cannot cause it to be injected as a number or null.
{
  const doc = kcRoute(graphCtx, 'file:admin/rbac.js');
  ok('(4a) generated_at is a string', typeof doc.generated_at === 'string');
  ok('(4a) generated_at looks like ISO-8601', /^\d{4}-\d{2}-\d{2}T/.test(doc.generated_at),
    JSON.stringify(doc.generated_at));
}

// (4b) generated_at: kcBundle (via makeIntentManifest) always produces an ISO-8601 string.
{
  const tmpClk = tmp();
  fs.writeFileSync(path.join(tmpClk, 'x.js'), '// clean\n');
  const nClk = { id: 'fs:x.js', kind: 'file', title: 'X', category: 'code', links: [], provenance: { store: 'fs', ref: 'x.js' } };
  const ctxClk = { city: { nodes: [nClk] }, byId: new Map([[nClk.id, nClk]]) };
  const m = kcBundle(ctxClk, ['fs:x.js'], { root: tmpClk });
  ok('(4b) manifest generated_at is a string', typeof m.generated_at === 'string');
  ok('(4b) manifest generated_at looks like ISO-8601', /^\d{4}-\d{2}-\d{2}T/.test(m.generated_at));
  fs.rmSync(tmpClk, { recursive: true, force: true });
}

// (4c) source_rev caveat is emitted when the city has a source_rev.
//      This makes the staleness window explicit in the advisory route.
{
  const doc = kcRoute(graphCtx, 'rbac'); // graphCtx has source_rev: 'deadbeef'
  const hasRevCaveat = doc.caveats.some(c => c.includes('rev') && c.includes('deadbeef'));
  ok('(4c) source_rev caveat present when city has source_rev', hasRevCaveat,
    JSON.stringify(doc.caveats));
  ok('(4c) source_rev stored in route doc', doc.source_rev === 'deadbeef');
}

// (4d) source_rev caveat absent when city has no source_rev.
{
  const noRevCtx = {
    city: { nodes: graphNodes, categories: graphCtx.city.categories, source_rev: null },
    byId: graphById,
  };
  const doc = kcRoute(noRevCtx, 'rbac');
  const revCaveats = doc.caveats.filter(c => c.includes('rev'));
  ok('(4d) no rev caveat when source_rev is null', revCaveats.length === 0,
    JSON.stringify(revCaveats));
  ok('(4d) source_rev in doc is null', doc.source_rev === null);
}

// (4e) Expiry is forwarded verbatim by kcBundle; a past expiry is structurally valid
//      (consumers must check it; the schema does not enforce future-only expiry).
//      A numeric expiry injection is forwarded but consumers are expected to reject it.
{
  const tmpExp = tmp();
  fs.writeFileSync(path.join(tmpExp, 'x.js'), '// ok\n');
  const nExp = { id: 'fs:x.js', kind: 'file', title: 'X', category: 'code', links: [], provenance: { store: 'fs', ref: 'x.js' } };
  const ctxExp = { city: { nodes: [nExp] }, byId: new Map([[nExp.id, nExp]]) };

  // Past expiry: structurally valid (schema does not enforce future-only)
  const pastExp = '1970-01-01T00:00:00.000Z';
  const m1 = kcBundle(ctxExp, ['fs:x.js'], { root: tmpExp, expiry: pastExp });
  ok('(4e) past expiry forwarded correctly', m1.expiry === pastExp);
  ok('(4e) manifest with past expiry passes schema (consumer must check)',
    validateIntentManifest(m1).ok === true);

  // Future expiry
  const futureExp = '2099-12-31T23:59:59.000Z';
  const m2 = kcBundle(ctxExp, ['fs:x.js'], { root: tmpExp, expiry: futureExp });
  ok('(4e) future expiry forwarded correctly', m2.expiry === futureExp);

  // null expiry (default)
  const m3 = kcBundle(ctxExp, ['fs:x.js'], { root: tmpExp });
  ok('(4e) default expiry is null', m3.expiry === null);

  fs.rmSync(tmpExp, { recursive: true, force: true });
}

// (4f) Manifest with an illegitimate secret_scan status cannot be produced by kcBundle
//      even if the caller modifies the returned object — the ORIGINAL call always reflects
//      the true scan outcome, and consumers must treat any post-production mutation as invalid.
//      We verify that validateIntentManifest catches the mutation.
{
  const tmpPost = tmp();
  fs.writeFileSync(path.join(tmpPost, 'clean.js'), '// clean\n');
  const nPost = { id: 'fs:clean.js', kind: 'file', title: 'Clean', category: 'code', links: [], provenance: { store: 'fs', ref: 'clean.js' } };
  const ctxPost = { city: { nodes: [nPost] }, byId: new Map([[nPost.id, nPost]]) };

  const m = kcBundle(ctxPost, ['fs:clean.js'], { root: tmpPost });
  ok('(4f) honest clean scan produces status="clean"', m.secret_scan.status === 'clean');

  // Simulate a consumer mutation attempting to forge 'blocked' → 'clean'
  const mutated = { ...m, secret_scan: { status: 'approved', count: 0 } };
  const res = validateIntentManifest(mutated);
  ok('(4f) forged status "approved" rejected by validateIntentManifest', res.ok === false,
    JSON.stringify(res.errors));

  fs.rmSync(tmpPost, { recursive: true, force: true });
}

// (4g) node_count mismatch in the city envelope is caught by validateCity.
//      An attacker cannot forge a city that claims fewer nodes than are present.
{
  const mismatchCity = {
    schema_version: '2.0',
    generated_at: new Date().toISOString(),
    source: { kind: 'fs', ref: '.', rev: 'HEAD' },
    categories: [{ id: 'code', label: 'Code', order: 0 }],
    nodes: [
      { id: 'fs:a.js', kind: 'file', title: 'A', category: 'code', links: [], provenance: { store: 'fs', ref: 'a.js' } },
      { id: 'fs:b.js', kind: 'file', title: 'B', category: 'code', links: [], provenance: { store: 'fs', ref: 'b.js' } },
    ],
    node_count: 1, // deliberately wrong
  };
  const res = validateCity(mismatchCity);
  ok('(4g) node_count mismatch rejected by validateCity', res.ok === false);
  ok('(4g) error mentions node_count', res.errors.some(e => e.includes('node_count')),
    JSON.stringify(res.errors));
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
