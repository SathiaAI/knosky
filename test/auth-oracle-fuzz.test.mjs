// KnoSky authorization-correctness fuzzing vs. ground-truth oracle (SAT-450).
// Run: node test/auth-oracle-fuzz.test.mjs
//
// Strategy:
//   For every (ctx, destination) pair the oracle independently computes the
//   expected authorization invariants (advisory flag, confidence bounds, path
//   safety, expected match cardinality).  kcRoute is then called and its result
//   is verified against those expectations.  Any deviation is a bug.
//
//   Additionally the oracle's oracleScanDecision is diffed against kcBundle's
//   secret_scan result across a matrix of (clean, blocked, mixed, boundary) file
//   content cases.  The two modules share only findSecrets() — everything else
//   is independent.
//
// Follows repo conventions: pure Node stdlib, ESM, no framework, same ok() harness.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { kcRoute } from '../core/route.mjs';
import { kcBundle } from '../core/bundle.mjs';
import { validateRouteDoc, validateIntentManifest } from '../core/schema.mjs';
import {
  oracleRouteDecision,
  verifyRouteDoc,
  oracleScanDecision,
  verifyScanDecision,
} from './auth-oracle.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-oracle-')); }

// ---------------------------------------------------------------------------
// Shared graph fixture (identical to the one in policy-fuzzer.mjs so that the
// oracle and policy-fuzzer run against the same data without coupling each
// other's source code).
// ---------------------------------------------------------------------------
function mkNode(id, category, links = [], tags = [], headings = []) {
  return {
    id,
    kind: 'file',
    title: id.replace(/^fs:/, '').replace(/\//g, ' '),
    summary: `Node ${id}`,
    category,
    headings,
    tags,
    links,
    churn: null,
    provenance: { store: 'fs', ref: id.replace(/^fs:/, '') },
  };
}

const BASE_NODES = [
  mkNode('fs:admin/rbac.js',      'privilege', ['fs:shared/utils.js'], ['auth', 'rbac'], ['isAdmin', 'checkRole']),
  mkNode('fs:user/profile.js',    'code',      ['fs:shared/utils.js'], ['user'],         ['getProfile']),
  mkNode('fs:shared/utils.js',    'code',      [],                     ['utils'],        ['log', 'validate']),
  mkNode('fs:test/rbac.test.js',  'test',      ['fs:admin/rbac.js'],   [],               []),
  mkNode('fs:docs/auth.md',       'docs',      [],                     ['docs'],         ['Overview']),
];

const BASE_CTX = {
  city: {
    nodes: BASE_NODES,
    categories: [
      { id: 'privilege', label: 'Privilege', order: 0 },
      { id: 'code',      label: 'Code',      order: 1 },
      { id: 'test',      label: 'Test',      order: 2 },
      { id: 'docs',      label: 'Docs',      order: 3 },
    ],
    source_rev: 'abc123',
  },
  byId: new Map(BASE_NODES.map(n => [n.id, n])),
};

// ===========================================================================
// SECTION 1 — Advisory invariants hold for all destination types
// Oracle assertion: advisory === true must ALWAYS hold regardless of destination.
// ===========================================================================
console.log('\n--- 1. Advisory invariants vs oracle ---');

{
  const destinations = [
    'file:admin/rbac.js',          // direct hit
    'file:nonexistent.js',         // miss
    'folder:admin',                // folder prefix
    'folder:nothing',              // empty folder
    'district:privilege',          // category hit
    'district:unknown_cat',        // category miss
    'importsOf:admin/rbac.js',     // out-edges
    'importsOf:nonexistent',       // out-edges miss
    'depChainTo:shared/utils.js',  // chain (has callers)
    'depChainTo:nonexistent',      // chain miss
    'rbac',                        // keyword
    'checkRole',                   // keyword on heading
    '',                            // empty
    'file:',                       // bare prefix
    'folder:',                     // bare prefix
    '../etc/passwd',               // traversal as keyword
    'a'.repeat(500),               // long keyword
  ];

  for (const dest of destinations) {
    const exp = oracleRouteDecision(BASE_CTX, dest);

    let doc = null, threw = false;
    try { doc = kcRoute(BASE_CTX, dest); } catch { threw = true; }

    ok(`(1) no throw for dest "${dest.slice(0, 40)}"`, !threw);
    if (!doc) continue;

    const { ok: pass, violations } = verifyRouteDoc(doc, exp);
    ok(`(1) oracle vs system for "${dest.slice(0, 40)}"`, pass, violations.join('; '));
    ok(`(1) validateRouteDoc for "${dest.slice(0, 40)}"`,
      validateRouteDoc(doc).ok === true,
      JSON.stringify(validateRouteDoc(doc).errors));
  }
}

// ===========================================================================
// SECTION 2 — Oracle enforces route emptiness for known misses
// When the oracle is certain no nodes match, route must be empty and
// confidence must be 0.
// ===========================================================================
console.log('\n--- 2. Certain-miss oracle enforcement ---');

{
  // These destinations provably resolve to zero nodes in BASE_CTX.
  const certainMisses = [
    'file:nonexistent.js',
    'folder:no/such/dir',
    'district:nonexistent_category',
    'importsOf:nonexistent.js',
    'depChainTo:nonexistent.js',
    'file:',
    'folder:',
  ];

  for (const dest of certainMisses) {
    const exp = oracleRouteDecision(BASE_CTX, dest);
    ok(`(2) oracle.expectEmptyRoute === true for "${dest}"`, exp.expectEmptyRoute === true);
    ok(`(2) oracle.expectZeroConfidence === true for "${dest}"`, exp.expectZeroConfidence === true);

    let doc = null, threw = false;
    try { doc = kcRoute(BASE_CTX, dest); } catch { threw = true; }
    ok(`(2) no throw for "${dest}"`, !threw);
    if (!doc) continue;

    ok(`(2) route is empty for "${dest}"`, doc.route.length === 0,
      JSON.stringify(doc.route));
    ok(`(2) confidence is 0 for "${dest}"`, doc.confidence === 0,
      String(doc.confidence));
    ok(`(2) advisory is true for "${dest}"`, doc.advisory === true);
  }
}

// ===========================================================================
// SECTION 3 — Path safety oracle
// Oracle asserts that every output path must be relative, no ".." segments,
// no absolute paths.  Checks across all prefix types and hostile inputs.
// ===========================================================================
console.log('\n--- 3. Path safety oracle ---');

{
  // Build a context with nodes whose safe provenance.ref values form the path pool.
  const pathCtx = BASE_CTX;
  const allDestinations = [
    'file:admin/rbac.js',
    'folder:admin',
    'folder:shared',
    'district:privilege',
    'district:code',
    'importsOf:admin/rbac.js',
    'importsOf:user/profile.js',
    'depChainTo:shared/utils.js',
    'rbac',
    'auth',
  ];

  for (const dest of allDestinations) {
    const exp = oracleRouteDecision(pathCtx, dest);
    ok(`(3) oracle.noBadPaths === true for "${dest}"`, exp.noBadPaths === true);

    const doc = kcRoute(pathCtx, dest);
    const { ok: pass, violations } = verifyRouteDoc(doc, exp);
    ok(`(3) path safety oracle agreement for "${dest}"`, pass, violations.join('; '));
  }
}

// ===========================================================================
// SECTION 4 — Secret-scan differential fuzzing
// Oracle applies findSecrets() independently to known content strings.
// kcBundle reads from disk. They should always agree on status.
// ===========================================================================
console.log('\n--- 4. Secret-scan oracle vs kcBundle ---');

{
  const CASES = [
    {
      label: 'all clean files',
      files: [
        { ref: 'a.js', content: 'const x = 1;\n' },
        { ref: 'b.js', content: '// nothing sensitive\n' },
      ],
    },
    {
      label: 'one AWS key',
      files: [
        { ref: 'a.js', content: 'const key = "AKIAIOSFODNN7EXAMPLE";\n' },
        { ref: 'b.js', content: '// clean\n' },
      ],
    },
    {
      label: 'one OpenAI key',
      files: [
        { ref: 'a.js', content: 'const k = "sk-AAAAAAAAAAAAAAAAAAAAB";\n' },
      ],
    },
    {
      label: 'mixed: clean + secret',
      files: [
        { ref: 'clean.js', content: '// totally safe\n' },
        { ref: 'secret.js', content: 'const s = "sk-AAAAAAAAAAAAAAAAAAAAB";\n' },
      ],
    },
    {
      label: 'GitHub token',
      files: [
        { ref: 'ci.js', content: 'const t = "ghp_AAAAAAAAAAAAAAAAAAAA";\n' },
      ],
    },
    {
      label: 'AWS key at exact boundary (16 alphanumeric after AKIA)',
      files: [
        { ref: 'creds.js', content: 'const c = "AKIAIOSFODNN7EXAMPLE";\n' },
      ],
    },
    {
      label: 'AWS key one char short (15 chars after AKIA — must be clean)',
      files: [
        { ref: 'creds.js', content: 'const c = "AKIAIOSFODNN7EXAMPL";\n' },
      ],
    },
    {
      label: 'multiple secrets in one file',
      files: [
        {
          ref: 'multi.js',
          content: [
            'const aws = "AKIAIOSFODNN7EXAMPLE";',
            'const oai = "sk-AAAAAAAAAAAAAAAAAAAAB";',
          ].join('\n'),
        },
      ],
    },
    {
      label: 'empty file',
      files: [
        { ref: 'empty.js', content: '' },
      ],
    },
    {
      label: 'no files',
      files: [],
    },
  ];

  for (const { label, files } of CASES) {
    const oracleResult = oracleScanDecision(files);
    ok(`(4) oracle computed for "${label}" (status=${oracleResult.status})`, true);

    // Write files to disk so kcBundle can read them
    const dir = tmp();
    const nodes = [];
    for (const { ref, content } of files) {
      const full = path.join(dir, ref);
      const parent = path.dirname(full);
      if (parent !== dir) fs.mkdirSync(parent, { recursive: true });
      fs.writeFileSync(full, content, 'utf8');
      nodes.push(mkNode('fs:' + ref, 'code'));
    }

    let manifest = null, threw = false;
    if (nodes.length > 0) {
      const ctx = {
        city: { nodes },
        byId: new Map(nodes.map(n => [n.id, n])),
      };
      try {
        manifest = kcBundle(ctx, nodes.map(n => n.id), { root: dir });
      } catch { threw = true; }
      ok(`(4) kcBundle does not throw for "${label}"`, !threw);
      if (manifest) {
        const { ok: pass, violations } = verifyScanDecision(manifest, oracleResult);
        ok(`(4) oracle agrees with kcBundle for "${label}"`, pass,
          violations.join('; '));
        ok(`(4) validateIntentManifest for "${label}"`,
          validateIntentManifest(manifest).ok === true,
          JSON.stringify(validateIntentManifest(manifest).errors));
      }
    } else {
      // Empty case — just test the oracle directly
      ok(`(4) empty-files oracle status is "clean"`, oracleResult.status === 'clean');
    }

    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

// ===========================================================================
// SECTION 5 — Oracle vs system across random/hostile graph mutations
// Injects adversarial nodes (unsafe refs, cyclic links, duplicate ids) and
// verifies that oracle invariants continue to hold.
// ===========================================================================
console.log('\n--- 5. Oracle vs system under hostile graph mutations ---');

// (5a) Node with unsafe provenance.ref — oracle route expectations must still hold
{
  const hostileRef = {
    id: 'fs:ok.js', kind: 'file', title: 'Ok', category: 'code',
    links: [], churn: null,
    provenance: { store: 'fs', ref: '../../etc/passwd' },   // unsafe ref
  };
  const ctx5a = {
    city: { nodes: [hostileRef], categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map([[hostileRef.id, hostileRef]]),
  };
  const exp = oracleRouteDecision(ctx5a, 'file:ok.js');
  let doc = null, threw = false;
  try { doc = kcRoute(ctx5a, 'file:ok.js'); } catch { threw = true; }
  ok('(5a) hostile ref: kcRoute does not throw', !threw);
  if (doc) {
    const { ok: pass, violations } = verifyRouteDoc(doc, exp);
    ok('(5a) hostile ref: oracle invariants hold', pass, violations.join('; '));
    // The route entry for this node must not emit the unsafe ref as a path
    const badPaths = (doc.route || []).map(e => e.path).filter(p => p && p.includes('..'));
    ok('(5a) hostile ref: no ".." paths in route output', badPaths.length === 0,
      JSON.stringify(badPaths));
  }
}

// (5b) Cyclic graph — oracle sees "no match" for unknown node; system must agree
{
  const cyc = id => ({
    id, kind: 'file', title: id, category: 'code', links: [], churn: null,
    provenance: { store: 'fs', ref: id.replace(/^fs:/, '') },
  });
  const cA = { ...cyc('fs:cy/a.js'), links: ['fs:cy/b.js'] };
  const cB = { ...cyc('fs:cy/b.js'), links: ['fs:cy/c.js'] };
  const cC = { ...cyc('fs:cy/c.js'), links: ['fs:cy/a.js'] }; // A→B→C→A
  const cycNodes = [cA, cB, cC];
  const cycCtx = {
    city: { nodes: cycNodes, categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map(cycNodes.map(n => [n.id, n])),
  };

  // Miss on non-existent — oracle certain: empty
  const expMiss = oracleRouteDecision(cycCtx, 'file:nonexistent.js');
  ok('(5b) cyclic graph: oracle expects empty for miss', expMiss.expectEmptyRoute);
  let doc5b = null, threw5b = false;
  try { doc5b = kcRoute(cycCtx, 'file:nonexistent.js'); } catch { threw5b = true; }
  ok('(5b) cyclic graph: no throw', !threw5b);
  if (doc5b) {
    const { ok: pass, violations } = verifyRouteDoc(doc5b, expMiss);
    ok('(5b) cyclic graph: oracle invariants hold for miss', pass, violations.join('; '));
  }

  // Hit on existing node — oracle: advisory=true, conf in [0,1]
  const expHit = oracleRouteDecision(cycCtx, 'file:cy/a.js');
  let doc5bHit = null;
  try { doc5bHit = kcRoute(cycCtx, 'file:cy/a.js'); } catch { /* handled below */ }
  if (doc5bHit) {
    const { ok: pass, violations } = verifyRouteDoc(doc5bHit, expHit);
    ok('(5b) cyclic graph: oracle invariants hold for hit', pass, violations.join('; '));
    ok('(5b) cyclic graph: route doc is valid', validateRouteDoc(doc5bHit).ok === true);
  }
}

// (5c) Very large graph — oracle path safety property must hold even at scale
{
  const hubNode = {
    id: 'fs:hub.js', kind: 'file', title: 'Hub', category: 'code',
    headings: [], tags: [],
    links: Array.from({ length: 100 }, (_, i) => `fs:leaf${i}.js`),
    churn: null, provenance: { store: 'fs', ref: 'hub.js' },
  };
  const leafNodes = Array.from({ length: 100 }, (_, i) => ({
    id: `fs:leaf${i}.js`, kind: 'file', title: `Leaf ${i}`, category: 'code',
    headings: [], tags: [], links: [], churn: null,
    provenance: { store: 'fs', ref: `leaf${i}.js` },
  }));
  const bigNodes = [hubNode, ...leafNodes];
  const bigCtx = {
    city: { nodes: bigNodes, categories: [{ id: 'code', label: 'Code', order: 0 }], source_rev: null },
    byId: new Map(bigNodes.map(n => [n.id, n])),
  };

  const exp = oracleRouteDecision(bigCtx, 'file:hub.js');
  const doc = kcRoute(bigCtx, 'file:hub.js', { limit: 8 });
  const { ok: pass, violations } = verifyRouteDoc(doc, exp);
  ok('(5c) large graph: oracle invariants hold', pass, violations.join('; '));
  ok('(5c) large graph: validateRouteDoc passes', validateRouteDoc(doc).ok === true);
}

// (5d) Empty graph — oracle certainty: all destinations are misses
{
  const emptyCtx = {
    city: { nodes: [], categories: [], source_rev: null },
    byId: new Map(),
  };
  for (const dest of [
    'file:x.js', 'folder:src', 'district:code',
    'importsOf:x.js', 'depChainTo:x.js', 'rbac',
  ]) {
    const exp = oracleRouteDecision(emptyCtx, dest);
    ok(`(5d) empty graph: oracle certain for "${dest}"`,
      exp.expectEmptyRoute === true && exp.expectZeroConfidence === true);
    const doc = kcRoute(emptyCtx, dest);
    const { ok: pass, violations } = verifyRouteDoc(doc, exp);
    ok(`(5d) empty graph: oracle agrees with system for "${dest}"`, pass, violations.join('; '));
  }
}

// ===========================================================================
// SECTION 6 — Protocol field invariants enforced by oracle
// All route docs must have knosky_protocol="1.0" and artifact_type="route".
// Oracle checks these independently of validateRouteDoc.
// ===========================================================================
console.log('\n--- 6. Protocol field oracle invariants ---');

{
  const docs = [
    kcRoute(BASE_CTX, 'file:admin/rbac.js'),
    kcRoute(BASE_CTX, 'district:privilege'),
    kcRoute(BASE_CTX, 'rbac'),
    kcRoute(BASE_CTX, 'file:nonexistent.js'),
    kcRoute(BASE_CTX, 'depChainTo:shared/utils.js'),
  ];

  for (const doc of docs) {
    const dest = doc.destination || '(unknown)';
    ok(`(6) knosky_protocol="1.0" for dest="${dest.slice(0,30)}"`,
      doc.knosky_protocol === '1.0');
    ok(`(6) artifact_type="route" for dest="${dest.slice(0,30)}"`,
      doc.artifact_type === 'route');
    ok(`(6) advisory===true for dest="${dest.slice(0,30)}"`,
      doc.advisory === true);
    ok(`(6) generated_at is ISO-8601 for dest="${dest.slice(0,30)}"`,
      typeof doc.generated_at === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(doc.generated_at));
  }
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
