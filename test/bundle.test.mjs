// KnoSky bundle engine tests. Run: node test/bundle.test.mjs
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { kcBundle } from '../core/bundle.mjs';
import { validateIntentManifest } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Set up a temp dir with two files: one clean, one containing a fake secret.
// ---------------------------------------------------------------------------

const tmpDir = mkdtempSync(join(tmpdir(), 'kcbundle-test-'));

const cleanRef = 'src/clean.mjs';
const secretRef = 'src/secret.mjs';

// Fake AWS access key that matches the detection pattern
const FAKE_SECRET = 'AKIAIOSFODNN7EXAMPLE';

mkdirSync(join(tmpDir, dirname(cleanRef)), { recursive: true });
mkdirSync(join(tmpDir, dirname(secretRef)), { recursive: true });
writeFileSync(join(tmpDir, cleanRef), '// just a clean file\nexport const x = 1;\n', 'utf8');
writeFileSync(join(tmpDir, secretRef), `// oops\nconst key = "${FAKE_SECRET}";\n`, 'utf8');

// ---------------------------------------------------------------------------
// Build a small ctx: two nodes whose provenance.ref points at the temp files.
// Node A links to Node B (provides an edge to test).
// ---------------------------------------------------------------------------

const nodeA = {
  id: 'fs:src/clean.mjs',
  kind: 'file',
  title: 'Clean module',
  summary: 'Nothing suspicious here',
  category: 'code',
  links: ['fs:src/secret.mjs'],
  provenance: { store: 'fs', ref: cleanRef },
};

const nodeB = {
  id: 'fs:src/secret.mjs',
  kind: 'file',
  title: 'Secret module',
  summary: 'Contains a credential',
  category: 'code',
  links: [],
  provenance: { store: 'fs', ref: secretRef },
};

const byId = new Map([
  [nodeA.id, nodeA],
  [nodeB.id, nodeB],
]);
const ctx = { city: { nodes: [nodeA, nodeB] }, byId };

// ---------------------------------------------------------------------------
// (a) Manifest with both nodes (one containing a secret) is BLOCKED
// ---------------------------------------------------------------------------
{
  const manifest = kcBundle(ctx, [nodeA.id, nodeB.id], { root: tmpDir });
  const result = validateIntentManifest(manifest);

  ok('(a) both nodes: manifest passes validateIntentManifest', result.ok === true, JSON.stringify(result.errors));
  ok('(a) artifact_type is intent-manifest', manifest.artifact_type === 'intent-manifest');
  ok('(a) advisory is true', manifest.advisory === true);

  // paths[] invariants
  ok('(a) paths[] has 2 entries', Array.isArray(manifest.paths) && manifest.paths.length === 2);
  for (let i = 0; i < manifest.paths.length; i++) {
    const entry = manifest.paths[i];
    ok(`(a) paths[${i}].path is a string`, typeof entry.path === 'string');
    ok(`(a) paths[${i}].path is relative (no leading /)`, !entry.path.startsWith('/'));
    ok(`(a) paths[${i}].path has no ".." segment`,
       !entry.path.split(/[/\\]/).some(s => s === '..'));
    ok(`(a) paths[${i}].sha256 is a string`, typeof entry.sha256 === 'string');
  }

  // edges — nodeA links to nodeB, both in the bundle
  ok('(a) edges[] has at least one entry', Array.isArray(manifest.edges) && manifest.edges.length >= 1);
  const hasEdge = manifest.edges.some(e => e.from === nodeA.id && e.to === nodeB.id);
  ok('(a) edge from nodeA -> nodeB present', hasEdge);

  // secret scan — blocked
  ok('(a) secret_scan.status === "blocked"', manifest.secret_scan.status === 'blocked',
     JSON.stringify(manifest.secret_scan));
  ok('(a) secret_scan.count > 0', manifest.secret_scan.count > 0);

  // NEVER put file contents in the manifest
  const serialized = JSON.stringify(manifest);
  ok('(a) serialized manifest does not contain file contents (AKIA key)',
     !serialized.includes(FAKE_SECRET));
  ok('(a) serialized manifest does not contain clean file source',
     !serialized.includes('export const x = 1'));
}

// ---------------------------------------------------------------------------
// (b) Manifest with only the clean file is CLEAN
// ---------------------------------------------------------------------------
{
  const manifest = kcBundle(ctx, [nodeA.id], { root: tmpDir });
  const result = validateIntentManifest(manifest);

  ok('(b) clean-only: manifest passes validateIntentManifest', result.ok === true, JSON.stringify(result.errors));
  ok('(b) paths[] has 1 entry', manifest.paths.length === 1);
  ok('(b) paths[0].path === cleanRef', manifest.paths[0].path === cleanRef);
  ok('(b) paths[0].sha256 is a 64-char hex string', /^[0-9a-f]{64}$/.test(manifest.paths[0].sha256));

  // no cross-edges (secret node not in bundle)
  ok('(b) edges[] is empty (secret not bundled)', manifest.edges.length === 0);

  ok('(b) secret_scan.status === "clean"', manifest.secret_scan.status === 'clean',
     JSON.stringify(manifest.secret_scan));
  ok('(b) secret_scan.count === 0', manifest.secret_scan.count === 0);
}

// ---------------------------------------------------------------------------
// (c) Manifest with only the secret file is BLOCKED
// ---------------------------------------------------------------------------
{
  const manifest = kcBundle(ctx, [nodeB.id], { root: tmpDir });
  const result = validateIntentManifest(manifest);

  ok('(c) secret-only: manifest passes validateIntentManifest', result.ok === true, JSON.stringify(result.errors));
  ok('(c) secret_scan.status === "blocked"', manifest.secret_scan.status === 'blocked');
  ok('(c) serialized manifest does not contain the secret', !JSON.stringify(manifest).includes(FAKE_SECRET));
}

// ---------------------------------------------------------------------------
// (d) Skipping: missing id, absolute ref, ".." ref
// ---------------------------------------------------------------------------
{
  // Node with absolute ref
  const nodeAbs = {
    id: 'fs:abs',
    kind: 'file',
    title: 'Abs',
    category: 'code',
    links: [],
    provenance: { store: 'fs', ref: '/etc/passwd' },
  };
  // Node with ".." ref
  const nodeDotDot = {
    id: 'fs:dotdot',
    kind: 'file',
    title: 'DotDot',
    category: 'code',
    links: [],
    provenance: { store: 'fs', ref: '../outside.mjs' },
  };
  const ctxSkip = {
    city: { nodes: [nodeAbs, nodeDotDot] },
    byId: new Map([
      [nodeAbs.id, nodeAbs],
      [nodeDotDot.id, nodeDotDot],
    ]),
  };

  // Also pass a non-existent id
  const manifest = kcBundle(ctxSkip, ['no-such-id', nodeAbs.id, nodeDotDot.id], { root: tmpDir });
  const result = validateIntentManifest(manifest);

  ok('(d) all-skipped: manifest still passes validateIntentManifest', result.ok === true, JSON.stringify(result.errors));
  ok('(d) paths[] is empty (all ids skipped)', manifest.paths.length === 0);
  ok('(d) secret_scan.status === "clean" (nothing scanned)', manifest.secret_scan.status === 'clean');
}

// ---------------------------------------------------------------------------
// (e) No root provided — sha256 is "" (empty string, still valid)
// ---------------------------------------------------------------------------
{
  const manifest = kcBundle(ctx, [nodeA.id], { root: undefined });
  const result = validateIntentManifest(manifest);

  ok('(e) no root: manifest passes validateIntentManifest', result.ok === true, JSON.stringify(result.errors));
  ok('(e) no root: sha256 is ""', manifest.paths[0].sha256 === '');
  ok('(e) no root: secret_scan is clean (no text to read)', manifest.secret_scan.status === 'clean');
}

// ---------------------------------------------------------------------------
// (f) expiry is forwarded
// ---------------------------------------------------------------------------
{
  const expiryTs = '2026-12-31T23:59:59Z';
  const manifest = kcBundle(ctx, [nodeA.id], { root: tmpDir, expiry: expiryTs });

  ok('(f) expiry is stored in manifest', manifest.expiry === expiryTs);
  ok('(f) manifest with expiry passes validateIntentManifest',
     validateIntentManifest(manifest).ok === true);
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
