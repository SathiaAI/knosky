// KnoSky adversarial-suite gate (SAT-465).
// Turns the implicit "for f in test/*.mjs" glob into a named, auditable
// pass/fail signal for the release workflow.  Each of the eight adversarial
// red-team suite files is invoked as a subprocess; if any exits non-zero the
// gate fails, blocking the release.
//
// Critical-tier per D-013/D-166.  Depends on SAT-437 (all eight suite files
// must exist and be runnable; their individual scenarios are exercised there).
//
// Run: node test/adversarial-suite.test.mjs

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Adversarial red-team suite files (SAT-437).
// These are the eight files cited as regression proof in RED-TEAM.md.
// ---------------------------------------------------------------------------
const SUITE = [
  'test/security-fixtures.mjs',
  'test/redteam-fixtures.mjs',
  'test/key-store-quorum-redteam.mjs',
  'test/trust-root-adversarial.test.mjs',
  'test/rendering-adversarial.test.mjs',
  'test/policy-fuzzer.mjs',
  'test/auth-oracle-fuzz.test.mjs',
  'test/regulated-sim-fixtures.mjs',
];

// ---------------------------------------------------------------------------
// (a) Every suite file exists on disk
// ---------------------------------------------------------------------------
for (const rel of SUITE) {
  ok(`(a) exists: ${rel}`, fs.existsSync(path.join(ROOT, rel)));
}

// ---------------------------------------------------------------------------
// (b) Every suite file runs and exits 0
// ---------------------------------------------------------------------------
for (const rel of SUITE) {
  const absPath = path.join(ROOT, rel);
  if (!fs.existsSync(absPath)) {
    // Already flagged in (a); skip subprocess to avoid a confusing error message.
    ok(`(b) passes: ${rel}`, false, '(file missing — run skipped)');
    continue;
  }
  const r = spawnSync(NODE, [absPath], { encoding: 'utf8', timeout: 60000 });
  const passed = r.status === 0 && r.signal === null;
  ok(`(b) passes: ${rel}`, passed,
    passed ? '' : `(exit ${r.status}, signal=${r.signal ?? 'none'}, stderr=${(r.stderr || '').slice(0, 200)})`);
}

// ---------------------------------------------------------------------------
// (c) Release workflow includes the test-runner step that picks up this gate.
// A regression pin — if the step is removed or renamed the gate would silently
// stop running, so we assert the pattern is still present.
// ---------------------------------------------------------------------------
{
  const releaseYml = path.join(ROOT, '.github/workflows/release.yml');
  const src = (() => {
    try { return fs.readFileSync(releaseYml, 'utf8'); } catch { return null; }
  })();
  ok('(c) release.yml exists', src !== null);
  ok('(c) release.yml test step iterates test/*.mjs',
    !!src && /for f in test\/\*\.mjs/.test(src));
  ok('(c) release.yml test step runs before publish',
    !!src && src.indexOf('for f in test/*.mjs') < src.indexOf('npm publish'));
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
