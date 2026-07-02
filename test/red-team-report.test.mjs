// KnoSky RED-TEAM.md structural gate (SAT-470).
// Validates that the public red-team report exists, stays well-formed, and
// continues to reference the key regression-proof test files as it evolves.
//
// Run: node test/red-team-report.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOC  = path.join(ROOT, 'RED-TEAM.md');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) File exists and is non-empty
// ---------------------------------------------------------------------------
const src = (() => {
  try { return fs.readFileSync(DOC, 'utf8'); } catch { return null; }
})();
ok('(a) RED-TEAM.md exists', src !== null);
ok('(a) doc is non-empty', src !== null && src.length > 0);

if (src) {

  // -------------------------------------------------------------------------
  // (b) Basic document structure
  // -------------------------------------------------------------------------
  ok('(b) doc has an H1 title', /^#\s+\S/m.test(src));
  ok('(b) doc has at least three H2 sections', (src.match(/^##\s+\S/gm) || []).length >= 3);
  ok('(b) doc uses fenced code blocks', (src.match(/^```/gm) || []).length >= 2);

  // -------------------------------------------------------------------------
  // (c) Fixed findings are enumerated (F-001 through at least F-004)
  // -------------------------------------------------------------------------
  ok('(c) doc lists finding F-001', /\bF-001\b/.test(src));
  ok('(c) doc lists finding F-002', /\bF-002\b/.test(src));
  ok('(c) doc lists finding F-003', /\bF-003\b/.test(src));
  ok('(c) doc lists finding F-004', /\bF-004\b/.test(src));

  // -------------------------------------------------------------------------
  // (d) Accepted limitations are named (by decision reference or RT- prefix)
  // -------------------------------------------------------------------------
  ok('(d) doc names accepted limitation D-163 or RT-KS-001', /D-163|RT-KS-001/.test(src));
  ok('(d) doc names accepted limitation D-167 or RT-KS-002', /D-167|RT-KS-002/.test(src));
  ok('(d) doc names accepted limitation D-168', /D-168/.test(src));

  // -------------------------------------------------------------------------
  // (e) Regression-proof test files are cited so readers can verify
  // -------------------------------------------------------------------------
  ok('(e) doc cites security-fixtures regression proof', /security-fixtures\.mjs/.test(src));
  ok('(e) doc cites redteam-fixtures regression proof', /redteam-fixtures\.mjs/.test(src));
  ok('(e) doc cites key-store-quorum-redteam regression proof', /key-store-quorum-redteam\.mjs/.test(src));
  ok('(e) doc cites trust-root-adversarial regression proof', /trust-root-adversarial\.test\.mjs/.test(src));

  // -------------------------------------------------------------------------
  // (f) Verification section contains a runnable code block
  // -------------------------------------------------------------------------
  ok('(f) doc includes a node invocation for at least one test file',
    /node test\//.test(src));

  // -------------------------------------------------------------------------
  // (g) Scope section is present (credibility requires honest out-of-scope notice)
  // -------------------------------------------------------------------------
  ok('(g) doc mentions what is in scope', /[Ii]n scope/.test(src));
  ok('(g) doc mentions what is out of scope', /[Oo]ut of scope/.test(src));

  // -------------------------------------------------------------------------
  // (h) No absolute filesystem paths baked in (would break on other machines)
  // -------------------------------------------------------------------------
  ok('(h) doc contains no hardcoded absolute paths',
    !/(?<!\w)(\/home\/|\/Users\/|C:\\\\)/.test(src));

  // -------------------------------------------------------------------------
  // (i) Does not contain claims the docs-wording test bans (D-164 forbidden phrases)
  // -------------------------------------------------------------------------
  const FORBIDDEN = [
    'TUF-compatible', 'implements TUF', 'tamper-evident',
    'zero-trust', 'enterprise-grade', 'SOC2',
  ];
  for (const phrase of FORBIDDEN) {
    ok(`(i) doc does not contain forbidden phrase "${phrase}"`, !src.includes(phrase));
  }

  // -------------------------------------------------------------------------
  // (j) "Fixed before publication" findings reference the version they shipped in
  // -------------------------------------------------------------------------
  ok('(j) doc anchors findings to a version (v0.5.0 or similar)',
    /v\d+\.\d+\.\d+/.test(src));

  // -------------------------------------------------------------------------
  // (k) The cited regression-proof test files actually exist on disk
  // -------------------------------------------------------------------------
  const CITED_TESTS = [
    'test/security-fixtures.mjs',
    'test/redteam-fixtures.mjs',
    'test/key-store-quorum-redteam.mjs',
    'test/trust-root-adversarial.test.mjs',
    'test/rendering-adversarial.test.mjs',
    'test/policy-fuzzer.mjs',
    'test/auth-oracle-fuzz.test.mjs',
    'test/regulated-sim-fixtures.mjs',
  ];
  for (const rel of CITED_TESTS) {
    ok(`(k) cited test file exists: ${rel}`,
      fs.existsSync(path.join(ROOT, rel)), `missing ${path.join(ROOT, rel)}`);
  }
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
