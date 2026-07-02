// KnoSky docs-wording regression test (SAT-445 / Decisions Log D-164).
// Locks the cleared TUF-evolution sentence and forbids the banned phrases.
// Run: node test/docs-wording.test.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// Docs that ship with the package and may carry public trust-model wording.
const PUBLIC_DOCS = [
  'README.md',
  'SECURITY.md',
  'PRIVACY.md',
  'LIMITATIONS.md',
  'CHANGELOG.md',
  'CREDITS.md',
];

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// ---------------------------------------------------------------------------
// (a) Decisions Log D-164 cleared sentence is present in SECURITY.md.
//     The sentence: "KnoSky's local trust model applies the core security
//     principles of TUF... adapted... to a fully local, no-egress agentic
//     environment, with attestation formats based on in-toto/DSSE."
//     We check the load-bearing substrings rather than exact text so minor
//     editorial rewraps do not break the test.
// ---------------------------------------------------------------------------
{
  const sec = read('SECURITY.md');
  ok(
    'SECURITY.md contains "local trust model applies the core security principles of TUF"',
    sec.includes('local trust model applies the core security principles of TUF'),
  );
  ok(
    'SECURITY.md contains "fully local, no-egress agentic environment"',
    sec.includes('fully local, no-egress agentic environment'),
  );
  ok(
    'SECURITY.md contains "attestation formats based on in-toto/DSSE"',
    sec.includes('attestation formats based on in-toto/DSSE'),
  );
}

// ---------------------------------------------------------------------------
// (b) Forbidden phrases never appear in any public doc (D-164 prohibition).
// ---------------------------------------------------------------------------
const FORBIDDEN = ['TUF-compatible', 'implements TUF'];

for (const docPath of PUBLIC_DOCS) {
  let text;
  try { text = read(docPath); } catch { continue; } // file may not exist yet — skip
  for (const phrase of FORBIDDEN) {
    ok(
      `"${phrase}" absent from ${docPath}`,
      !text.includes(phrase),
      text.includes(phrase) ? `found forbidden phrase in ${docPath}` : '',
    );
  }
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
