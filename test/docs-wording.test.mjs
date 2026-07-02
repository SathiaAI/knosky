// KnoSky docs-wording regression test (SAT-445 / SAT-473 / Decisions Log D-164).
// Locks the cleared TUF-evolution sentence verbatim and forbids the banned phrases.
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
// (a) Decisions Log D-164 cleared sentence is present in SECURITY.md,
//     verbatim and byte-for-byte. Any deviation is a hard failure.
// ---------------------------------------------------------------------------
const APPROVED_SENTENCE =
  "KnoSky's local trust model applies the core security principles of TUF" +
  " — role separation, threshold signing, survivable key compromise, and freshness-guaranteed revocation" +
  " — adapted from TUF's server-oriented update distribution to a fully local, no-egress agentic environment," +
  " with attestation formats based on in-toto/DSSE.";

{
  const sec = read('SECURITY.md');
  ok(
    'SECURITY.md contains the exact D-164 approved TUF-evolution sentence (verbatim)',
    sec.includes(APPROVED_SENTENCE),
    sec.includes(APPROVED_SENTENCE)
      ? ''
      : 'byte-for-byte match failed — sentence was reworded or is missing',
  );
}

// ---------------------------------------------------------------------------
// (b) Forbidden phrases never appear in any public doc (D-164 prohibition,
//     expanded in SAT-473 to include all phrases banned by the ticket).
// ---------------------------------------------------------------------------
const FORBIDDEN = [
  'TUF-compatible',
  'implements TUF',
  'tamper-evident',
  'zero-trust',
  'enterprise-grade',
  'SOC2',
];

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
