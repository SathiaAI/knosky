// KnoSky launch-content tests (SAT-471). Run: node test/launch-content.test.mjs
//
// Locks the minimum structure required for the standard launch-mechanic files:
//   wiki/comparison.md  — comparison page (KnoSky vs. alternatives)
//   wiki/show-hn.md     — Show HN post draft
//   README.md           — must link to the comparison page

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function read(rel) {
  try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch { return null; }
}

// ---------------------------------------------------------------------------
// 1. wiki/comparison.md — structure and required content
// ---------------------------------------------------------------------------
{
  const src = read('wiki/comparison.md');
  ok('(1) wiki/comparison.md exists', src !== null);

  if (src) {
    // Must have an H1 title
    ok('(1) comparison.md has an H1 title', /^#\s+\S/m.test(src));

    // Must name KnoSky and at least two alternatives
    ok('(1) comparison.md mentions KnoSky',      /KnoSky/.test(src));
    ok('(1) comparison.md mentions Cursor or Copilot',
       /Cursor|Copilot/i.test(src));
    ok('(1) comparison.md mentions Sourcegraph',  /Sourcegraph/i.test(src));

    // Must have a "when to choose" or similar section
    ok('(1) comparison.md has a "when to choose" or similar guidance',
       /when to choose|best for|use.case/i.test(src));

    // Must mention privacy or local-first (honest disclaimer)
    ok('(1) comparison.md mentions local-first or privacy',
       /local.first|privacy|never leaves/i.test(src));

    // Must link back to PRIVACY.md (as per project disclosure convention)
    ok('(1) comparison.md links to PRIVACY.md', /PRIVACY\.md/.test(src));

    // No absolute filesystem paths baked in
    ok('(1) comparison.md has no hardcoded absolute paths',
       !/(?<!\w)(\/home\/|\/Users\/|C:\\\\)/.test(src));

    // At least three H2 sections (table, when-to-choose, alternatives)
    const h2Count = (src.match(/^##\s+\S/gm) || []).length;
    ok('(1) comparison.md has at least three H2 sections', h2Count >= 3,
       `found ${h2Count}`);

    // Must not contain any of the banned phrases (inherits docs-wording gate)
    for (const phrase of ['enterprise-grade', 'SOC2', 'zero-trust', 'tamper-evident']) {
      ok(`(1) comparison.md does not contain banned phrase "${phrase}"`,
         !src.includes(phrase));
    }
  }
}

// ---------------------------------------------------------------------------
// 2. wiki/show-hn.md — structure and required content
// ---------------------------------------------------------------------------
{
  const src = read('wiki/show-hn.md');
  ok('(2) wiki/show-hn.md exists', src !== null);

  if (src) {
    // Must have an H1 title
    ok('(2) show-hn.md has an H1 title', /^#\s+\S/m.test(src));

    // Title section must begin with "Show HN:"
    ok('(2) show-hn.md title starts with "Show HN:"', /Show HN:/i.test(src));

    // Must mention the one-command quickstart
    ok('(2) show-hn.md mentions "npx knosky"', /npx knosky/.test(src));

    // Must name the MCP / AI-assistant grounding use-case
    ok('(2) show-hn.md mentions MCP or AI assistant grounding',
       /MCP|AI assistant|grounded/i.test(src));

    // Must state the local/no-upload privacy promise
    ok('(2) show-hn.md states nothing leaves the machine',
       /nothing ever leaves|local.first|no.upload|no account/i.test(src));

    // Must mention the license (FSL or MIT)
    ok('(2) show-hn.md mentions the license', /FSL|MIT/.test(src));

    // Must include a GitHub URL for the project
    ok('(2) show-hn.md includes the GitHub repo URL',
       /github\.com\/SathiaAI\/knosky/i.test(src));

    // Must include a Q&A or FAQ section (standard Show HN practice)
    ok('(2) show-hn.md includes a Q&A or anticipated questions section',
       /Q&A|Q:|anticipated|FAQ/i.test(src));

    // No absolute filesystem paths baked in
    ok('(2) show-hn.md has no hardcoded absolute paths',
       !/(?<!\w)(\/home\/|\/Users\/|C:\\\\)/.test(src));

    // Must not contain any banned phrases
    for (const phrase of ['enterprise-grade', 'SOC2', 'zero-trust', 'tamper-evident']) {
      ok(`(2) show-hn.md does not contain banned phrase "${phrase}"`,
         !src.includes(phrase));
    }
  }
}

// ---------------------------------------------------------------------------
// 3. README.md — must link to the comparison page
// ---------------------------------------------------------------------------
{
  const src = read('README.md');
  ok('(3) README.md exists', src !== null);

  if (src) {
    ok('(3) README.md links to wiki/comparison.md',
       /wiki\/comparison\.md/.test(src));
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
