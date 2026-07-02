// KnoSky wiki/start-here.md content tests. Run: node test/wiki-start-here.test.mjs
//
// Validates that the first-adoption doc exists and covers the minimum required
// sections so it stays useful as the project evolves.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOC  = path.join(ROOT, 'wiki', 'start-here.md');

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
ok('(a) wiki/start-here.md exists', src !== null);
ok('(a) doc is non-empty', src !== null && src.length > 0);

// Only run structural checks if the file was readable.
if (src) {

  // -------------------------------------------------------------------------
  // (b) Has an H1 title
  // -------------------------------------------------------------------------
  const h1 = src.match(/^#\s+\S/m);
  ok('(b) doc has an H1 title', h1 !== null);

  // -------------------------------------------------------------------------
  // (c) Covers requirements section (Node version)
  // -------------------------------------------------------------------------
  ok('(c) doc mentions Node.js requirement', /Node\.js/i.test(src));
  ok('(c) doc specifies Node version 18', /\b18\b/.test(src));

  // -------------------------------------------------------------------------
  // (d) Covers the one-command quickstart
  // -------------------------------------------------------------------------
  ok('(d) doc shows "npx knosky" quickstart', /npx knosky/.test(src));

  // -------------------------------------------------------------------------
  // (e) Covers MCP connection with both Claude Code and JSON config examples
  // -------------------------------------------------------------------------
  ok('(e) doc mentions Claude Code MCP setup', /claude mcp add/.test(src));
  ok('(e) doc includes JSON MCP config snippet', /KC_CITY/.test(src));
  ok('(e) doc names at least one MCP tool (kc_search)', /kc_search/.test(src));

  // -------------------------------------------------------------------------
  // (f) Makes the advisory / privacy commitment visible
  // -------------------------------------------------------------------------
  ok('(f) doc mentions local-first / nothing leaves your machine',
     /nothing ever leaves your machine|local.first/i.test(src));
  ok('(f) doc links to PRIVACY.md', /PRIVACY\.md/.test(src));

  // -------------------------------------------------------------------------
  // (g) No absolute filesystem paths baked in (would break on other machines)
  // -------------------------------------------------------------------------
  const hasAbsolutePath = /(?<!\w)(\/home\/|\/Users\/|C:\\\\)/.test(src);
  ok('(g) doc contains no hardcoded absolute paths', !hasAbsolutePath, src.slice(0, 120));

  // -------------------------------------------------------------------------
  // (h) Code blocks use fenced markdown (```) — no indented-only blocks
  // -------------------------------------------------------------------------
  const fencedBlocks = (src.match(/^```/gm) || []).length;
  ok('(h) doc uses fenced code blocks', fencedBlocks >= 2,
     `found ${fencedBlocks} opening fences`);

  // -------------------------------------------------------------------------
  // (i) At least one H2 section beyond the H1
  // -------------------------------------------------------------------------
  const h2Count = (src.match(/^##\s+\S/gm) || []).length;
  ok('(i) doc has at least three H2 sections', h2Count >= 3,
     `found ${h2Count}`);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
