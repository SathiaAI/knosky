// Operational-overlay ingest tests. Run: node test/overlays.test.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readOverlays } from '../core/overlays.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-ov-')); }

// 1) Istanbul coverage-summary.json with two files maps coverage % correctly
{
  const d = tmp();
  fs.mkdirSync(path.join(d, 'coverage'));
  const summary = {
    total: { lines: { pct: 80 }, statements: { pct: 80 }, functions: { pct: 80 }, branches: { pct: 80 } },
    'src/foo.js': { lines: { pct: 100 }, statements: { pct: 100 }, functions: { pct: 100 }, branches: { pct: 100 } },
    'src/bar.js': { lines: { pct: 42.5 }, statements: { pct: 42.5 }, functions: { pct: 50 }, branches: { pct: 33 } },
  };
  fs.writeFileSync(path.join(d, 'coverage', 'coverage-summary.json'), JSON.stringify(summary));

  const ov = readOverlays(d);

  ok('foo.js coverage is 100', ov['src/foo.js']?.coverage === 100, String(ov['src/foo.js']?.coverage));
  ok('bar.js coverage is 42.5', ov['src/bar.js']?.coverage === 42.5, String(ov['src/bar.js']?.coverage));
  ok('total row is excluded', !('total' in ov));
  ok('only two entries returned', Object.keys(ov).length === 2, String(Object.keys(ov).length));
}

// 2) Dir with no artifacts returns {}
{
  const d = tmp();
  const ov = readOverlays(d);
  ok('empty dir returns {}', Object.keys(ov).length === 0, JSON.stringify(ov));
}

// 3) coverage % is clamped to 0..100 (defensive: Istanbul can report >100 in edge cases)
{
  const d = tmp();
  fs.mkdirSync(path.join(d, 'coverage'));
  const summary = {
    'src/quirk.js': { lines: { pct: 120 }, statements: { pct: 120 }, functions: { pct: 120 }, branches: { pct: 120 } },
  };
  fs.writeFileSync(path.join(d, 'coverage', 'coverage-summary.json'), JSON.stringify(summary));

  const ov = readOverlays(d);
  ok('coverage clamped to 100 when Istanbul reports >100', ov['src/quirk.js']?.coverage === 100, String(ov['src/quirk.js']?.coverage));
}

// 4) Malformed JSON returns {} without throwing
{
  const d = tmp();
  fs.mkdirSync(path.join(d, 'coverage'));
  fs.writeFileSync(path.join(d, 'coverage', 'coverage-summary.json'), 'not json {{{');

  let threw = false;
  let ov = {};
  try { ov = readOverlays(d); } catch { threw = true; }
  ok('malformed JSON returns {} without throwing', !threw && Object.keys(ov).length === 0);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
