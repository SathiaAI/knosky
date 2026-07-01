// Operational-overlay metadata ingest (D-155): file-level ONLY.
// Reads existing local test/coverage artifacts under `root` — never executes tests.
// Returns a map { '<relpath>': { coverage?: number(0..100), test?: 'pass'|'fail' } }.
// Key: relpath is always forward-slash, relative to root, no leading './'.
import fs from 'node:fs';
import path from 'node:path';

// Parse Istanbul coverage-summary.json. Returns partial overlay map.
function readIstanbul(root) {
  const fp = path.join(root, 'coverage', 'coverage-summary.json');
  let raw;
  try { raw = fs.readFileSync(fp, 'utf8'); } catch { return {}; }
  let json;
  try { json = JSON.parse(raw); } catch { return {}; }
  const out = {};
  for (const [key, val] of Object.entries(json)) {
    if (key === 'total') continue;                  // skip the aggregate row
    if (!val || typeof val !== 'object') continue;
    const pct = val.lines?.pct;
    if (typeof pct !== 'number') continue;
    const rel = key.replace(/\\/g, '/').replace(/^\.\//, '');
    out[rel] = { coverage: Math.min(100, Math.max(0, pct)) };
  }
  return out;
}

// Merge source into dest (dest wins on conflict).
function merge(dest, src) {
  for (const [k, v] of Object.entries(src)) {
    dest[k] = dest[k] ? { ...v, ...dest[k] } : v;
  }
}

/**
 * Read all recognised local test/coverage artifacts under `root` and return
 * a file-level overlay map.  Never executes tests or modifies files.
 *
 * @param {string} root  Absolute or relative path to the project root.
 * @returns {{ [relpath: string]: { coverage?: number, test?: 'pass'|'fail' } }}
 */
export function readOverlays(root) {
  const out = {};
  merge(out, readIstanbul(root));
  return out;
}
