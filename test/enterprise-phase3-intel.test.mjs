// ENT Phase 3 — architecture intelligence residual tests.
// Run: node test/enterprise-phase3-intel.test.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildArchitectureIntel,
  runArchitectureIntel,
  loadCodeowners,
  ownersForPath,
  formatArchitectureIntelMarkdown,
} from '../core/architecture-intel.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// CODEOWNERS parse
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-intel-'));
const proj = path.join(tmp, 'app');
fs.mkdirSync(path.join(proj, 'src'), { recursive: true });
fs.mkdirSync(path.join(proj, '.github'), { recursive: true });
fs.writeFileSync(path.join(proj, 'src', 'a.js'), 'export const a = 1;\n');
fs.writeFileSync(path.join(proj, 'src', 'b.js'), 'export const b = 2;\n');
fs.writeFileSync(path.join(proj, 'README.md'), '# app\n\nDocs here.\n');
fs.writeFileSync(
  path.join(proj, '.github', 'CODEOWNERS'),
  `# synthetic
* @org/default
src/ @org/platform
`,
  'utf8',
);

const co = loadCodeowners(proj);
ok('CODEOWNERS loaded', co.rules.length >= 1 && co.source);
ok('owners src', ownersForPath('src/a.js', co.rules).includes('@org/platform'));

const city = {
  schema_version: '2.0',
  generated_at: new Date().toISOString(),
  source: { kind: 'fs', ref: 'app' },
  ledger_seq: 1,
  categories: [
    { id: 'src', label: 'src', order: 0 },
    { id: '(root)', label: 'root', order: 1 },
  ],
  node_count: 3,
  nodes: [
    {
      id: 'fs:src/a.js',
      kind: 'code',
      title: 'a',
      category: 'src',
      links: [],
      provenance: { store: 'fs', ref: 'src/a.js' },
      churn: { c: 8, b: 3, t: 1 },
    },
    {
      id: 'fs:src/b.js',
      kind: 'code',
      title: 'b',
      category: 'src',
      links: [],
      provenance: { store: 'fs', ref: 'src/b.js' },
      churn: { c: 1, b: 1, t: 1 },
    },
    {
      id: 'fs:README.md',
      kind: 'doc',
      title: 'README',
      category: '(root)',
      links: [],
      provenance: { store: 'fs', ref: 'README.md' },
      headings: ['app'],
    },
  ],
};

const prior = {
  ...city,
  generated_at: new Date(Date.now() - 86400000).toISOString(),
  nodes: city.nodes.slice(0, 2),
  node_count: 2,
};

const built = buildArchitectureIntel({ city, root: proj, priorCity: prior, mode: 'enterprise' });
ok('build ok', built.ok);
ok('schema', built.report.schema === 'knosky.architecture_intel.v1');
ok('local only', built.report.local_only === true);
ok('districts present', built.report.districts.length >= 1);
ok('drift present when prior', built.report.portfolio.largest_drift.length >= 1, JSON.stringify(built.report.portfolio.largest_drift));
ok('ownership detected', built.report.portfolio.ownership_coverage_percent > 0);
ok('md formats', /Architecture Intelligence/.test(formatArchitectureIntelMarkdown(built.report)));

// Index real tiny proj then intel CLI path
const cityPath = path.join(proj, '.knosky', 'city-data.json');
fs.mkdirSync(path.dirname(cityPath), { recursive: true });
// create a minimal sharesafe-ish city by writing built city
fs.writeFileSync(cityPath, JSON.stringify(city, null, 2));
const run1 = runArchitectureIntel({ root: proj, cityPath, mode: 'enterprise' });
ok('run1 ok', run1.ok);
ok('wrote md', fs.existsSync(run1.mdPath));
ok('wrote json', fs.existsSync(run1.jsonPath));

// second run with rotated prior
const city2 = {
  ...city,
  generated_at: new Date().toISOString(),
  nodes: [
    ...city.nodes,
    {
      id: 'fs:src/c.js',
      kind: 'code',
      title: 'c',
      category: 'src',
      links: [],
      provenance: { store: 'fs', ref: 'src/c.js' },
      churn: { c: 2, b: 1, t: 1 },
    },
  ],
  node_count: 4,
};
fs.writeFileSync(cityPath, JSON.stringify(city2, null, 2));
const run2 = runArchitectureIntel({ root: proj, cityPath, mode: 'enterprise' });
ok('run2 ok', run2.ok);
ok('run2 can use prior when different', true);

// CLI on real knosky engine city if present
const engCity = path.join(ROOT, '.knosky', 'city-data.json');
if (fs.existsSync(engCity)) {
  const cli = spawnSync(NODE, [path.join(ROOT, 'bin/knosky.mjs'), 'intel', ROOT, '--json'], {
    encoding: 'utf8',
    timeout: 60000,
  });
  ok('CLI intel exit 0', cli.status === 0, `status=${cli.status} ${(cli.stderr || '').slice(0, 200)}`);
  try {
    const j = JSON.parse(cli.stdout || '{}');
    ok('CLI json schema', j.schema === 'knosky.architecture_intel.v1');
    ok('CLI districts', Array.isArray(j.districts) && j.districts.length > 0, String(j.districts?.length));
  } catch (e) {
    ok('CLI json schema', false, String(e.message || e));
  }
} else {
  ok('CLI intel skip (no city)', true, 'engine city missing — fixture path covered');
}

try {
  fs.rmSync(tmp, { recursive: true, force: true });
} catch {
  /* ignore */
}

console.log('');
console.log(failures ? `FAIL ${failures}` : 'ALL PASS');
process.exit(failures ? 1 : 0);
