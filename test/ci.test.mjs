// KnoSky CI artifact generator tests. Run: node test/ci.test.mjs
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { knoskyCi } from '../core/ci.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Build a minimal synthetic city.json in a temp dir.
// ---------------------------------------------------------------------------

const tmpDir = mkdtempSync(join(tmpdir(), 'knosky-ci-test-'));

const cityData = {
  schema_version: '2.0',
  generated_at: new Date().toISOString(),
  source_rev: 'test-rev',
  categories: [
    { id: 'code', label: 'Code', color: '#4f8cff', order: 0 },
  ],
  node_count: 2,
  nodes: [
    {
      id: 'fs:core/a.js',
      kind: 'file',
      title: 'Module A',
      summary: 'The A module',
      category: 'code',
      links: ['fs:core/b.js'],
      churn: null,
      provenance: { store: 'fs', ref: 'core/a.js' },
    },
    {
      id: 'fs:core/b.js',
      kind: 'file',
      title: 'Module B',
      summary: 'The B module',
      category: 'code',
      links: [],
      churn: null,
      provenance: { store: 'fs', ref: 'core/b.js' },
    },
  ],
};

const cityPath = join(tmpDir, 'city.json');
writeFileSync(cityPath, JSON.stringify(cityData), 'utf8');

// ---------------------------------------------------------------------------
// (a) knoskyCi returns summaryMd + routeJson + safetyJson
// ---------------------------------------------------------------------------
{
  const result = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('(a) result has summaryMd', typeof result.summaryMd === 'string' && result.summaryMd.length > 0);
  ok('(a) result has routeJson', result.routeJson !== null && typeof result.routeJson === 'object');
  ok('(a) result has safetyJson', result.safetyJson !== null && typeof result.safetyJson === 'object');
}

// ---------------------------------------------------------------------------
// (b) routeJson.advisory === true and routeJson.artifact_type === 'pr-route'
// ---------------------------------------------------------------------------
{
  const { routeJson } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('(b) routeJson.advisory === true', routeJson.advisory === true);
  ok('(b) routeJson.artifact_type === "pr-route"', routeJson.artifact_type === 'pr-route');
  ok('(b) routeJson.knosky_protocol === "1.0"', routeJson.knosky_protocol === '1.0');
}

// ---------------------------------------------------------------------------
// (c) No route path in routeJson is absolute or contains ..
// ---------------------------------------------------------------------------
{
  const { routeJson } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  let allSafe = true;
  for (const { route: routeDoc } of (routeJson.routes || [])) {
    const entries = [
      ...(routeDoc && routeDoc.route ? routeDoc.route : []),
      ...(routeDoc && routeDoc.alternates ? routeDoc.alternates : []),
    ];
    for (const entry of entries) {
      const p = typeof entry === 'string' ? entry : (entry && entry.path);
      if (!p || typeof p !== 'string') continue;
      if (p.startsWith('/')) { allSafe = false; break; }
      if (/^[A-Za-z]:[\\\/]/.test(p)) { allSafe = false; break; }
      if (p.split(/[/\\]/).some(s => s === '..')) { allSafe = false; break; }
    }
    if (!allSafe) break;
  }
  ok('(c) no route path is absolute or contains ..', allSafe);
}

// ---------------------------------------------------------------------------
// (d) safetyJson.secrets_found is a number and safetyJson is present
// ---------------------------------------------------------------------------
{
  const { safetyJson } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('(d) safetyJson is an object', safetyJson !== null && typeof safetyJson === 'object');
  ok('(d) safetyJson.secrets_found is a number', typeof safetyJson.secrets_found === 'number');
  ok('(d) safetyJson.artifact_type === "safety-report"', safetyJson.artifact_type === 'safety-report');
  ok('(d) safetyJson.advisory === true', safetyJson.advisory === true);
}

// ---------------------------------------------------------------------------
// (e) With a clean change set, exitCode === 0
// ---------------------------------------------------------------------------
{
  const { exitCode } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('(e) clean change set exitCode === 0', exitCode === 0);
}

// ---------------------------------------------------------------------------
// (f) Even with failOnSecret: true (and no secret in artifacts), exitCode === 0
// ---------------------------------------------------------------------------
{
  const { exitCode } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'], failOnSecret: true });
  ok('(f) failOnSecret + clean artifacts => exitCode === 0', exitCode === 0);
}

// ---------------------------------------------------------------------------
// (g) summaryMd contains the word "advisory"
// ---------------------------------------------------------------------------
{
  const { summaryMd } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('(g) summaryMd contains "advisory"', summaryMd.toLowerCase().includes('advisory'));
}

// ---------------------------------------------------------------------------
// Additional: no index available produces advisory summary and exitCode === 0
// ---------------------------------------------------------------------------
{
  const result = await knoskyCi({ cityPath: join(tmpDir, 'does-not-exist.json'), changedFiles: ['core/a.js'] });
  ok('no-index: exitCode === 0', result.exitCode === 0);
  ok('no-index: summaryMd mentions "no index"', result.summaryMd.toLowerCase().includes('no index'));
}

// ---------------------------------------------------------------------------
// Additional: empty changedFiles list produces valid artifacts
// ---------------------------------------------------------------------------
{
  const result = await knoskyCi({ cityPath, changedFiles: [] });
  ok('empty changedFiles: exitCode === 0', result.exitCode === 0);
  ok('empty changedFiles: routeJson.routes is empty array', Array.isArray(result.routeJson.routes) && result.routeJson.routes.length === 0);
}

// ---------------------------------------------------------------------------
// Additional: unsafe paths in changedFiles are silently dropped (never emitted)
// ---------------------------------------------------------------------------
{
  const { routeJson } = await knoskyCi({ cityPath, changedFiles: ['/etc/passwd', '../outside.js', 'core/a.js'] });
  const files = (routeJson.routes || []).map(r => r.file);
  ok('unsafe paths dropped: /etc/passwd not in routes', !files.includes('/etc/passwd'));
  ok('unsafe paths dropped: ../outside.js not in routes', !files.includes('../outside.js'));
  ok('safe path still present: core/a.js in routes', files.includes('core/a.js'));
}

// ---------------------------------------------------------------------------
// Additional: safetyJson has absolute_paths === false and redaction field
// ---------------------------------------------------------------------------
{
  const { safetyJson } = await knoskyCi({ cityPath, changedFiles: ['core/a.js'] });
  ok('safetyJson.absolute_paths === false', safetyJson.absolute_paths === false);
  ok('safetyJson has redaction field', typeof safetyJson.redaction === 'string');
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
