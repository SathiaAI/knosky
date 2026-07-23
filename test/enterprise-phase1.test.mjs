// Enterprise Phase 1 residual tests (FR-KS-ENT-101…112 core).
// Run: node test/enterprise-phase1.test.mjs
// Label: product residual tests — not full host suite certificate alone.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  resolveRunMode,
  isEnterpriseMode,
  applyEnterpriseProfile,
  writeEnterpriseConfigStub,
  capabilityMatrix,
} from '../core/enterprise-mode.mjs';
import {
  buildSecurityReport,
  writeSecurityReportFiles,
  formatSecurityReportMarkdown,
  scanCityArtifactSecrets,
} from '../core/security-report.mjs';
import { packAuditBundle, verifyAuditBundle } from '../core/audit-bundle.mjs';
import {
  assertInsideRoot,
  inspectMapToolSurface,
  checkCityFreshness,
  FORBIDDEN_MAP_OPS,
} from '../core/ro-guarantee.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// --- mode resolve ---
ok('resolveRunMode enterprise', resolveRunMode({ cliMode: 'enterprise' }) === 'enterprise');
ok('resolveRunMode regulated', resolveRunMode({ cliMode: 'regulated' }) === 'regulated');
ok('resolveRunMode casual default', resolveRunMode({}) === 'casual');
ok('isEnterpriseMode', isEnterpriseMode('enterprise') && isEnterpriseMode('regulated') && !isEnterpriseMode('casual'));

const prof = applyEnterpriseProfile('enterprise', { telemetry: true, fail_on_secret: false });
ok('enterprise non-negotiable telemetry false', prof.telemetry === false);
ok('enterprise non-negotiable fail_on_secret', prof.fail_on_secret === true);
ok('enterprise share_safe', prof.share_safe === true);

// --- capability matrix dual table ---
const matrix = capabilityMatrix();
ok('matrix has map RO tools', matrix.map_tools_read_only.allowed.includes('kc_search'));
ok('matrix has Mode B tools separate', matrix.mode_b_governed.tools.includes('kc_route'));
ok('matrix forbids write', matrix.forbidden_as_map_tools.some((x) => /Write/i.test(x)));
ok('matrix dual honesty non-empty', String(matrix.dual_table_honesty).length > 20);

// --- path traversal ---
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-ent-'));
ok('inside root ok', assertInsideRoot(tmpRoot, 'src/a.js').ok);
ok('traversal denied', !assertInsideRoot(tmpRoot, '../../etc/passwd').ok);
ok('FORBIDDEN_MAP_OPS listed', FORBIDDEN_MAP_OPS.includes('path_traversal'));

// --- MCP surface inspect ---
const mcpSrc = fs.readFileSync(path.join(ROOT, 'mcp', 'server.mjs'), 'utf8');
const surf = inspectMapToolSurface(mcpSrc);
ok('MCP map tools present', surf.ok, `missing=${surf.missingMap} bad=${surf.forbiddenRegistered}`);
ok('MCP has readOnlyHint', surf.hasReadOnlyHints);

// --- synthetic clean project: enterprise index + report + audit ---
const proj = path.join(tmpRoot, 'clean-proj');
fs.mkdirSync(path.join(proj, 'src'), { recursive: true });
fs.writeFileSync(path.join(proj, 'src', 'hello.js'), 'export const x = 1;\n', 'utf8');
fs.writeFileSync(path.join(proj, 'README.md'), '# Clean synthetic\n\nHello.\n', 'utf8');

const stub = writeEnterpriseConfigStub(proj, 'enterprise');
ok('config stub created', stub.created && fs.existsSync(stub.path));

const r = spawnSync(
  NODE,
  [path.join(ROOT, 'bin/knosky.mjs'), 'enterprise', proj, '--no-open', '--no-serve'],
  { encoding: 'utf8', timeout: 120000 },
);
ok('enterprise CLI exit 0', r.status === 0, `status=${r.status} err=${(r.stderr || '').slice(0, 300)}`);
const cityPath = path.join(proj, '.knosky', 'city-data.json');
ok('city written', fs.existsSync(cityPath));
const secPath = path.join(proj, '.knosky', 'security-report.json');
ok('security-report.json written', fs.existsSync(secPath));
const sumPath = path.join(proj, '.knosky', 'security-summary.md');
ok('security-summary.md written', fs.existsSync(sumPath));

let report = null;
try {
  report = JSON.parse(fs.readFileSync(secPath, 'utf8'));
} catch {
  report = null;
}
ok('report schema', report?.schema === 'knosky.security_report.v1');
ok('report enterprise profile', report?.enterprise_profile === true);
ok('report provenance coverage', (report?.provenance?.coverage_percent ?? 0) >= 99 || report?.provenance?.node_count === 0);
ok('report RO asserted', report?.mcp?.read_only_mode_asserted === true);
ok('md mentions local use', /local use/i.test(fs.readFileSync(sumPath, 'utf8')));

const scan = scanCityArtifactSecrets(cityPath);
ok('clean city no secrets', scan.ok, `total=${scan.total}`);

// audit pack + verify
const pack = packAuditBundle({ root: proj, mode: 'enterprise' });
ok('audit pack ok', pack.ok, pack.reason || pack.bundleDir);
const ver = verifyAuditBundle(pack.bundleDir);
ok('audit verify PASS', ver.ok, (ver.errors || []).join('; '));

// stale check on fresh city
const city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
const fresh = checkCityFreshness({ city, root: proj, maxAgeMs: 7 * 24 * 3600 * 1000 });
ok('fresh city not stale', fresh.ok && !fresh.stale, JSON.stringify(fresh.issues || []));

// secret fixture share-safe still fails closed via indexer (existing behavior)
const dirty = path.join(tmpRoot, 'dirty-proj');
fs.mkdirSync(dirty, { recursive: true });
fs.writeFileSync(
  path.join(dirty, 'leak.md'),
  '# leak\n\naws key AKIAIOSFODNN7EXAMPLE\n',
  'utf8',
);
const r2 = spawnSync(
  NODE,
  [path.join(ROOT, 'bin/knosky.mjs'), 'enterprise', dirty, '--no-open', '--no-serve'],
  { encoding: 'utf8', timeout: 120000 },
);
ok('secret fixture fail-closed non-zero', r2.status !== 0, `status=${r2.status}`);

// buildSecurityReport unit without full city
const mini = buildSecurityReport({
  root: proj,
  mode: 'enterprise',
  shareSafe: true,
  secretsPre: 0,
  city: { nodes: [{ id: '1', provenance: { ref: 'a' } }], node_count: 1, generated_at: new Date().toISOString() },
});
ok('format md non-empty', formatSecurityReportMarkdown(mini).includes('KnoSky'));
const wr = writeSecurityReportFiles(path.join(tmpRoot, 'rep'), mini);
ok('writeSecurityReportFiles', fs.existsSync(wr.jsonPath));

// cleanup best-effort
try {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
} catch {
  /* windows locks */
}

console.log('');
console.log(failures ? `FAIL ${failures}` : 'ALL PASS');
process.exit(failures ? 1 : 0);
