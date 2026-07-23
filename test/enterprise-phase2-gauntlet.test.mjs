// Enterprise Phase 2 — adversarial gauntlet residual tests.
// Run: node test/enterprise-phase2-gauntlet.test.mjs

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { listScenarios, runGauntlet, materializeSyntheticHost, SCENARIO_CATALOG } from '../core/adversarial-gauntlet.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

const scenarios = listScenarios();
ok('catalog has >= 8 scenarios', scenarios.length >= 8, String(scenarios.length));
ok(
  'covers secret ignore path mcp injection stale symlink huge',
  ['secrets', 'ignore_rules', 'path_disclosure', 'mcp_boundary', 'prompt_injection', 'stale_citation', 'symlink_escape', 'hostile_scale'].every((c) =>
    scenarios.some((s) => s.class === c),
  ),
);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-adv-host-'));
const h = materializeSyntheticHost('001_secret_in_heading', tmp);
ok('materialize secret host', fs.existsSync(path.join(h, 'SYNTHETIC_NOT_CUSTOMER_DATA.txt')));
ok('synthetic label file', fs.readFileSync(path.join(h, 'SYNTHETIC_NOT_CUSTOMER_DATA.txt'), 'utf8').includes('NOT customer'));

// Full gauntlet (deterministic families; no LLM spend)
const outDir = path.join(os.tmpdir(), 'ks-adv-run-' + Date.now());
const rollup = await runGauntlet({ outDir, llm: false });
ok('rollup schema', rollup.schema === 'knosky.adversarial_gauntlet.v1');
ok('private flag', rollup.private === true && rollup.publishable === false);
ok('ran all catalog by default', rollup.total === SCENARIO_CATALOG.length, String(rollup.total));
ok('artifacts dir exists', fs.existsSync(path.join(outDir, 'gauntlet-rollup.md')));
ok('rollup json exists', fs.existsSync(path.join(outDir, 'gauntlet-rollup.json')));
ok('green on current controls', rollup.green === true, `failCount=${rollup.failCount}`);

if (!rollup.green) {
  for (const s of rollup.scenarios.filter((x) => x.overall !== 'PASS')) {
    console.log('  FAIL-DETAIL', s.id, s.overall);
  }
}

// CLI list + run sample
const list = spawnSync(NODE, [path.join(ROOT, 'bin/knosky.mjs'), 'adversarial', 'list'], {
  encoding: 'utf8',
  timeout: 30000,
});
ok('CLI adversarial list exit 0', list.status === 0);
ok('CLI list JSON scenarios', /001_secret_in_heading/.test(list.stdout || ''));

const runCli = spawnSync(
  NODE,
  [path.join(ROOT, 'bin/knosky.mjs'), 'adversarial', 'run', '--only', '004_mcp_path_traversal,003_absolute_path_share_safe'],
  { encoding: 'utf8', timeout: 180000 },
);
ok('CLI adversarial run subset exit 0', runCli.status === 0, `status=${runCli.status} ${(runCli.stderr || '').slice(0, 200)}`);
ok('CLI prints PRIVATE GREEN or rollup', /PRIVATE GREEN|Pass \//i.test(runCli.stdout || ''));

// cleanup
try {
  fs.rmSync(tmp, { recursive: true, force: true });
} catch {
  /* ignore */
}

console.log('');
console.log(failures ? `FAIL ${failures}` : 'ALL PASS');
process.exit(failures ? 1 : 0);
