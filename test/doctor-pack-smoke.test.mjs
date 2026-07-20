// Doctor scorecard + pack smoke residual tests
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import {
  buildDoctorScorecard,
  doctorScorecardLines,
  doctorExitCode,
  inspectSsot,
  inspectMcpMenu,
} from '../core/doctor-scorecard.mjs';
import { runPackSmoke } from '../tools/pack-smoke.mjs';
import { runSwarmBench } from '../core/swarm-bench.mjs';
import { registerAgentWithLease, loadDomain } from '../core/domain-store.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');

test('SSOT + MCP inspect from doctor helpers', () => {
  const s = inspectSsot(REPO);
  assert.equal(s.menuOk, true);
  assert.equal(s.codesOk, true);
  assert.equal(s.ladderOk, true);
  const m = inspectMcpMenu(REPO);
  assert.equal(m.present, true);
  assert.equal(m.missing.length, 0);
  assert.equal(m.hasModeB, true);
});

test('doctor scorecard warns or infos without leases; no silent Windows ensure', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-doc-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const card = buildDoctorScorecard({ domainRoot, repoRoot: REPO });
    assert.ok(card.rows.some((r) => r.id === 'MODEB-LEASES'));
    assert.ok(card.rows.some((r) => r.id === 'LADDER'));
    assert.ok(card.rows.some((r) => r.id === 'L3-MOD' || r.id === 'L3'));
    const lines = doctorScorecardLines({ domainRoot, repoRoot: REPO });
    assert.ok(lines.some((l) => /scorecard|Mode B|L3/i.test(l)));
    // fails only on hard structural issues; empty domain should not hard-fail Mode B wiring
    assert.equal(card.rows.find((r) => r.id === 'MCP')?.level, 'ok');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('doctor improves MODEB-LEASES after agent-register', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-doc2-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const d = loadDomain(domainRoot);
    const reg = registerAgentWithLease(d, { agentId: 'doc-agent', classes: ['public', 'internal'] });
    assert.equal(reg.ok, true, JSON.stringify(reg));
    const card = buildDoctorScorecard({ domainRoot, repoRoot: REPO });
    const leaseRow = card.rows.find((r) => r.id === 'MODEB-LEASES');
    assert.equal(leaseRow.level, 'ok');
    assert.equal(doctorExitCode(card) === 0 || doctorExitCode(card) === 2, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('pack smoke matrix green against SSOT packs', () => {
  const out = runPackSmoke(REPO);
  assert.equal(out.ok, true, JSON.stringify(out.failed, null, 2));
  assert.ok(out.pass >= 8);
});

test('swarm bench reports conflict + quota + heatmap', () => {
  const out = runSwarmBench();
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.metrics.conflict_detected, true);
  assert.equal(out.metrics.quota_enforced, true);
  assert.equal(out.metrics.heatmap_written, true);
});
