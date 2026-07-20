// Operator auth + registration / revoke gates (Rule 3 merge blockers)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadDomain, registerAgentWithLease } from '../core/domain-store.mjs';
import { bootstrapOperator, assertOperator } from '../core/operator-auth.mjs';
import { createSwarmCoordinator, readSwarmHeatmap } from '../core/swarm-coordinator.mjs';

test('readSwarmHeatmap is exported and callable', () => {
  assert.equal(typeof readSwarmHeatmap, 'function');
  const dir = mkdtempSync(join(tmpdir(), 'ks-hm-'));
  try {
    const r = readSwarmHeatmap(join(dir, '.knosky'));
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'no_heatmap');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('elevated classes require operator; confidential blocked without token', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const d = loadDomain(domainRoot);
    const bad = registerAgentWithLease(d, {
      agentId: 'evil',
      classes: ['confidential'],
    });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /operator_required/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('after bootstrap operator, registration requires token; with token elevated OK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op2-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const boot = bootstrapOperator(domainRoot);
    assert.equal(boot.ok, true);
    assert.ok(boot.operatorToken);
    assert.equal(assertOperator(domainRoot, boot.operatorToken).ok, true);

    const d = loadDomain(domainRoot);
    const noTok = registerAgentWithLease(d, {
      agentId: 'worker',
      classes: ['public'],
    });
    assert.equal(noTok.ok, false); // domain secured

    const ok = registerAgentWithLease(
      d,
      { agentId: 'worker', classes: ['public', 'restricted'] },
      { operatorToken: boot.operatorToken },
    );
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.ok(ok.leaseId);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('foreign lease revoke denied without operator; holder self-revoke allowed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op3-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({ domainRoot });
    const issued = swarm.issueLease({ agentId: 'alice' });
    assert.equal(issued.ok, true);
    const foreign = swarm.revokeLease(issued.leaseId, { callerAgentId: 'bob' });
    assert.equal(foreign.ok, false);
    const self = swarm.revokeLease(issued.leaseId, { callerAgentId: 'alice' });
    assert.equal(self.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('open solo public/internal register still works before operators exist', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op4-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const d = loadDomain(domainRoot);
    const ok = registerAgentWithLease(d, {
      agentId: 'solo',
      classes: ['public', 'internal'],
    });
    assert.equal(ok.ok, true, JSON.stringify(ok));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
