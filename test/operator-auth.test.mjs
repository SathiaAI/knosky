// Operator auth + registration / revoke gates (Rule 3 merge blockers)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadDomain, registerAgentWithLease } from '../core/domain-store.mjs';
import {
  bootstrapOperator,
  assertOperator,
  revokeOperator,
} from '../core/operator-auth.mjs';
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

test('elevated classes require quorum — confidential blocked without tokens', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const d = loadDomain(domainRoot);
    const bad = registerAgentWithLease(d, {
      agentId: 'evil',
      classes: ['confidential'],
    });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /operator|quorum/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('dual bootstrap: a on wire, b file-only; elevated needs both tokens', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op2-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const boot = bootstrapOperator(domainRoot);
    assert.equal(boot.ok, true);
    assert.equal(boot.mode, 'dual');
    assert.ok(boot.operatorToken);
    // operator-b must NOT be returned as operatorToken2 on the bootstrap object for stdout safety
    assert.equal(boot.operatorToken2, undefined);
    assert.ok(boot.tokenFileB);
    assert.ok(existsSync(boot.tokenFileB));
    const tokenB = readFileSync(boot.tokenFileB, 'utf8').trim();
    assert.ok(tokenB.startsWith('opk_'));
    assert.equal(assertOperator(domainRoot, boot.operatorToken).ok, true);
    assert.equal(assertOperator(domainRoot, tokenB).ok, true);

    const d = loadDomain(domainRoot);
    const noTok = registerAgentWithLease(d, {
      agentId: 'worker',
      classes: ['public'],
    });
    assert.equal(noTok.ok, false); // domain secured

    // one token insufficient for elevated
    const one = registerAgentWithLease(
      d,
      { agentId: 'worker', classes: ['public', 'restricted'] },
      { operatorToken: boot.operatorToken },
    );
    assert.equal(one.ok, false);

    const ok = registerAgentWithLease(
      d,
      { agentId: 'worker', classes: ['public', 'restricted'] },
      { operatorToken: boot.operatorToken, operatorToken2: tokenB },
    );
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.ok(ok.leaseId);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('operator cannot self-revoke; second operator can revoke first', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-op5-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const boot = bootstrapOperator(domainRoot);
    assert.equal(boot.ok, true);
    const tokenB = readFileSync(boot.tokenFileB, 'utf8').trim();
    const self = revokeOperator(domainRoot, {
      targetOperatorId: boot.operatorId,
      callerOperatorToken: boot.operatorToken,
    });
    assert.equal(self.ok, false);
    assert.equal(self.reason, 'cannot_self_revoke_operator');
    const cross = revokeOperator(domainRoot, {
      targetOperatorId: boot.operatorId,
      callerOperatorToken: tokenB,
    });
    assert.equal(cross.ok, true, JSON.stringify(cross));
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
