// L3 swarm coordinator floor tests (DEC-113 thin foundation)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createSwarmCoordinator,
  readSwarmHeatmap,
} from '../core/swarm-coordinator.mjs';
import { CODES } from '../core/decision-codes.mjs';
import { verifyAuditChain } from '../core/audit-writer.mjs';
import { resolveLeaseIdentity } from '../core/local-ipc-identity.mjs';

test('two agents can each hold active leases', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({ domainRoot });

    const a = swarm.issueLease({ agentId: 'agent-alpha' });
    const b = swarm.issueLease({ agentId: 'agent-beta' });

    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.ok(a.leaseId);
    assert.ok(b.leaseId);
    assert.notEqual(a.leaseId, b.leaseId);

    const ra = resolveLeaseIdentity(swarm.domain.leaseStore, a.leaseId, 'agent-alpha');
    const rb = resolveLeaseIdentity(swarm.domain.leaseStore, b.leaseId, 'agent-beta');
    assert.equal(ra.ok, true);
    assert.equal(rb.ok, true);
    assert.equal(ra.agentId, 'agent-alpha');
    assert.equal(rb.agentId, 'agent-beta');

    const leases = swarm.listLeases().filter((l) => l.status === 'active');
    assert.equal(leases.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('claim conflict deny when second agent claims same file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({ domainRoot });

    const a = swarm.issueLease({ agentId: 'agent-a' });
    const b = swarm.issueLease({ agentId: 'agent-b' });
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);

    const c1 = swarm.claim({
      agentId: 'agent-a',
      leaseId: a.leaseId,
      kind: 'file',
      resource: 'src/core/auth.js',
    });
    assert.equal(c1.ok, true);
    assert.equal(c1.code, CODES.ALLOW);
    assert.ok(c1.claimId);

    const c2 = swarm.claim({
      agentId: 'agent-b',
      leaseId: b.leaseId,
      kind: 'file',
      resource: 'src/core/auth.js',
    });
    assert.equal(c2.ok, false);
    assert.equal(c2.code, CODES.DENY);
    assert.equal(c2.reason, 'claim_conflict');
    assert.equal(c2.holder, 'agent-a');
    assert.ok(c2.wait_position >= 1);

    const chain = verifyAuditChain(domainRoot);
    assert.equal(chain.ok, true);
    assert.ok(chain.count >= 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('quota deny when maxClaimsPerAgent exceeded (backpressure)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({
      domainRoot,
      quotas: { maxClaimsPerAgent: 2, maxActionsPerWindow: 100 },
    });

    const a = swarm.issueLease({ agentId: 'quota-agent' });
    assert.equal(a.ok, true);

    const c1 = swarm.claim({ agentId: 'quota-agent', leaseId: a.leaseId, resource: 'f1.js' });
    const c2 = swarm.claim({ agentId: 'quota-agent', leaseId: a.leaseId, resource: 'f2.js' });
    const c3 = swarm.claim({ agentId: 'quota-agent', leaseId: a.leaseId, resource: 'f3.js' });

    assert.equal(c1.ok, true);
    assert.equal(c2.ok, true);
    assert.equal(c3.ok, false);
    assert.equal(c3.reason, 'quota_claims');
    assert.equal(c3.backpressure, true);
    assert.equal(c3.code, CODES.DENY);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('heatmap written to .knosky/swarm/heatmap.json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({ domainRoot });

    swarm.issueLease({ agentId: 'heat-a' });
    swarm.issueLease({ agentId: 'heat-b' });
    swarm.claim({ agentId: 'heat-a', kind: 'district', resource: 'public' });

    const wr = swarm.writeHeatmap();
    assert.equal(wr.ok, true);
    assert.ok(existsSync(wr.path));
    assert.ok(wr.path.endsWith(join('swarm', 'heatmap.json')) || wr.path.replace(/\\/g, '/').endsWith('swarm/heatmap.json'));

    const disk = JSON.parse(readFileSync(wr.path, 'utf8'));
    assert.equal(disk.v, 1);
    assert.equal(disk.layer, 'L3');
    assert.ok(disk.agents['heat-a']);
    assert.ok(disk.agents['heat-b']);
    assert.ok(disk.totals.active_leases >= 2);
    assert.ok(disk.totals.active_claims >= 1);

    const viaReader = readSwarmHeatmap(domainRoot);
    assert.equal(viaReader.ok, true);
    assert.equal(viaReader.heatmap.layer, 'L3');

    const st = swarm.status();
    assert.equal(st.ok, true);
    assert.ok(st.heatmap.totals);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('lease expire and revoke bind for Mode B identity helper', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({ domainRoot });
    const issued = swarm.issueLease({ agentId: 'ephem', ttlMs: 1 });
    assert.equal(issued.ok, true);

    // Force-expire path (holder)
    const exp = swarm.expireLease(issued.leaseId, { callerAgentId: 'ephem' });
    assert.equal(exp.ok, true);
    assert.equal(exp.status, 'expired');
    const bad = resolveLeaseIdentity(swarm.domain.leaseStore, issued.leaseId, 'ephem');
    assert.equal(bad.ok, false);
    assert.equal(bad.reason, 'lease_expired');

    const issued2 = swarm.issueLease({ agentId: 'ephem' });
    // Foreign revoke without operator must fail
    const foreign = swarm.revokeLease(issued2.leaseId, { reason: 'hostile', callerAgentId: 'other' });
    assert.equal(foreign.ok, false);
    assert.equal(foreign.reason, 'operator_or_holder_required');
    // Holder self-revoke OK
    const rev = swarm.revokeLease(issued2.leaseId, { reason: 'test', callerAgentId: 'ephem' });
    assert.equal(rev.ok, true);
    const bad2 = resolveLeaseIdentity(swarm.domain.leaseStore, issued2.leaseId, 'ephem');
    assert.equal(bad2.ok, false);
    assert.equal(bad2.reason, 'lease_revoked');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('anti-probe trips after rapid DENY flood', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-swarm-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const swarm = createSwarmCoordinator({
      domainRoot,
      quotas: {
        maxClaimsPerAgent: 1,
        antiProbeDenyThreshold: 5,
        antiProbeWindowMs: 60_000,
        maxActionsPerWindow: 200,
      },
    });
    const a = swarm.issueLease({ agentId: 'prober' });
    const holder = swarm.issueLease({ agentId: 'holder' });
    swarm.claim({ agentId: 'holder', leaseId: holder.leaseId, resource: 'contested.js' });

    let trips = 0;
    for (let i = 0; i < 8; i++) {
      const r = swarm.claim({
        agentId: 'prober',
        leaseId: a.leaseId,
        resource: 'contested.js',
        enqueue: false,
      });
      assert.equal(r.ok, false);
      if (r.probe) trips += 1;
    }
    assert.ok(trips >= 1, 'expected at least one anti-probe trip');
    const heat = swarm.buildHeatmap();
    assert.ok(heat.agents.prober.probe_trips >= 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
