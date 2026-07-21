// Simple swarm benchmark harness (DEC-113 remaining — L3 foundation measure).
// Runs two agents: claim conflict + quota path; emits JSON summary. No network.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createSwarmCoordinator } from './swarm-coordinator.mjs';
import { registerAgentWithLease, loadDomain } from './domain-store.mjs';

/**
 * @param {object} [opts]
 * @param {string} [opts.domainRoot]
 * @returns {{ ok: boolean, metrics: object, events: object[] }}
 */
export function runSwarmBench(opts = {}) {
  const tmp = opts.domainRoot
    ? null
    : mkdtempSync(join(tmpdir(), 'ks-swarm-bench-'));
  const domainRoot = opts.domainRoot || join(tmp, '.knosky');
  const events = [];
  const t0 = Date.now();

  try {
    const domain = loadDomain(domainRoot);
    const a = registerAgentWithLease(domain, {
      agentId: 'bench-a',
      classes: ['public', 'internal'],
    });
    if (!a.ok) throw new Error('register A failed: ' + a.reason);
    const b = registerAgentWithLease(domain, {
      agentId: 'bench-b',
      classes: ['public', 'internal'],
    });
    if (!b.ok) throw new Error('register B failed: ' + b.reason);
    const coord = createSwarmCoordinator({
      domainRoot,
      domain: loadDomain(domainRoot),
      quotas: {
        maxClaimsPerAgent: 2,
        maxActionsPerWindow: 50,
        antiProbeDenyThreshold: 20,
      },
    });

    // A claims a file
    const c1 = coord.claim({
      agentId: a.agentId,
      leaseId: a.leaseId,
      resource: 'file:src/bench.js',
      kind: 'file',
    });
    events.push({ step: 'a_claim', ok: c1.ok, code: c1.decision_code || c1.reason });

    // B conflicts
    const c2 = coord.claim({
      agentId: b.agentId,
      leaseId: b.leaseId,
      resource: 'file:src/bench.js',
      kind: 'file',
    });
    events.push({
      step: 'b_conflict',
      ok: !c2.ok,
      code: c2.decision_code || c2.reason,
    });

    // Quota pressure on A
    coord.claim({
      agentId: a.agentId,
      leaseId: a.leaseId,
      resource: 'file:src/b2.js',
      kind: 'file',
    });
    const c3 = coord.claim({
      agentId: a.agentId,
      leaseId: a.leaseId,
      resource: 'file:src/b3.js',
      kind: 'file',
    });
    events.push({
      step: 'a_quota',
      ok: !c3.ok || c3.reason === 'quota_claims' || c3.decision_code === 'DENY',
      code: c3.decision_code || c3.reason,
    });

    const heat = coord.writeHeatmap();
    const ms = Date.now() - t0;
    const metrics = {
      duration_ms: ms,
      conflict_detected: events.find((e) => e.step === 'b_conflict')?.ok === true,
      quota_enforced: events.find((e) => e.step === 'a_quota')?.ok === true,
      heatmap_written: !!heat?.ok,
      agents: 2,
    };
    const ok = metrics.conflict_detected && metrics.quota_enforced && metrics.heatmap_written;
    return { ok, metrics, events, domainRoot, heatmapPath: heat?.path };
  } finally {
    if (tmp) {
      try {
        rmSync(tmp, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  }
}
