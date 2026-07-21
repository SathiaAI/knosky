// KnoSky L3 swarm coordinator floor (DEC-113) — thin local control plane.
// Built on Mode B domain leases (domain-store) + audit-writer multi-agent events.
// Pure ESM, Node stdlib. Windows-safe atomic writes (no mandatory fsync).

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  loadDomain,
  resolveDomainRoot,
  registerAgentWithLease,
} from './domain-store.mjs';
import { writeDecisionReceipt } from './audit-writer.mjs';
import { CODES } from './decision-codes.mjs';
import {
  assertOperator,
  assertOperatorQuorum,
  operatorCount,
  sanitizeClasses,
  ELEVATED,
} from './operator-auth.mjs';
import { resolveLeaseIdentity } from './local-ipc-identity.mjs';

/** Default climate knobs (simple counter model). */
export const DEFAULT_SWARM_QUOTAS = Object.freeze({
  maxClaimsPerAgent: 8,
  maxActiveLeasesPerAgent: 4,
  maxActionsPerWindow: 32,
  windowMs: 60_000,
  antiProbeDenyThreshold: 12,
  antiProbeWindowMs: 10_000,
  enableFifoWait: true,
});

/**
 * Soft atomic JSON write — no fsync (Windows EPERM-safe).
 * @param {string} path
 * @param {object} obj
 */
function atomicWriteSoft(path, obj) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

/**
 * @param {string} domainRoot
 */
export function swarmPaths(domainRoot) {
  const swarmDir = join(domainRoot, 'swarm');
  return {
    swarmDir,
    heatmapPath: join(swarmDir, 'heatmap.json'),
    claimsPath: join(swarmDir, 'claims.json'),
  };
}

function nowIso() {
  return new Date().toISOString();
}

function mintId(prefix) {
  return `${prefix}_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
}

function pruneWindow(tsArr, windowMs, now = Date.now()) {
  const cut = now - windowMs;
  return tsArr.filter((t) => t >= cut);
}

/**
 * Create a local L3 swarm coordinator bound to a trust domain.
 *
 * @param {object} [opts]
 * @param {string} [opts.domainRoot]
 * @param {string} [opts.cityPath]
 * @param {ReturnType<typeof loadDomain>} [opts.domain]
 * @param {Partial<typeof DEFAULT_SWARM_QUOTAS>} [opts.quotas]
 */
export function createSwarmCoordinator(opts = {}) {
  const domainRoot = resolveDomainRoot(opts.cityPath, opts.domainRoot);
  const domain = opts.domain || loadDomain(domainRoot);
  const paths = swarmPaths(domainRoot);
  mkdirSync(paths.swarmDir, { recursive: true });

  const quotas = { ...DEFAULT_SWARM_QUOTAS, ...(opts.quotas || {}) };

  /** @type {Map<string, { claimId: string, agentId: string, kind: string, resource: string, since: string }>} */
  const claims = new Map();
  /** FIFO waiters per resource key */
  /** @type {Map<string, string[]>} */
  const waiters = new Map();
  /** Per-agent counters / sliding windows */
  /** @type {Map<string, { actionTs: number[], denyTs: number[], probeTrips: number }>} */
  const agentStats = new Map();

  // Restore durable claims if present (best-effort).
  if (existsSync(paths.claimsPath)) {
    try {
      const doc = JSON.parse(readFileSync(paths.claimsPath, 'utf8'));
      for (const [key, rec] of Object.entries(doc.claims || {})) {
        if (rec && rec.agentId && rec.resource) claims.set(key, rec);
      }
    } catch {
      /* ignore corrupt; rebuild in memory */
    }
  }

  function statsFor(agentId) {
    if (!agentStats.has(agentId)) {
      agentStats.set(agentId, { actionTs: [], denyTs: [], probeTrips: 0 });
    }
    return agentStats.get(agentId);
  }

  function claimCount(agentId) {
    let n = 0;
    for (const c of claims.values()) if (c.agentId === agentId) n += 1;
    return n;
  }

  function activeLeaseCount(agentId) {
    let n = 0;
    for (const rec of domain.leaseStore.values()) {
      if (rec.agentId === agentId && rec.status === 'active') {
        if (rec.expires_at && Date.parse(rec.expires_at) <= Date.now()) continue;
        n += 1;
      }
    }
    return n;
  }

  function persistClaims() {
    const out = {};
    for (const [k, v] of claims.entries()) out[k] = v;
    atomicWriteSoft(paths.claimsPath, { v: 1, claims: out, updated_at: nowIso() });
  }

  function emit(decision_code, agentId, tool, meta = {}) {
    return writeDecisionReceipt({
      domainRoot,
      decision_code,
      agent_id: agentId,
      tool,
      mode: 'B',
      destination: null,
      meta: {
        swarm: true,
        layer: 'L3',
        ...meta,
      },
    });
  }

  function noteAction(agentId) {
    const s = statsFor(agentId);
    const t = Date.now();
    s.actionTs = pruneWindow(s.actionTs.concat(t), quotas.windowMs, t);
  }

  function noteDeny(agentId, reason) {
    const s = statsFor(agentId);
    const t = Date.now();
    s.denyTs = pruneWindow(s.denyTs.concat(t), quotas.antiProbeWindowMs, t);
    s.actionTs = pruneWindow(s.actionTs.concat(t), quotas.windowMs, t);
    let probe = false;
    if (s.denyTs.length >= quotas.antiProbeDenyThreshold) {
      s.probeTrips += 1;
      probe = true;
      // Clear window so each trip is distinct
      s.denyTs = [];
    }
    return { probe, reason };
  }

  function backpressureHit(agentId) {
    const s = statsFor(agentId);
    const t = Date.now();
    s.actionTs = pruneWindow(s.actionTs, quotas.windowMs, t);
    return s.actionTs.length >= quotas.maxActionsPerWindow;
  }

  function resourceKey(kind, resource) {
    return `${kind}:${resource}`;
  }

  /**
   * Ensure agent is registered in the domain store (idempotent on same id).
   * Elevated classes require TWO distinct operator tokens (same Rule 3 as domain-store).
   * @param {{ agentId: string, role?: string, classes?: string[], operatorToken?: string, operatorToken2?: string }} agent
   */
  function registerAgent(agent) {
    const agentId = agent.agentId;
    if (!agentId || typeof agentId !== 'string') {
      return { ok: false, code: CODES.ERROR_INVALID_INPUT, reason: 'agentId_required' };
    }

    if (!domain.agents[agentId]) {
      const issued = registerAgentWithLease(
        domain,
        {
          agentId,
          role: agent.role || 'coder',
          classes: Array.isArray(agent.classes) ? agent.classes : ['public', 'internal'],
        },
        {
          operatorToken: agent.operatorToken || process.env.KC_OPERATOR_TOKEN,
          operatorToken2: agent.operatorToken2 || process.env.KC_OPERATOR_TOKEN_2,
        },
      );
      if (!issued.ok) {
        return {
          ok: false,
          code: CODES.DENY_IDENTITY,
          reason: issued.reason,
          next_action: issued.next_action,
        };
      }
      // Reload after registerAgentWithLease mutated disk
      const fresh = loadDomain(domainRoot);
      domain.agents = fresh.agents;
      domain.policy = fresh.policy;
      domain.leaseStore = fresh.leaseStore;
    }
    emit(CODES.ALLOW, agentId, 'swarm_register', { event: 'agent_register' });
    noteAction(agentId);
    return { ok: true, code: CODES.ALLOW, agentId, agent: domain.agents[agentId] };
  }

  /**
   * Issue a fresh active lease for an agent (wraps domain-store).
   * Registers agent if missing (subject to operator gates / quorum).
   * @param {{ agentId: string, role?: string, classes?: string[], ttlMs?: number|null, operatorToken?: string, operatorToken2?: string }} opts
   */
  function issueLease(optsIn = {}) {
    const agentId = optsIn.agentId;
    if (!agentId || typeof agentId !== 'string') {
      return { ok: false, code: CODES.ERROR_INVALID_INPUT, reason: 'agentId_required' };
    }

    if (backpressureHit(agentId)) {
      const d = noteDeny(agentId, 'backpressure');
      const rc = emit(CODES.DENY, agentId, 'swarm_lease_issue', {
        event: 'lease_issue_denied',
        reason: 'backpressure',
        probe: d.probe,
      });
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'backpressure',
        backpressure: true,
        probe: d.probe,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }

    if (activeLeaseCount(agentId) >= quotas.maxActiveLeasesPerAgent) {
      const d = noteDeny(agentId, 'quota_leases');
      const rc = emit(CODES.DENY, agentId, 'swarm_lease_issue', {
        event: 'lease_issue_denied',
        reason: 'quota_leases',
        probe: d.probe,
      });
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'quota_leases',
        backpressure: true,
        probe: d.probe,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }

    // Always mint via domain-store for mode-B compatible records.
    // registerAgentWithLease overwrites agent classes — preserve existing if present.
    const existing = domain.agents[agentId];
    const classes = optsIn.classes || existing?.classes || ['public', 'internal'];
    const role = optsIn.role || existing?.role || 'coder';
    const operatorToken = optsIn.operatorToken || process.env.KC_OPERATOR_TOKEN;
    const operatorToken2 = optsIn.operatorToken2 || process.env.KC_OPERATOR_TOKEN_2;

    // If agent already registered, mint lease without clobbering registry fields hard:
    let leaseId;
    if (existing) {
      leaseId = mintId('lease');
      const ttlMs = optsIn.ttlMs == null ? null : Number(optsIn.ttlMs);
      const rec = {
        leaseId,
        agentId,
        status: 'active',
        created_at: nowIso(),
        expires_at:
          ttlMs && Number.isFinite(ttlMs) && ttlMs > 0
            ? new Date(Date.now() + ttlMs).toISOString()
            : null,
      };
      domain.leaseStore.set(leaseId, rec);
      domain.saveLeases();
    } else {
      const issued = registerAgentWithLease(
        domain,
        { agentId, classes, role },
        { operatorToken, operatorToken2 },
      );
      if (!issued.ok) {
        return {
          ok: false,
          code: CODES.DENY_IDENTITY,
          reason: issued.reason,
          next_action: issued.next_action,
        };
      }
      leaseId = issued.leaseId;
      if (optsIn.ttlMs && Number.isFinite(optsIn.ttlMs) && optsIn.ttlMs > 0) {
        const rec = domain.leaseStore.get(leaseId);
        if (rec) {
          rec.expires_at = new Date(Date.now() + optsIn.ttlMs).toISOString();
          domain.leaseStore.set(leaseId, rec);
          domain.saveLeases();
        }
      }
    }

    noteAction(agentId);
    const rc = emit(CODES.ALLOW, agentId, 'swarm_lease_issue', {
      event: 'lease_issued',
      lease_id: leaseId,
    });
    writeHeatmap();
    return {
      ok: true,
      code: CODES.ALLOW,
      agentId,
      leaseId,
      receipt_id: rc.ok ? rc.receipt_id : undefined,
    };
  }

  /**
   * Expire a lease (TTL / sweep). Self-service expiration for system clock only
   * via expireDueLeases; manual expire requires operator OR the holder agentId.
   * @param {string} leaseId
   * @param {{ operatorToken?: string, callerAgentId?: string, system?: boolean }} [auth]
   */
  function expireLease(leaseId, auth = {}) {
    const lease = domain.leaseStore.get(leaseId);
    if (!lease) {
      return { ok: false, code: CODES.DENY_IDENTITY, reason: 'unknown_lease_id' };
    }
    if (lease.status !== 'active') {
      return { ok: true, code: CODES.ALLOW, leaseId, status: lease.status, noop: true };
    }
    if (!auth.system) {
      const gate = authorizeLeaseAdmin(lease, auth);
      if (!gate.ok) return gate;
    }
    lease.status = 'expired';
    lease.expired_at = nowIso();
    domain.leaseStore.set(leaseId, lease);
    domain.saveLeases();
    const rc = emit(CODES.ALLOW, lease.agentId, 'swarm_lease_expire', {
      event: 'lease_expired',
      lease_id: leaseId,
    });
    writeHeatmap();
    return {
      ok: true,
      code: CODES.ALLOW,
      leaseId,
      agentId: lease.agentId,
      status: 'expired',
      receipt_id: rc.ok ? rc.receipt_id : undefined,
    };
  }

  /**
   * Revoke a lease (security / operator OR holder self-revoke).
   * Foreign revocation requires operatorToken — never unilateral third-party.
   * @param {string} leaseId
   * @param {{ reason?: string, operatorToken?: string, callerAgentId?: string }} [meta]
   */
  function revokeLease(leaseId, meta = {}) {
    const lease = domain.leaseStore.get(leaseId);
    if (!lease) {
      return { ok: false, code: CODES.DENY_IDENTITY, reason: 'unknown_lease_id' };
    }
    const gate = authorizeLeaseAdmin(lease, meta);
    if (!gate.ok) return gate;

    lease.status = 'revoked';
    lease.revoked_at = nowIso();
    lease.revoke_reason = meta.reason || (gate.mode === 'holder' ? 'self_revoke' : 'operator');
    lease.revoked_by = gate.mode === 'operator' ? gate.operatorId : lease.agentId;
    domain.leaseStore.set(leaseId, lease);
    domain.saveLeases();
    const rc = emit(CODES.ALLOW, lease.agentId, 'swarm_lease_revoke', {
      event: 'lease_revoked',
      lease_id: leaseId,
      reason: lease.revoke_reason,
      by: lease.revoked_by,
    });
    writeHeatmap();
    return {
      ok: true,
      code: CODES.ALLOW,
      leaseId,
      agentId: lease.agentId,
      status: 'revoked',
      receipt_id: rc.ok ? rc.receipt_id : undefined,
    };
  }

  /** @param {any} lease @param {{ operatorToken?: string, callerAgentId?: string }} auth */
  function authorizeLeaseAdmin(lease, auth = {}) {
    const token = auth.operatorToken || process.env.KC_OPERATOR_TOKEN;
    const op = assertOperator(domainRoot, token);
    if (op.ok) {
      return { ok: true, mode: 'operator', operatorId: op.operatorId };
    }
    // Holder may expire/revoke own lease (self only).
    if (auth.callerAgentId && auth.callerAgentId === lease.agentId) {
      return { ok: true, mode: 'holder' };
    }
    return {
      ok: false,
      code: CODES.DENY_IDENTITY,
      reason: 'operator_or_holder_required',
      next_action: 'Provide operatorToken or callerAgentId matching the lease holder',
    };
  }

  /**
   * Sweep leases past expires_at → expired (system; no operator needed).
   */
  function expireDueLeases() {
    const out = [];
    const t = Date.now();
    for (const [id, rec] of domain.leaseStore.entries()) {
      if (rec.status !== 'active') continue;
      if (rec.expires_at && Date.parse(rec.expires_at) <= t) {
        const r = expireLease(id, { system: true });
        out.push(r);
      }
    }
    return out;
  }

  /**
     * File or district claim with conflict deny + optional FIFO wait.
     * leaseId is REQUIRED (Mode B / L3 lease-bound identity).
     * @param {{ agentId: string, leaseId: string, kind?: 'file'|'district', resource: string, enqueue?: boolean }} req
     */
    function claim(req = {}) {
      const agentId = req.agentId;
      const kind = req.kind === 'district' ? 'district' : 'file';
      const resource = typeof req.resource === 'string' ? req.resource.trim() : '';
      if (!agentId || !resource) {
        return { ok: false, code: CODES.ERROR_INVALID_INPUT, reason: 'agentId_and_resource_required' };
      }
      if (!req.leaseId || typeof req.leaseId !== 'string') {
        return {
          ok: false,
          code: CODES.DENY_IDENTITY,
          reason: 'lease_required',
          next_action: 'Pass leaseId from knosky agent-register / issueLease',
        };
      }

      expireDueLeases();

      // Required lease bind check (anti-spoof)
      {
        const lease = domain.leaseStore.get(req.leaseId);
        if (!lease || lease.status !== 'active' || lease.agentId !== agentId) {
          const d = noteDeny(agentId, 'bad_lease');
          const rc = emit(CODES.DENY_IDENTITY, agentId, 'swarm_claim', {
            event: 'claim_denied',
            reason: 'bad_lease',
            kind,
            resource: resource.slice(0, 200),
            probe: d.probe,
          });
          writeHeatmap();
          return {
            ok: false,
            code: CODES.DENY_IDENTITY,
            reason: 'bad_lease',
            probe: d.probe,
            receipt_id: rc.ok ? rc.receipt_id : undefined,
          };
        }
        if (lease.expires_at && Date.parse(lease.expires_at) <= Date.now()) {
          expireLease(req.leaseId, { system: true });
          const d = noteDeny(agentId, 'lease_expired');
          const rc = emit(CODES.DENY_IDENTITY, agentId, 'swarm_claim', {
            event: 'claim_denied',
            reason: 'lease_expired',
            kind,
            resource: resource.slice(0, 200),
            probe: d.probe,
          });
          writeHeatmap();
          return {
            ok: false,
            code: CODES.DENY_IDENTITY,
            reason: 'lease_expired',
            probe: d.probe,
            receipt_id: rc.ok ? rc.receipt_id : undefined,
          };
        }
      }

    if (backpressureHit(agentId)) {
      const d = noteDeny(agentId, 'backpressure');
      const rc = emit(CODES.DENY, agentId, 'swarm_claim', {
        event: 'claim_denied',
        reason: 'backpressure',
        kind,
        resource: resource.slice(0, 200),
        probe: d.probe,
      });
      writeHeatmap();
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'backpressure',
        backpressure: true,
        probe: d.probe,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }

    if (claimCount(agentId) >= quotas.maxClaimsPerAgent) {
      const d = noteDeny(agentId, 'quota_claims');
      const rc = emit(CODES.DENY, agentId, 'swarm_claim', {
        event: 'claim_denied',
        reason: 'quota_claims',
        kind,
        resource: resource.slice(0, 200),
        probe: d.probe,
      });
      writeHeatmap();
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'quota_claims',
        backpressure: true,
        probe: d.probe,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }

    const key = resourceKey(kind, resource);
    const held = claims.get(key);
    if (held && held.agentId !== agentId) {
      const d = noteDeny(agentId, 'claim_conflict');
      const enqueue = req.enqueue !== false && quotas.enableFifoWait;
      if (enqueue) {
        const q = waiters.get(key) || [];
        if (!q.includes(agentId)) q.push(agentId);
        waiters.set(key, q);
      }
      const rc = emit(CODES.DENY, agentId, 'swarm_claim', {
        event: 'claim_conflict',
        reason: 'claim_conflict',
        kind,
        resource: resource.slice(0, 200),
        holder: held.agentId,
        wait_position: enqueue ? (waiters.get(key) || []).indexOf(agentId) + 1 : null,
        probe: d.probe,
      });
      writeHeatmap();
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'claim_conflict',
        holder: held.agentId,
        wait_position: enqueue ? (waiters.get(key) || []).indexOf(agentId) + 1 : null,
        probe: d.probe,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }

    if (held && held.agentId === agentId) {
      noteAction(agentId);
      return { ok: true, code: CODES.ALLOW, claimId: held.claimId, agentId, kind, resource, refreshed: true };
    }

    const claimId = mintId('claim');
        const rec = {
          claimId,
          agentId,
          kind,
          resource,
          since: nowIso(),
        };
        // Audit first — fail closed before mutating claims map
        const rc = emit(CODES.ALLOW, agentId, 'swarm_claim', {
          event: 'claim_granted',
          claim_id: claimId,
          kind,
          resource: resource.slice(0, 200),
        });
        if (!rc.ok) {
          return {
            ok: false,
            code: CODES.DENY_AUDIT,
            reason: 'audit_write_failed',
            next_action: rc.reason || 'audit ledger unavailable',
          };
        }
        claims.set(key, rec);
        persistClaims();
        noteAction(agentId);
        writeHeatmap();
        return {
          ok: true,
          code: CODES.ALLOW,
          claimId,
          agentId,
          kind,
          resource,
          receipt_id: rc.receipt_id,
        };
      }

  /**
   * Release a file/district claim; promote FIFO waiter if any.
   * @param {{ agentId: string, kind?: 'file'|'district', resource: string }} req
   */
  function releaseClaim(req = {}) {
    const agentId = req.agentId;
    const kind = req.kind === 'district' ? 'district' : 'file';
    const resource = typeof req.resource === 'string' ? req.resource.trim() : '';
    if (!agentId || !resource) {
      return { ok: false, code: CODES.ERROR_INVALID_INPUT, reason: 'agentId_and_resource_required' };
    }
    const key = resourceKey(kind, resource);
    const held = claims.get(key);
    if (!held) {
      return { ok: true, code: CODES.ALLOW, noop: true, agentId, resource };
    }
    if (held.agentId !== agentId) {
      const d = noteDeny(agentId, 'not_holder');
      const rc = emit(CODES.DENY, agentId, 'swarm_release', {
        event: 'release_denied',
        reason: 'not_holder',
        holder: held.agentId,
        kind,
        resource: resource.slice(0, 200),
        probe: d.probe,
      });
      return {
        ok: false,
        code: CODES.DENY,
        reason: 'not_holder',
        holder: held.agentId,
        receipt_id: rc.ok ? rc.receipt_id : undefined,
      };
    }
    claims.delete(key);
    persistClaims();
    noteAction(agentId);
    const rc = emit(CODES.ALLOW, agentId, 'swarm_release', {
      event: 'claim_released',
      claim_id: held.claimId,
      kind,
      resource: resource.slice(0, 200),
    });

    // Fairness: promote next FIFO waiter if any (do not auto-grant if they now exceed quota —
    // leave them first in queue and let them call claim()).
    const q = waiters.get(key) || [];
    const next = q.shift();
    if (q.length) waiters.set(key, q);
    else waiters.delete(key);

    writeHeatmap();
    return {
      ok: true,
      code: CODES.ALLOW,
      released: held.claimId,
      next_waiter: next || null,
      receipt_id: rc.ok ? rc.receipt_id : undefined,
    };
  }

  /**
   * Build operator heatmap snapshot (in-memory).
   */
  function buildHeatmap() {
    expireDueLeases();
    const agents = {};
    for (const [agentId, rec] of Object.entries(domain.agents || {})) {
      const s = statsFor(agentId);
      const t = Date.now();
      s.actionTs = pruneWindow(s.actionTs, quotas.windowMs, t);
      s.denyTs = pruneWindow(s.denyTs, quotas.antiProbeWindowMs, t);
      agents[agentId] = {
        role: rec.role || null,
        active_leases: activeLeaseCount(agentId),
        active_claims: claimCount(agentId),
        actions_in_window: s.actionTs.length,
        denies_in_probe_window: s.denyTs.length,
        probe_trips: s.probeTrips,
        backpressure:
          s.actionTs.length >= quotas.maxActionsPerWindow ||
          claimCount(agentId) >= quotas.maxClaimsPerAgent,
      };
    }

    const claimList = [];
    const byDistrict = {};
    const byFilePrefix = {};
    for (const c of claims.values()) {
      claimList.push({
        claim_id: c.claimId,
        agent_id: c.agentId,
        kind: c.kind,
        resource: c.resource,
        since: c.since,
      });
      if (c.kind === 'district') {
        byDistrict[c.resource] = (byDistrict[c.resource] || 0) + 1;
      } else {
        const prefix = c.resource.split(/[\\/]/).slice(0, 2).join('/') || c.resource;
        byFilePrefix[prefix] = (byFilePrefix[prefix] || 0) + 1;
      }
    }

    let activeLeases = 0;
    let expiredLeases = 0;
    let revokedLeases = 0;
    for (const rec of domain.leaseStore.values()) {
      if (rec.status === 'active') activeLeases += 1;
      else if (rec.status === 'expired') expiredLeases += 1;
      else if (rec.status === 'revoked') revokedLeases += 1;
    }

    const waiting = {};
    for (const [k, q] of waiters.entries()) waiting[k] = [...q];

    return {
      v: 1,
      layer: 'L3',
      ts: nowIso(),
      domain_root: domainRoot,
      quotas: { ...quotas },
      totals: {
        agents: Object.keys(agents).length,
        active_leases: activeLeases,
        expired_leases: expiredLeases,
        revoked_leases: revokedLeases,
        active_claims: claimList.length,
        wait_queues: Object.keys(waiting).length,
      },
      agents,
      claims: claimList,
      heat: {
        districts: byDistrict,
        file_prefixes: byFilePrefix,
      },
      waiters: waiting,
    };
  }

  /**
   * Write heatmap snapshot to `.knosky/swarm/heatmap.json`.
   */
  function writeHeatmap() {
    const snap = buildHeatmap();
    atomicWriteSoft(paths.heatmapPath, snap);
    return { ok: true, path: paths.heatmapPath, snapshot: snap };
  }

  /**
   * Read heatmap from disk (or build live if missing).
   */
  function status() {
    if (existsSync(paths.heatmapPath)) {
      try {
        const disk = JSON.parse(readFileSync(paths.heatmapPath, 'utf8'));
        // Refresh live counters on read
        const live = buildHeatmap();
        return { ok: true, path: paths.heatmapPath, heatmap: live, disk_ts: disk.ts || null };
      } catch {
        /* fall through */
      }
    }
    const live = writeHeatmap();
    return { ok: true, path: paths.heatmapPath, heatmap: live.snapshot, disk_ts: live.snapshot.ts };
  }

  function listLeases() {
    expireDueLeases();
    const out = [];
    for (const [id, rec] of domain.leaseStore.entries()) {
      out.push({
        leaseId: id,
        agentId: rec.agentId,
        status: rec.status,
        created_at: rec.created_at || null,
        expires_at: rec.expires_at || null,
      });
    }
    return out;
  }

  function listAgents() {
    return { ...domain.agents };
  }

  return {
    domainRoot,
    domain,
    paths,
    quotas,
    registerAgent,
    issueLease,
    expireLease,
    revokeLease,
    expireDueLeases,
    claim,
    releaseClaim,
    buildHeatmap,
    writeHeatmap,
    status,
    listLeases,
    listAgents,
    /** @internal test helpers */
    _claims: claims,
    _waiters: waiters,
    _stats: agentStats,
  };
}

/**
 * Convenience: read heatmap JSON for CLI without creating a full coordinator.
 * @param {string} [domainRoot]
 * @param {string} [cityPath]
 */
export function readSwarmHeatmap(domainRoot, cityPath) {
  const root = resolveDomainRoot(cityPath, domainRoot);
  const { heatmapPath } = swarmPaths(root);
  if (!existsSync(heatmapPath)) {
    return { ok: false, reason: 'no_heatmap', path: heatmapPath, domainRoot: root };
  }
  try {
    const heatmap = JSON.parse(readFileSync(heatmapPath, 'utf8'));
    return { ok: true, path: heatmapPath, domainRoot: root, heatmap };
  } catch (err) {
    return {
      ok: false,
      reason: err && err.message ? err.message : String(err),
      path: heatmapPath,
      domainRoot: root,
    };
  }
}
