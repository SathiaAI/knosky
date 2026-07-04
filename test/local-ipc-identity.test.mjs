// KnoSky F0.4 — Local authentication: kernel-verified principal identity (SAT-548).
//
// Tests for core/local-ipc-identity.mjs.
//
// Coverage:
//   F04-001  getPeerIdentity returns a kernel-verified identity (pid/uid/gid)
//            for a real Unix socket — pid must equal process.pid.
//   F04-002  Identity fields are kernel-derived integers; mechanism matches
//            platform.
//   F04-003  resolveLeaseIdentity returns authoritative agentId from the
//            server-side store, NEVER from the request payload.
//   F04-004  Spoofing attempt (payloadAgentId != record.agentId) → rejected.
//   F04-005  resolveLeaseIdentity handles missing/expired/revoked leases.
//   F04-006  conformanceReport loopback self-test: selfTestPassed=true and
//            selfTestPid === process.pid on supported platforms.
//   F04-007  getPeerIdentity with a null/bad handle returns null, never throws.
//   F04-008  resolveLeaseIdentity rejects missing leaseId and unknown leaseId.
//   F04-009  Lease store is authoritative: agentId from payload is
//            "checked-not-trusted" — present but matching payload is accepted,
//            absent payload is accepted; only a mismatching payload is rejected.
//
// Run: node test/local-ipc-identity.test.mjs

import net from 'node:net';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  getPeerIdentity,
  resolveLeaseIdentity,
  conformanceReport,
  SANDBOX_CARVEOUT_EVENT,
} from '../core/local-ipc-identity.mjs';

const PLATFORM = os.platform();

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a Unix socket server, connect to it, return the accepted socket handle
 * and close everything once the callback completes.
 *
 * @param {(handle: object) => void} cb - called with the accepted socket's _handle.
 * @returns {Promise<void>}
 */
function withSelfConnectedSocket(cb) {
  return new Promise((resolve, reject) => {
    const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-f04-test-'));
    const sockPath = path.join(sockDir, 'test.sock');

    const srv = net.createServer((sock) => {
      try {
        cb(sock._handle);
      } catch (e) {
        reject(e);
      } finally {
        sock.destroy();
        srv.close(() => {
          try { fs.unlinkSync(sockPath); } catch { /* best effort */ }
          try { fs.rmdirSync(sockDir); } catch { /* best effort */ }
          resolve();
        });
      }
    });

    srv.on('error', reject);
    srv.listen(sockPath, () => {
      const c = net.connect(sockPath);
      c.on('error', reject);
      c.once('connect', () => c.destroy());
    });
  });
}

// ---------------------------------------------------------------------------
// Lease store fixture
// ---------------------------------------------------------------------------

const LEASE_STORE = new Map([
  ['lease-001', { leaseId: 'lease-001', agentId: 'agent-alpha', status: 'active', pid: 1234, uid: 1000 }],
  ['lease-002', { leaseId: 'lease-002', agentId: 'agent-beta',  status: 'active', pid: 5678, uid: 1000 }],
  ['lease-exp', { leaseId: 'lease-exp', agentId: 'agent-dead',  status: 'expired' }],
  ['lease-rev', { leaseId: 'lease-rev', agentId: 'agent-gone',  status: 'revoked' }],
]);

// ===========================================================================
// F04-001  getPeerIdentity returns kernel-verified identity on Unix
// ===========================================================================
console.log('\n--- F04-001/002  getPeerIdentity loopback ---');

if (PLATFORM === 'linux' || PLATFORM === 'darwin') {
  await withSelfConnectedSocket((handle) => {
    const identity = getPeerIdentity(handle);

    ok('F04-001: getPeerIdentity returns non-null on ' + PLATFORM, identity !== null,
      identity === null ? '(returned null; C compiler may be missing)' : '');

    if (identity) {
      // F04-002: kernel-derived fields
      ok('F04-002: pid is a positive integer', Number.isInteger(identity.pid) && identity.pid > 0,
        'pid=' + identity.pid);
      ok('F04-002: uid is a non-negative integer', Number.isInteger(identity.uid) && identity.uid >= 0,
        'uid=' + identity.uid);
      ok('F04-002: gid is a non-negative integer on Linux',
        PLATFORM === 'darwin' || (Number.isInteger(identity.gid) && identity.gid >= 0),
        'gid=' + identity.gid);

      ok('F04-001: pid equals process.pid (kernel-verified loopback)',
        identity.pid === process.pid,
        'expected=' + process.pid + ' got=' + identity.pid);

      const expectedMechanism = PLATFORM === 'linux' ? 'SO_PEERCRED' : 'LOCAL_PEERCRED';
      ok('F04-002: mechanism field matches platform', identity.mechanism === expectedMechanism,
        'mechanism=' + identity.mechanism);
      ok('F04-002: platform field is correct', identity.platform === PLATFORM,
        'platform=' + identity.platform);
    }
  });
} else if (PLATFORM === 'win32') {
  ok('F04-001: Windows platform detected (named-pipe path; full test in F0.5 fixture)', true);
} else {
  ok('F04-001: unsupported platform — getPeerIdentity returns null gracefully',
    getPeerIdentity(null) === null);
}

// ===========================================================================
// F04-007  getPeerIdentity with null/bad handle never throws, returns null
// ===========================================================================
console.log('\n--- F04-007  null/bad handle safety ---');

{
  const cases = [null, undefined, {}, { fd: -1 }, { fd: 'string' }, 42, 'string'];
  for (const h of cases) {
    const label = String(JSON.stringify(h) ?? 'undefined').slice(0, 30);
    let threw = false;
    let result;
    try { result = getPeerIdentity(h); } catch { threw = true; }
    ok('F04-007: no throw for handle=' + label, !threw);
    ok('F04-007: returns null for handle=' + label, result === null);
  }
}

// ===========================================================================
// F04-003  resolveLeaseIdentity returns authoritative agentId from the store
// ===========================================================================
console.log('\n--- F04-003  resolveLeaseIdentity: server-side authority ---');

{
  // Basic happy path — no payload agentId supplied (typical evaluator path).
  const r1 = resolveLeaseIdentity(LEASE_STORE, 'lease-001');
  ok('F04-003: ok=true for known active lease', r1.ok === true, JSON.stringify(r1));
  ok('F04-003: returned agentId is from store, not payload',
    r1.agentId === 'agent-alpha', 'agentId=' + r1.agentId);
  ok('F04-003: returned lease record is the store record',
    r1.lease && r1.lease.leaseId === 'lease-001');

  const r2 = resolveLeaseIdentity(LEASE_STORE, 'lease-002');
  ok('F04-003: second lease resolves correctly',
    r2.ok === true && r2.agentId === 'agent-beta');
}

// ===========================================================================
// F04-009  Checked-not-trusted: matching payload passes; mismatching rejected
// ===========================================================================
console.log('\n--- F04-009  payload agentId is checked-not-trusted ---');

{
  // Matching payload agentId — allowed (payload agrees with store).
  const rMatch = resolveLeaseIdentity(LEASE_STORE, 'lease-001', 'agent-alpha');
  ok('F04-009: matching payloadAgentId allowed', rMatch.ok === true,
    JSON.stringify(rMatch));
  ok('F04-009: returned agentId is STILL from store, not payload copy',
    rMatch.agentId === 'agent-alpha');

  // Absent payload (null) — allowed always.
  const rNull = resolveLeaseIdentity(LEASE_STORE, 'lease-001', null);
  ok('F04-009: null payloadAgentId always allowed', rNull.ok === true);

  // Absent payload (undefined) — treated same as null.
  const rUndef = resolveLeaseIdentity(LEASE_STORE, 'lease-001', undefined);
  ok('F04-009: undefined payloadAgentId treated same as null', rUndef.ok === true);
}

// ===========================================================================
// F04-004  Spoofing attempt: payloadAgentId != record.agentId → rejected
// ===========================================================================
console.log('\n--- F04-004  anti-spoofing: mismatching payloadAgentId rejected ---');

{
  // An attacker sends leaseId='lease-001' but claims to be 'agent-attacker'.
  const rSpoof = resolveLeaseIdentity(LEASE_STORE, 'lease-001', 'agent-attacker');
  ok('F04-004: mismatching payloadAgentId is rejected', rSpoof.ok === false,
    JSON.stringify(rSpoof));
  ok('F04-004: rejection reason is payload_agent_id_mismatch',
    rSpoof.reason === 'payload_agent_id_mismatch', 'reason=' + rSpoof.reason);
  // Make sure the actual authoritative agentId is NOT present in the error response
  // (no inadvertent disclosure — evaluator can log as needed, but the return value
  // does not echo the correct agentId back to the attacker).
  ok('F04-004: error response does not echo authoritative agentId',
    !('agentId' in rSpoof));

  // Swap: use lease-002's agentId with lease-001's leaseId (cross-lease spoof).
  const rCross = resolveLeaseIdentity(LEASE_STORE, 'lease-001', 'agent-beta');
  ok('F04-004: cross-lease agentId injection rejected', rCross.ok === false,
    JSON.stringify(rCross));
  ok('F04-004: cross-lease mismatch reason', rCross.reason === 'payload_agent_id_mismatch');

  // Empty string agentId — treated as mismatch (not as absent).
  const rEmpty = resolveLeaseIdentity(LEASE_STORE, 'lease-001', '');
  ok('F04-004: empty string payloadAgentId treated as mismatch (not absent)',
    rEmpty.ok === false);
}

// ===========================================================================
// F04-005  resolveLeaseIdentity handles missing/expired/revoked leases
// ===========================================================================
console.log('\n--- F04-005  lease lifecycle rejection ---');

{
  const rExp = resolveLeaseIdentity(LEASE_STORE, 'lease-exp');
  ok('F04-005: expired lease rejected', rExp.ok === false, JSON.stringify(rExp));
  ok('F04-005: expired reason', rExp.reason === 'lease_expired');

  const rRev = resolveLeaseIdentity(LEASE_STORE, 'lease-rev');
  ok('F04-005: revoked lease rejected', rRev.ok === false, JSON.stringify(rRev));
  ok('F04-005: revoked reason', rRev.reason === 'lease_revoked');
}

// ===========================================================================
// F04-008  Missing / unknown leaseId → rejected
// ===========================================================================
console.log('\n--- F04-008  missing/unknown leaseId ---');

{
  const cases = [
    ['', 'missing_lease_id'],
    [null, 'missing_lease_id'],
    [undefined, 'missing_lease_id'],
    ['lease-unknown-xyz', 'unknown_lease_id'],
    ['LEASE-001', 'unknown_lease_id'],  // case-sensitive
    ['lease-001' + '\x00inject', 'unknown_lease_id'],  // NUL-injection
    ['a'.repeat(1000), 'unknown_lease_id'],   // overly long
  ];
  for (const [leaseId, expectedReason] of cases) {
    const r = resolveLeaseIdentity(LEASE_STORE, leaseId);
    ok(`F04-008: leaseId=${JSON.stringify(String(leaseId).slice(0, 30))} → ok=false`,
      r.ok === false, JSON.stringify(r));
    ok(`F04-008: reason=${expectedReason} for leaseId=${JSON.stringify(String(leaseId).slice(0, 30))}`,
      r.reason === expectedReason, 'got=' + r.reason);
  }

  // Non-Map store (should not throw; returns unknown_lease_id or similar)
  let threw5 = false;
  let r5;
  try { r5 = resolveLeaseIdentity(null, 'lease-001'); } catch { threw5 = true; }
  ok('F04-008: null leaseStore does not throw', !threw5);
  ok('F04-008: null leaseStore returns ok=false', r5 && r5.ok === false);

  let threw6 = false;
  let r6;
  try { r6 = resolveLeaseIdentity({}, 'lease-001'); } catch { threw6 = true; }
  ok('F04-008: plain-object leaseStore does not throw', !threw6);
  ok('F04-008: plain-object leaseStore returns ok=false', r6 && r6.ok === false);
}

// ===========================================================================
// F04-006  conformanceReport loopback self-test
// ===========================================================================
console.log('\n--- F04-006  conformanceReport ---');

{
  let report;
  let threw = false;
  try { report = await conformanceReport(); } catch { threw = true; }

  ok('F04-006: conformanceReport does not throw', !threw);
  ok('F04-006: report is an object', report && typeof report === 'object');
  ok('F04-006: report.platform matches os.platform()', report?.platform === PLATFORM);

  if (PLATFORM === 'linux' || PLATFORM === 'darwin') {
    if (report?.compilerAvailable) {
      ok('F04-006: selfTestPassed === true (compiler available, loopback succeeded)',
        report.selfTestPassed === true,
        'error=' + report.error);
      ok('F04-006: selfTestPid === process.pid',
        report.selfTestPid === process.pid,
        'expected=' + process.pid + ' got=' + report.selfTestPid);
      ok('F04-006: mechanism is SO_PEERCRED or LOCAL_PEERCRED',
        report.mechanism === 'SO_PEERCRED' || report.mechanism === 'LOCAL_PEERCRED');
      ok('F04-006: no error when self-test passes',
        report.selfTestPassed ? report.error === null : true);
    } else {
      // No compiler: the conformance test cannot run, which is itself a valid
      // (if degraded) state. F0.5 fixture would emit a carveout event.
      ok('F04-006: compilerAvailable=false — selfTestPassed=false (degraded, expected)',
        report.selfTestPassed === false);
      ok('F04-006: error describes missing compiler',
        typeof report.error === 'string' && report.error.includes('compiler'));
    }
  } else if (PLATFORM === 'win32') {
    ok('F04-006: Windows — mechanism is GetNamedPipeClientProcessId',
      report?.mechanism === 'GetNamedPipeClientProcessId');
  }
}

// ===========================================================================
// SANDBOX_CARVEOUT_EVENT export
// ===========================================================================
console.log('\n--- SANDBOX_CARVEOUT_EVENT constant ---');

{
  ok('SANDBOX_CARVEOUT_EVENT is exported string',
    typeof SANDBOX_CARVEOUT_EVENT === 'string' && SANDBOX_CARVEOUT_EVENT.length > 0);
  ok('SANDBOX_CARVEOUT_EVENT value is f04_sandbox_carveout',
    SANDBOX_CARVEOUT_EVENT === 'f04_sandbox_carveout');
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
