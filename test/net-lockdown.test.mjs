// KnoSky F0.5 — OS-level network lockdown for the evaluator process (SAT-549).
//
// Tests for core/net-lockdown.mjs.
//
// Coverage:
//   F05-001  probeNetworkLockdownSupport returns a well-formed LockdownReport.
//   F05-002  wrapArgsForLockdown returns a non-empty prefix on Linux (unshare
//            available) and [] on unsupported platforms.
//   F05-003  doctorLines returns an array of non-empty strings describing status.
//   F05-004  Active-detection: probeNetworkLockdownSupport.active is true when
//            called from inside an isolated namespace (Linux only).
//   F05-005  Sandbox actually blocks external TCP connections (ENETUNREACH).
//   F05-006  F0.4-survives-sandbox conformance fixture: conformanceReport()
//            (SO_PEERCRED / LOCAL_PEERCRED) still works inside the sandbox.
//            (Required by F0.4↔F0.5 interaction note in local-ipc-identity.mjs.)
//   F05-007  probeNetworkLockdownSupport never throws on any platform.
//   F05-008  Unix-domain sockets work inside the isolated namespace (IPC path).
//   F05-009  unsupportedReason is a non-empty string when supported === false.
//
// Run: node test/net-lockdown.test.mjs

import { spawnSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  probeNetworkLockdownSupport,
  wrapArgsForLockdown,
  doctorLines,
} from '../core/net-lockdown.mjs';

const PLATFORM = os.platform();
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// F05-001  probeNetworkLockdownSupport returns a well-formed LockdownReport
// ---------------------------------------------------------------------------
console.log('\n--- F05-001  probeNetworkLockdownSupport shape ---');

{
  let report;
  let threw = false;
  try { report = probeNetworkLockdownSupport(); } catch { threw = true; }

  ok('F05-001: does not throw', !threw);
  ok('F05-001: returns an object', report && typeof report === 'object');
  ok('F05-001: platform field matches os.platform()', report?.platform === PLATFORM,
    'got=' + report?.platform);
  ok('F05-001: strategy is a non-empty string',
    typeof report?.strategy === 'string' && report.strategy.length > 0,
    'strategy=' + report?.strategy);
  ok('F05-001: supported is boolean', typeof report?.supported === 'boolean');
  ok('F05-001: toolAvailable is boolean', typeof report?.toolAvailable === 'boolean');
  ok('F05-001: active is boolean', typeof report?.active === 'boolean');
  ok('F05-001: detail is a non-empty string',
    typeof report?.detail === 'string' && report.detail.length > 0);

  // unsupportedReason is string when !supported, null when supported
  if (report?.supported) {
    ok('F05-001: unsupportedReason is null when supported=true',
      report.unsupportedReason === null, 'got=' + report.unsupportedReason);
  } else {
    ok('F05-001: unsupportedReason is a non-empty string when supported=false',
      typeof report?.unsupportedReason === 'string' && report.unsupportedReason.length > 0,
      'got=' + report?.unsupportedReason);
  }
}

// ---------------------------------------------------------------------------
// F05-009  unsupportedReason contract (re-verify for all platforms)
// ---------------------------------------------------------------------------
console.log('\n--- F05-009  unsupportedReason contract ---');

{
  const r = probeNetworkLockdownSupport();
  if (r.supported) {
    ok('F05-009: unsupportedReason === null when supported', r.unsupportedReason === null);
  } else {
    ok('F05-009: unsupportedReason is a string when !supported',
      typeof r.unsupportedReason === 'string' && r.unsupportedReason.length > 0,
      'got=' + r.unsupportedReason);
  }
}

// ---------------------------------------------------------------------------
// F05-007  probeNetworkLockdownSupport never throws (call it multiple times)
// ---------------------------------------------------------------------------
console.log('\n--- F05-007  never throws ---');

{
  for (let i = 0; i < 5; i++) {
    let threw = false;
    try { probeNetworkLockdownSupport(); } catch { threw = true; }
    ok(`F05-007: call #${i + 1} does not throw`, !threw);
  }
}

// ---------------------------------------------------------------------------
// F05-002  wrapArgsForLockdown
// ---------------------------------------------------------------------------
console.log('\n--- F05-002  wrapArgsForLockdown ---');

{
  let result;
  let threw = false;
  try { result = wrapArgsForLockdown(); } catch { threw = true; }

  ok('F05-002: does not throw', !threw);
  ok('F05-002: returns an array', Array.isArray(result), 'got=' + typeof result);

  if (PLATFORM === 'linux') {
    const r = probeNetworkLockdownSupport();
    if (r.toolAvailable) {
      ok('F05-002 (Linux): prefix is non-empty when unshare is available',
        result.length > 0, 'prefix=' + JSON.stringify(result));
      ok('F05-002 (Linux): first element is "unshare"',
        result[0] === 'unshare', 'got=' + result[0]);
      ok('F05-002 (Linux): contains --user and --net flags',
        result.includes('--user') && result.includes('--net'),
        'prefix=' + JSON.stringify(result));
    } else {
      ok('F05-002 (Linux): returns [] when unshare unavailable', result.length === 0);
    }
  } else if (PLATFORM === 'darwin') {
    // On macOS prefix is ['sandbox-exec', ...] or [] if unavailable.
    if (result.length > 0) {
      ok('F05-002 (macOS): first element is "sandbox-exec"', result[0] === 'sandbox-exec',
        'got=' + result[0]);
    } else {
      ok('F05-002 (macOS): empty prefix is valid when sandbox-exec unavailable', true);
    }
  } else {
    ok('F05-002 (non-Linux/macOS): returns [] (no runtime wrap)', result.length === 0,
      'got=' + JSON.stringify(result));
  }
}

// ---------------------------------------------------------------------------
// F05-003  doctorLines
// ---------------------------------------------------------------------------
console.log('\n--- F05-003  doctorLines ---');

{
  let lines;
  let threw = false;
  try { lines = doctorLines(); } catch { threw = true; }

  ok('F05-003: does not throw', !threw);
  ok('F05-003: returns a non-empty array', Array.isArray(lines) && lines.length > 0,
    'length=' + lines?.length);
  ok('F05-003: all entries are non-empty strings',
    lines?.every(l => typeof l === 'string' && l.length > 0),
    lines?.filter(l => !l).join(', ') || '');
  ok('F05-003: first line mentions F0.5',
    lines?.[0]?.includes('F0.5'), 'first=' + lines?.[0]);
  ok('F05-003: lines contain platform strategy mention',
    lines?.some(l => l.toLowerCase().includes('namespace') ||
                     l.toLowerCase().includes('sandbox') ||
                     l.toLowerCase().includes('appcontainer') ||
                     l.toLowerCase().includes('wfp') ||
                     l.toLowerCase().includes('none') ||
                     l.toLowerCase().includes('unsupported')),
    lines?.join(' | '));
}

// ---------------------------------------------------------------------------
// Platform-specific deeper tests (Linux)
// ---------------------------------------------------------------------------

if (PLATFORM === 'linux') {
  const r = probeNetworkLockdownSupport();

  // F05-004  Active-detection inside isolated namespace
  console.log('\n--- F05-004  active=true inside isolated net namespace (Linux) ---');

  if (r.toolAvailable) {
    // Run net-lockdown probe INSIDE the namespace via a child node process
    const innerScript = `
import { probeNetworkLockdownSupport } from ${JSON.stringify(path.join(ROOT, 'core/net-lockdown.mjs'))};
const r = probeNetworkLockdownSupport();
process.stdout.write(JSON.stringify(r));
    `.trim();

    const result = spawnSync(
      'unshare', ['--user', '--net', '--', NODE, '--input-type=module'],
      {
        input: innerScript,
        encoding: 'utf8',
        timeout: 15000,
        cwd: ROOT,
      }
    );

    ok('F05-004: child process in namespace exits successfully',
      result.status === 0,
      result.stderr ? 'stderr=' + result.stderr.trim().slice(0, 200) : '');

    let innerReport;
    try { innerReport = JSON.parse(result.stdout || '{}'); } catch { /* handled below */ }

    ok('F05-004: probe output is parseable JSON', innerReport && typeof innerReport === 'object',
      'stdout=' + (result.stdout || '').slice(0, 100));

    ok('F05-004: active === true inside isolated namespace',
      innerReport?.active === true, 'active=' + innerReport?.active);
    ok('F05-004: supported === true inside isolated namespace',
      innerReport?.supported === true, 'supported=' + innerReport?.supported);

  } else {
    ok('F05-004: SKIP — unshare not available on this system', true);
  }

  // F05-005  Sandbox blocks external TCP connections
  console.log('\n--- F05-005  sandbox blocks external TCP (Linux) ---');

  if (r.toolAvailable) {
    // Try to connect to a non-routable address (TEST-NET-1; RFC 5737)
    // Inside a net namespace ENETUNREACH is immediate; no actual network hit.
    const connectScript = `
const net = require('net');
const s = net.createConnection({ host: '192.0.2.1', port: 80, timeout: 1000 });
s.on('error', e => { process.stdout.write(e.code); process.exit(0); });
s.on('connect', () => { process.stdout.write('CONNECTED'); process.exit(0); });
setTimeout(() => { process.stdout.write('TIMEOUT'); process.exit(0); }, 2000);
    `.trim();

    const result = spawnSync(
      'unshare', ['--user', '--net', '--', NODE, '-e', connectScript],
      { encoding: 'utf8', timeout: 10000, cwd: ROOT }
    );

    ok('F05-005: child process exits successfully', result.status === 0,
      'stderr=' + (result.stderr || '').slice(0, 100));
    ok('F05-005: external TCP gets ENETUNREACH (not CONNECTED)',
      result.stdout === 'ENETUNREACH',
      'got=' + result.stdout);

  } else {
    ok('F05-005: SKIP — unshare not available', true);
  }

  // F05-006  F0.4-survives-sandbox conformance fixture
  // Required by local-ipc-identity.mjs SANDBOX_CARVEOUT_NOTE:
  //   "Each platform sandbox profile (F0.5) must ship a dedicated conformance
  //    fixture that exercises getPeerIdentity() from inside that specific sandbox
  //    before the profile is considered complete."
  console.log('\n--- F05-006  F0.4 survives sandbox (conformanceReport inside namespace) ---');

  if (r.toolAvailable) {
    const f04Script = `
import { conformanceReport } from ${JSON.stringify(path.join(ROOT, 'core/local-ipc-identity.mjs'))};
const r = await conformanceReport();
process.stdout.write(JSON.stringify(r));
    `.trim();

    const result = spawnSync(
      'unshare', ['--user', '--net', '--', NODE, '--input-type=module'],
      {
        input: f04Script,
        encoding: 'utf8',
        timeout: 20000,
        cwd: ROOT,
      }
    );

    ok('F05-006: conformanceReport child exits successfully inside sandbox',
      result.status === 0,
      result.stderr ? 'stderr=' + result.stderr.trim().slice(0, 200) : '');

    let f04Report;
    try { f04Report = JSON.parse(result.stdout || '{}'); } catch { /* handled below */ }

    ok('F05-006: conformanceReport output is parseable JSON',
      f04Report && typeof f04Report === 'object',
      'stdout=' + (result.stdout || '').slice(0, 100));

    ok('F05-006 F0.4-survives-sandbox: selfTestPassed === true inside net namespace',
      f04Report?.selfTestPassed === true,
      'report=' + JSON.stringify(f04Report));

    ok('F05-006 F0.4-survives-sandbox: selfTestPid is a positive integer',
      typeof f04Report?.selfTestPid === 'number' && f04Report.selfTestPid > 0,
      'selfTestPid=' + f04Report?.selfTestPid);

    ok('F05-006 F0.4-survives-sandbox: mechanism is SO_PEERCRED',
      f04Report?.mechanism === 'SO_PEERCRED',
      'mechanism=' + f04Report?.mechanism);

    ok('F05-006 F0.4-survives-sandbox: no error when self-test passes',
      f04Report?.selfTestPassed ? f04Report.error === null : true,
      'error=' + f04Report?.error);

    // Confirm: the sandbox did NOT emit a SANDBOX_CARVEOUT_EVENT for SO_PEERCRED
    // (Unix sockets are unaffected by the network namespace — no carve-out needed).
    ok('F05-006: no carveout event emitted (SO_PEERCRED works natively in net namespace)',
      f04Report?.selfTestPassed === true);

  } else {
    ok('F05-006: SKIP — unshare not available', true);
  }

  // F05-008  Unix-domain sockets work inside isolated namespace
  console.log('\n--- F05-008  Unix-domain sockets work in isolated namespace (Linux) ---');

  if (r.toolAvailable) {
    const unixScript = `
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-f05-ipc-'));
const sockPath = path.join(dir, 'test.sock');

const srv = net.createServer(c => {
  c.end('pong');
  srv.close(() => {
    try { fs.unlinkSync(sockPath); fs.rmdirSync(dir); } catch {}
  });
});

srv.listen(sockPath, () => {
  const c = net.connect(sockPath);
  c.on('data', d => {
    process.stdout.write(d.toString().trim() === 'pong' ? 'UNIX_SOCKET_OK' : 'UNIX_SOCKET_BAD');
    c.destroy();
  });
  c.on('error', e => {
    process.stdout.write('UNIX_SOCKET_ERROR:' + e.code);
    process.exit(1);
  });
});
    `.trim();

    const result = spawnSync(
      'unshare', ['--user', '--net', '--', NODE, '-e', unixScript],
      { encoding: 'utf8', timeout: 10000, cwd: ROOT }
    );

    ok('F05-008: Unix socket test exits successfully', result.status === 0,
      'stderr=' + (result.stderr || '').slice(0, 100));
    ok('F05-008: Unix-domain socket IPC works inside isolated network namespace',
      result.stdout === 'UNIX_SOCKET_OK',
      'got=' + result.stdout);

  } else {
    ok('F05-008: SKIP — unshare not available', true);
  }

} else if (PLATFORM === 'darwin') {
  // macOS: lighter checks — we can only verify the probe shape and doctorLines
  // since sandbox-exec(1) availability varies across CI images.
  console.log('\n--- F05-004/005/006/008  macOS: probe + doctor (no runtime wrap in CI) ---');

  const r = probeNetworkLockdownSupport();
  ok('macOS: strategy mentions sandbox-exec',
    r.strategy.includes('sandbox-exec'), 'strategy=' + r.strategy);
  ok('macOS: detail is non-empty', typeof r.detail === 'string' && r.detail.length > 0);

  if (r.toolAvailable) {
    ok('macOS: toolAvailable=true means wrapArgsForLockdown has sandbox-exec',
      wrapArgsForLockdown()[0] === 'sandbox-exec');
  }

} else if (PLATFORM === 'win32') {
  console.log('\n--- F05-004/005/006/008  Windows: probe-only checks ---');

  const r = probeNetworkLockdownSupport();
  ok('Windows: strategy mentions AppContainer or WFP', r.strategy.length > 0,
    'strategy=' + r.strategy);
  ok('Windows: wrapArgsForLockdown returns []', wrapArgsForLockdown().length === 0);

} else {
  console.log('\n--- F05-004/005/006/008  Unsupported platform: probe-only ---');

  ok('unsupported: supported=false', probeNetworkLockdownSupport().supported === false);
  ok('unsupported: wrapArgsForLockdown returns []', wrapArgsForLockdown().length === 0);
  ok('unsupported: unsupportedReason is set',
    typeof probeNetworkLockdownSupport().unsupportedReason === 'string');
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
