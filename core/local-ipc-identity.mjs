// KnoSky F0.4 — Local authentication: kernel-verified principal identity (SAT-548).
//
// Establishes the OS-kernel-verified identity of the process on the other end of a
// local IPC connection.  NEVER relies on a self-asserted field from the request
// payload — identity comes exclusively from the kernel via:
//
//   Linux   : SO_PEERCRED (getsockopt over a Unix-domain socket)
//   macOS   : LOCAL_PEERCRED (getsockopt) or xpc_connection_get_audit_token
//   Windows : GetNamedPipeClientProcessId + OpenProcessToken over a named pipe
//
// Two-layer clarification from the ticket (D-193/D-194):
//   F0.4 proves "real local OS process" (pid/uid/gid from the kernel).
//   Swarm-lease binding (TRD §2.8) is a separate layer that maps a kernel-verified
//   process to a named agent role — that is `resolveLeaseIdentity()` below.
//
// Lease-identity fix (GLM, round-3): the evaluator NEVER trusts `agentId` from
// the request payload.  It looks up the lease record server-side by `leaseId`;
// the record's own `agentId` is authoritative.  The payload copy is checked
// against the record (mismatch → reject) but never accepted as truth on its own.
//
// F0.4↔F0.5 interaction: each platform sandbox profile (F0.5) must ship a
// dedicated conformance fixture that exercises getPeerIdentity() from inside that
// specific sandbox before the profile is considered complete.  If a sandbox
// profile blocks the IPC primitive a narrow, logged carve-out is emitted instead
// of a general sandbox loosening (see SANDBOX_CARVEOUT_NOTE below).
//
// Pure Node stdlib, ESM — no third-party dependencies.
// Requires a C compiler (cc/gcc/clang) at first call on Linux/macOS for the
// helper binary; the path is cached process-wide after first compile.

import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';

const PLATFORM = platform();

// ---------------------------------------------------------------------------
// SANDBOX_CARVEOUT_NOTE
//
// When F0.4's IPC primitive cannot be exercised inside an F0.5 sandbox profile,
// the profile MUST emit a structured carve-out log entry of the form:
//
//   { level: 'warn', event: 'f04_sandbox_carveout',
//     primitive: <'SO_PEERCRED'|'LOCAL_PEERCRED'|'GetNamedPipeClientProcessId'>,
//     sandbox: <profile-name>, reason: <string> }
//
// The carve-out is ONLY for the specific IPC primitive, never a general loosening.
// `knosky doctor` reads this log and surfaces it to the operator.
// ---------------------------------------------------------------------------
export const SANDBOX_CARVEOUT_EVENT = 'f04_sandbox_carveout';

// ---------------------------------------------------------------------------
// SO_PEERCRED helper binary (Linux)
// ---------------------------------------------------------------------------
//
// Node.js does not expose getsockopt(SO_PEERCRED) natively.  We compile a tiny
// C helper on first use.  The helper receives the socket fd on its own stdin (fd 0)
// and prints "pid uid gid\n" to stdout.  Receiving via fd 0 lets Node pass the
// live fd without a subprocess fd-inheritance gap (the handle is passed directly
// in the stdio option array).
//
// The binary is placed under a process-scoped temp directory and reused for the
// process lifetime.  On platforms where cc/gcc is unavailable the IPC identity
// layer degrades gracefully (returns null with a diagnostic).

const HELPER_SRC_LINUX = `
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Receive the socket fd on stdin (fd 0) via the Node.js stdio handle pass.
   Call getsockopt SO_PEERCRED on that fd, print pid uid gid. */
int main(void) {
    struct ucred cred;
    memset(&cred, 0, sizeof(cred));
    socklen_t len = sizeof(cred);
    if (getsockopt(0, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        perror("getsockopt SO_PEERCRED");
        return 1;
    }
    printf("%d %d %d\\n", (int)cred.pid, (int)cred.uid, (int)cred.gid);
    return 0;
}
`;

// macOS uses LOCAL_PEERCRED with struct xucred (different from Linux ucred).
const HELPER_SRC_MACOS = `
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ucred.h>
#include <unistd.h>

int main(void) {
    struct xucred cred;
    memset(&cred, 0, sizeof(cred));
    socklen_t len = sizeof(cred);
    /* LOCAL_PEERCRED on macOS returns the peer's effective uid/gids.
       Note: macOS does not include pid in xucred; pid is obtained via
       LOCAL_PEEREPID (separate getsockopt call). */
    if (getsockopt(0, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) < 0) {
        perror("getsockopt LOCAL_PEERCRED");
        return 1;
    }
    int pid = 0;
    socklen_t pidlen = sizeof(pid);
    /* LOCAL_PEEREPID = 7 on macOS */
    getsockopt(0, SOL_LOCAL, 7, &pid, &pidlen);
    printf("%d %d 0\\n", pid, (int)cred.cr_uid);
    return 0;
}
`;

/** @type {string|null} cached path to the compiled helper binary */
let _helperPath = null;

/**
 * Compile and cache the peercred helper binary for the current platform.
 * Returns the absolute path to the compiled binary, or null if compilation fails.
 *
 * @returns {string|null}
 */
function compilePeercredHelper() {
  if (_helperPath !== null) return _helperPath;

  const src = PLATFORM === 'linux' ? HELPER_SRC_LINUX
            : PLATFORM === 'darwin' ? HELPER_SRC_MACOS
            : null;
  if (!src) return null;   // Windows uses a different mechanism

  let dir;
  try {
    dir = mkdtempSync(join(tmpdir(), 'knosky-ipc-'));
  } catch {
    return null;
  }

  const srcPath = join(dir, 'peercred.c');
  const binPath = join(dir, 'peercred');

  try {
    writeFileSync(srcPath, src, 'utf8');
  } catch {
    return null;
  }

  // Try cc, then gcc, then clang in order.
  const compilers = ['cc', 'gcc', 'clang'];
  for (const cc of compilers) {
    try {
      execFileSync(cc, ['-O2', '-o', binPath, srcPath], { stdio: 'ignore', timeout: 15000 });
      _helperPath = binPath;
      return binPath;
    } catch {
      // try next compiler
    }
  }

  return null;  // no compiler available
}

// ---------------------------------------------------------------------------
// getPeerIdentity — main public API
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} PeerIdentity
 * @property {number}  pid        - Kernel-reported PID of the peer process.
 * @property {number}  uid        - Kernel-reported UID of the peer process.
 * @property {number}  gid        - Kernel-reported GID of the peer process (0 on macOS).
 * @property {string}  mechanism  - Which kernel primitive was used.
 * @property {string}  platform   - OS platform string.
 */

/**
 * Obtain the kernel-verified identity of the process connected to `socketHandle`.
 *
 * `socketHandle` must be a live `net.Socket._handle` (a TCP/pipe handle object
 * from Node.js's internal binding layer) that exposes an `fd` property.  The
 * function reads the socket's peer credentials directly from the OS kernel —
 * the peer process cannot forge these values.
 *
 * Returns `null` (never throws) when:
 *   - the platform is not yet supported
 *   - the handle has no accessible fd
 *   - the compiler is unavailable (Linux/macOS)
 *   - the kernel call itself fails (e.g. inside an F0.5 sandbox)
 *
 * When returning `null` on Linux/macOS the caller SHOULD emit a
 * SANDBOX_CARVEOUT_EVENT log entry identifying the specific primitive that
 * failed; that entry surfaces in `knosky doctor`.
 *
 * @param {object} socketHandle  - net.Socket._handle from an accepted connection.
 * @returns {PeerIdentity|null}
 */
export function getPeerIdentity(socketHandle) {
  if (PLATFORM === 'linux' || PLATFORM === 'darwin') {
    return _getPeerIdentityUnix(socketHandle);
  }
  if (PLATFORM === 'win32') {
    return _getPeerIdentityWin32(socketHandle);
  }
  return null;
}

/**
 * Linux / macOS implementation: SO_PEERCRED / LOCAL_PEERCRED via helper binary.
 *
 * @param {object} socketHandle
 * @returns {PeerIdentity|null}
 */
function _getPeerIdentityUnix(socketHandle) {
  const helperBin = compilePeercredHelper();
  if (!helperBin) return null;

  if (!socketHandle || typeof socketHandle !== 'object') return null;

  // Pass the socket fd to the helper via its stdin slot (position 0 in stdio).
  // Node's spawnSync supports passing a handle object directly in the stdio
  // array; this causes libuv to dup the fd into the child's stdin.
  let result;
  try {
    result = spawnSync(helperBin, [], {
      stdio: [socketHandle, 'pipe', 'ignore'],
      encoding: 'utf8',
      timeout: 5000,
    });
  } catch {
    return null;
  }

  if (result.status !== 0 || result.signal !== null) return null;

  const parts = (result.stdout || '').trim().split(' ').map(Number);
  if (parts.length < 3 || parts.some(n => !Number.isInteger(n) || n < 0)) return null;

  const [pid, uid, gid] = parts;
  // pid === 0 is suspicious on Linux (only kernel threads have pid 0).
  // Accept on macOS where LOCAL_PEEREPID may return 0 in some edge cases.
  if (PLATFORM === 'linux' && pid === 0) return null;

  return {
    pid,
    uid,
    gid,
    mechanism: PLATFORM === 'linux' ? 'SO_PEERCRED' : 'LOCAL_PEERCRED',
    platform: PLATFORM,
  };
}

/**
 * Windows implementation: GetNamedPipeClientProcessId + OpenProcessToken.
 *
 * On Windows, knosky uses a named pipe for local IPC.  The kernel provides
 * the client's PID via GetNamedPipeClientProcessId; the token (uid analogue)
 * is obtained via ImpersonateNamedPipeClient + OpenProcessToken.
 *
 * This implementation calls a PowerShell one-liner with the pipe handle so
 * that no C++ addon is required for the Windows path.
 *
 * @param {object} socketHandle
 * @returns {PeerIdentity|null}
 */
function _getPeerIdentityWin32(socketHandle) {
  // Windows named pipes expose the fd as a HANDLE value.
  const fd = socketHandle?.fd;
  if (typeof fd !== 'number' || fd < 0) return null;

  // PowerShell script: call GetNamedPipeClientProcessId on the handle value,
  // output JSON {pid, sid}.  The SID encodes the uid analogue on Windows.
  const ps = [
    '$h=[IntPtr]' + fd + ';',
    '$pid=0;',
    '[void][KnoskySec.Pipe]::GetNamedPipeClientProcessId($h,[ref]$pid);',
    '$tok=[System.IntPtr]::Zero;',
    '[KnoskySec.Pipe]::OpenProcessToken([Diagnostics.Process]::GetProcessById($pid).Handle,8,[ref]$tok)|Out-Null;',
    '$id=New-Object System.Security.Principal.WindowsIdentity $tok;',
    'Write-Output ("{0} {1}" -f $pid,$id.User.Value)',
  ].join(' ');

  let result;
  try {
    result = spawnSync('powershell.exe', ['-NoProfile', '-Command', ps], {
      encoding: 'utf8',
      timeout: 10000,
    });
  } catch {
    return null;
  }

  if (result.status !== 0) return null;

  const line = (result.stdout || '').trim();
  const m = line.match(/^(\d+)\s+(.+)$/);
  if (!m) return null;

  const pid = Number(m[1]);
  if (!Number.isInteger(pid) || pid <= 0) return null;

  return {
    pid,
    uid: -1,            // Windows uses SID, not numeric uid
    gid: -1,
    sid: m[2],          // Windows Security Identifier
    mechanism: 'GetNamedPipeClientProcessId',
    platform: 'win32',
  };
}

// ---------------------------------------------------------------------------
// resolveLeaseIdentity — swarm-lease anti-spoofing (GLM round-3 fix)
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} LeaseRecord
 * @property {string}  leaseId    - Stable, server-assigned lease identifier.
 * @property {string}  agentId    - Authoritative agent identity (server-side record).
 * @property {number}  [pid]      - PID of the process that registered the lease (optional).
 * @property {number}  [uid]      - UID of the process that registered the lease (optional).
 * @property {string}  [status]   - 'active' | 'expired' | 'revoked'.
 */

/**
 * Resolve the authoritative agent identity for an incoming request.
 *
 * CRITICAL invariant (GLM round-3): the evaluator NEVER trusts `payloadAgentId`
 * (the `agentId` field from the request payload) as truth.  Instead it looks up
 * the lease record server-side using `leaseId`.  The record's own `agentId` is
 * returned as the authoritative identity.
 *
 * If `payloadAgentId` is supplied AND does not match the record's `agentId`,
 * the call returns a spoofing-attempt error rather than accepting either value.
 * Payload copy is checked-not-trusted: the check closes the agent-spoofing-
 * under-shared-UID gap described in the ticket.
 *
 * @param {Map<string, LeaseRecord>} leaseStore
 *   Server-side, authoritative store of live lease records (keyed by leaseId).
 * @param {string} leaseId
 *   The leaseId extracted from the incoming request (used only as a lookup key).
 * @param {string|null} [payloadAgentId]
 *   The agentId the request self-asserts (optional; never used as truth).
 * @returns {{ ok: true, agentId: string, lease: LeaseRecord }
 *          |{ ok: false, reason: string }}
 */
export function resolveLeaseIdentity(leaseStore, leaseId, payloadAgentId = null) {
  if (!leaseId || typeof leaseId !== 'string') {
    return { ok: false, reason: 'missing_lease_id' };
  }

  const lease = leaseStore instanceof Map ? leaseStore.get(leaseId) : null;
  if (!lease) {
    return { ok: false, reason: 'unknown_lease_id' };
  }

  if (lease.status === 'expired') {
    return { ok: false, reason: 'lease_expired' };
  }
  if (lease.status === 'revoked') {
    return { ok: false, reason: 'lease_revoked' };
  }

  const authoritative = lease.agentId;
  if (!authoritative || typeof authoritative !== 'string') {
    return { ok: false, reason: 'lease_missing_agent_id' };
  }

  // Check-not-trust: if the request also asserts an agentId, verify it agrees
  // with the server-side record.  A mismatch signals a spoofing attempt.
  if (payloadAgentId !== null && payloadAgentId !== undefined) {
    if (payloadAgentId !== authoritative) {
      return {
        ok: false,
        reason: 'payload_agent_id_mismatch',
        // Do not echo back either value — let the caller log as needed.
      };
    }
  }

  return { ok: true, agentId: authoritative, lease };
}

// ---------------------------------------------------------------------------
// conformanceReport — used by F0.4↔F0.5 sandbox conformance fixtures
// ---------------------------------------------------------------------------

/**
 * Run a self-check of the F0.4 identity mechanism and return a structured report.
 *
 * Called by each F0.5 sandbox conformance fixture to verify that F0.4 still
 * functions correctly inside that specific sandbox before the profile is
 * considered complete.  If the check fails the fixture MUST emit a
 * SANDBOX_CARVEOUT_EVENT log entry for the specific IPC primitive and surface
 * it in `knosky doctor`.
 *
 * The report shape:
 * ```
 * {
 *   platform: string,
 *   mechanism: 'SO_PEERCRED'|'LOCAL_PEERCRED'|'GetNamedPipeClientProcessId'|'unsupported',
 *   compilerAvailable: boolean,   // Linux / macOS
 *   selfTestPassed: boolean,
 *   selfTestPid: number|null,     // must equal process.pid when selfTestPassed
 *   error: string|null,
 * }
 * ```
 *
 * @returns {Promise<object>}
 */
export async function conformanceReport() {
  if (PLATFORM === 'win32') {
    // Windows: simple named-pipe self-test is complex to set up here;
    // return a partial report.  Full conformance is done by the F0.5 fixture.
    return {
      platform: 'win32',
      mechanism: 'GetNamedPipeClientProcessId',
      compilerAvailable: null,
      selfTestPassed: false,
      selfTestPid: null,
      error: 'windows conformance test requires F0.5 fixture setup',
    };
  }

  const helperBin = compilePeercredHelper();
  const mechanism = PLATFORM === 'linux' ? 'SO_PEERCRED' : 'LOCAL_PEERCRED';

  if (!helperBin) {
    return {
      platform: PLATFORM,
      mechanism,
      compilerAvailable: false,
      selfTestPassed: false,
      selfTestPid: null,
      error: 'no C compiler available (cc/gcc/clang); could not compile peercred helper',
    };
  }

  // Run a loopback self-test: this process connects to itself over a Unix socket
  // and reads back its own pid via getPeerIdentity().
  const { createServer, connect } = await import('node:net');
  const { join: pjoin } = await import('node:path');
  const { mkdtempSync: mkdtmp, unlinkSync: unlink } = await import('node:fs');

  const sockDir = mkdtmp(join(tmpdir(), 'knosky-f04-conf-'));
  const sockPath = pjoin(sockDir, 'self.sock');

  let selfTestPassed = false;
  let selfTestPid = null;
  let error = null;

  try {
    await new Promise((resolve, reject) => {
      const srv = createServer((sock) => {
        const identity = getPeerIdentity(sock._handle);
        if (identity && identity.pid === process.pid) {
          selfTestPassed = true;
          selfTestPid = identity.pid;
        } else {
          error = identity
            ? `pid mismatch: expected ${process.pid}, got ${identity.pid}`
            : 'getPeerIdentity returned null';
        }
        sock.destroy();
        srv.close(resolve);
      });
      srv.on('error', reject);
      srv.listen(sockPath, () => {
        const c = connect(sockPath);
        c.on('error', reject);
        c.once('connect', () => c.destroy());
      });
    });
  } catch (e) {
    error = String(e?.message || e);
    selfTestPassed = false;
  }

  try { unlink(sockPath); } catch { /* best effort */ }
  try { unlink(sockDir); } catch { /* best effort */ }

  return {
    platform: PLATFORM,
    mechanism,
    compilerAvailable: true,
    selfTestPassed,
    selfTestPid,
    error,
  };
}
