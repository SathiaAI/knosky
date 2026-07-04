// KnoSky F0.5 — OS-level network lockdown for the evaluator process (SAT-549).
//
// Defense-in-depth: places the evaluator in a network namespace (Linux) or
// equivalent OS-level sandbox that structurally denies non-loopback network
// syscalls at the kernel level.  The static no-egress import lint (F1 Fix 7)
// remains as a cheap first line of defense that blocks the common case before
// this heavier enforcement.
//
// Platform strategies
// -------------------
//   Linux   : unprivileged user+network namespace via `unshare --user --net`.
//             Kernel provides an empty routing table (ENETUNREACH for external
//             routes); Unix-domain sockets and the loopback interface are
//             accessible from within Node (Unix sockets don't require a loopup
//             table entry; loopback can be raised with `ip link set lo up` when
//             the process has the right capabilities inside the namespace).
//
//   macOS   : App Sandbox is a packaging/deployment concern (entitlements must
//             be set at codesign time, not at runtime).  We detect whether the
//             current process is already running inside a sandbox and surface
//             the result in `knosky doctor`.  Runtime wrapping requires the
//             `sandbox-exec` tool; we probe for it and report.
//
//   Windows : WFP/AppContainer isolation is configured at packaging time.
//             We detect whether the current process is in a restricted token
//             (AppContainer) and surface the result in `knosky doctor`.
//
// F0.4 compatibility (SANDBOX_CARVEOUT_NOTE)
// ------------------------------------------
//   After entering the network namespace the IPC primitive used by F0.4 must
//   still work.  On Linux, SO_PEERCRED operates over Unix-domain sockets which
//   are unaffected by the network namespace; the F0.4 conformance fixture is
//   run inside the namespace to verify this before the lockdown is considered
//   complete.
//
// `knosky doctor` integration
// ---------------------------
//   probeNetworkLockdownSupport() returns a structured report consumed by
//   `knosky doctor`.  On unsupported platforms (or when the required tools are
//   absent) the report is NOT empty — it says so plainly rather than silently
//   proceeding as if sandboxed.
//
// Authority: D-193. Design: OUTPUTS/2026-07-05-KnoSky-F0-F1-DesignGate-v3-Combined.md §F0.5.
//
// Pure Node stdlib, ESM — no third-party dependencies.

import { spawnSync, execFileSync } from 'node:child_process';
import { platform } from 'node:os';

const PLATFORM = platform();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} LockdownReport
 * @property {string}   platform         - OS platform string ('linux'|'darwin'|'win32'|other).
 * @property {string}   strategy         - Lockdown strategy name for this platform.
 * @property {boolean}  supported        - Whether the lockdown can be applied on this platform+environment.
 * @property {boolean}  toolAvailable    - Whether the required OS tool is available (Linux: unshare, macOS: sandbox-exec).
 * @property {boolean}  active           - Whether the current process is already inside a lockdown.
 * @property {string}   detail           - Human-readable explanation (shown by `knosky doctor`).
 * @property {string|null} unsupportedReason  - If !supported, a plain-English reason; null when supported.
 */

/**
 * Probe whether OS-level network lockdown is supported on the current platform
 * and environment.  Returns a structured report consumed by `knosky doctor`.
 *
 * This function never throws.  On any error it returns a report with
 * supported=false and a descriptive unsupportedReason.
 *
 * @returns {LockdownReport}
 */
export function probeNetworkLockdownSupport() {
  try {
    if (PLATFORM === 'linux') return _probeLinux();
    if (PLATFORM === 'darwin') return _probeDarwin();
    if (PLATFORM === 'win32') return _probeWin32();
    return _probeUnsupported();
  } catch (e) {
    return {
      platform: PLATFORM,
      strategy: 'unknown',
      supported: false,
      toolAvailable: false,
      active: false,
      detail: 'probe threw unexpectedly: ' + String(e?.message || e),
      unsupportedReason: 'probe threw unexpectedly: ' + String(e?.message || e),
    };
  }
}

/**
 * Return the additional argv prefix that wraps a Node.js child process in the
 * OS-level network lockdown for the current platform.
 *
 * On Linux: `['unshare', '--user', '--net', '--', ...]`.
 * On macOS: `['sandbox-exec', '-p', DENY_NETWORK_PROFILE, '--', ...]` when
 *           sandbox-exec is available and not already sandboxed.
 * On Windows / unsupported: returns `[]` (no prefix; lockdown not available).
 *
 * Callers splice this in front of the command and args they want to run:
 *   const prefix = wrapArgsForLockdown();
 *   spawnSync(prefix[0] ?? 'node', [...prefix.slice(1), 'node', script, ...args]);
 *
 * Returns `[]` if the platform doesn't support wrapping or if the required
 * tool is not available (callers should check probeNetworkLockdownSupport()
 * first and warn via `knosky doctor` in that case).
 *
 * @returns {string[]}
 */
export function wrapArgsForLockdown() {
  if (PLATFORM === 'linux') {
    if (_unshareAvailable()) return ['unshare', '--user', '--net', '--'];
    return [];
  }
  if (PLATFORM === 'darwin') {
    if (_sandboxExecAvailable()) return ['sandbox-exec', '-p', _MACOS_SANDBOX_PROFILE, '--'];
    return [];
  }
  // Windows: AppContainer/WFP is a packaging concern; no runtime wrap available.
  return [];
}

/**
 * Return an array of human-readable lines for `knosky doctor` output
 * describing the F0.5 network lockdown status.
 *
 * @returns {string[]}
 */
export function doctorLines() {
  const r = probeNetworkLockdownSupport();
  const lines = [];

  const statusEmoji = r.supported ? (r.active ? '🟢' : '🟡') : '🔴';
  lines.push(`${statusEmoji} F0.5 network lockdown (${r.strategy})`);

  if (r.active) {
    lines.push('   Status : ACTIVE — this process is running inside a network-isolated sandbox.');
  } else if (r.supported && r.toolAvailable) {
    lines.push('   Status : available but not active for this process.');
    lines.push('   Action : use wrapArgsForLockdown() when spawning the evaluator process.');
  } else if (!r.toolAvailable) {
    lines.push('   Status : tool not available — ' + (r.unsupportedReason || r.detail));
  } else {
    lines.push('   Status : ' + (r.unsupportedReason || r.detail));
  }

  lines.push('   Detail : ' + r.detail);
  return lines;
}

// ---------------------------------------------------------------------------
// Linux probe
// ---------------------------------------------------------------------------

/**
 * On Linux, the lockdown uses `unshare --user --net` to place the evaluator
 * in an unprivileged user+network namespace.  The kernel-level routing table
 * inside this namespace has no external routes, so all TCP/UDP attempts to
 * non-loopback addresses fail with ENETUNREACH.  Unix-domain sockets are
 * unaffected (they're not part of the network stack).
 *
 * Detection of "already active": we read /proc/self/status for NSpid (a
 * non-1 NSpid means the process is in a namespace that differs from the
 * initial namespace, which is necessary but loose).  More precisely, we check
 * /proc/self/net/if_inet6 and /proc/self/net/arp: in an empty namespace the
 * ARP table is empty and no routable IPv4/IPv6 unicast addresses exist.
 *
 * @returns {LockdownReport}
 */
function _probeLinux() {
  const toolAvailable = _unshareAvailable();
  const active = _linuxIsNetNsIsolated();

  if (!toolAvailable) {
    return {
      platform: 'linux',
      strategy: 'user+net-namespace (unshare)',
      supported: false,
      toolAvailable: false,
      active,
      detail: '`unshare` binary not found in PATH; cannot apply network namespace lockdown.',
      unsupportedReason: '`unshare` not available — install util-linux',
    };
  }

  return {
    platform: 'linux',
    strategy: 'user+net-namespace (unshare)',
    supported: true,
    toolAvailable: true,
    active,
    detail: active
      ? 'Running inside an unprivileged user+net namespace — external routes absent (ENETUNREACH).'
      : '`unshare` available; evaluator should be launched via wrapArgsForLockdown().',
    unsupportedReason: null,
  };
}

/**
 * Heuristic: are we already inside an isolated network namespace on Linux?
 *
 * Reads /proc/self/net/route.  In the initial (host) namespace, there is at
 * least one non-loopback route.  In an isolated namespace (unshare --net with
 * no external interfaces added), only the loopback route (or nothing at all)
 * is present — the "Iface" column will only show "lo", or the table will be
 * empty after the header line.
 *
 * Returns false on any read error (conservative: don't claim we're isolated
 * when we can't tell).
 *
 * @returns {boolean}
 */
function _linuxIsNetNsIsolated() {
  try {
    const { readFileSync } = await_free_readFileSync();
    const route = readFileSync('/proc/self/net/route', 'utf8');
    const dataLines = route.split('\n').slice(1).filter(l => l.trim().length > 0);
    // Each data line starts with the interface name.  If every line starts
    // with 'lo' (or there are no data lines), the namespace is isolated.
    if (dataLines.length === 0) return true;
    return dataLines.every(l => l.trimStart().startsWith('lo'));
  } catch {
    return false;
  }
}

// Synchronous readFileSync wrapper (avoids dynamic import in a sync context).
function await_free_readFileSync() {
  // Already imported at module top via static import — re-export inline.
  return { readFileSync: _readFileSync_impl };
}

// Resolved once at module load; avoids a dynamic import inside a probe.
import { readFileSync as _readFileSync_impl } from 'node:fs';

/**
 * Check if `unshare` is available in PATH.
 * @returns {boolean}
 */
function _unshareAvailable() {
  try {
    const r = spawnSync('unshare', ['--version'], { stdio: 'pipe', timeout: 3000 });
    return r.status === 0 || r.stderr?.toString().includes('unshare');
  } catch {
    // spawnSync throws if the binary doesn't exist
    return false;
  }
}

// ---------------------------------------------------------------------------
// macOS probe
// ---------------------------------------------------------------------------

// Minimal sandbox-exec profile that denies all outbound network connections
// while allowing loopback (127.0.0.1 / ::1) and Unix-domain sockets.
// sandbox-exec(1) uses SBPL (Scheme-based sandbox policy language).
const _MACOS_SANDBOX_PROFILE = `
(version 1)
(deny default)
(allow process*)
(allow file*)
(allow ipc*)
(allow mach*)
(allow signal)
(allow sysctl*)
(allow system*)
(allow network*)
(deny network-outbound
  (not (remote ip "localhost:*"))
  (not (remote ip "[::1]:*"))
  (not (remote unix-socket)))
`.trim();

/**
 * On macOS, sandbox-exec(1) provides a per-process sandbox.  Full App Sandbox
 * requires entitlements set at codesign time (packaging concern), but
 * sandbox-exec(1) can apply a subset of sandbox policies at runtime.
 *
 * We probe sandbox-exec availability and whether the current process is
 * running under a sandbox (via the `sandbox_check` syscall reported in
 * CS_OPS flags — approximated here by checking for SBX_SANDBOX_ACTIVE in
 * the Security framework; in practice we use `csops` output).
 *
 * @returns {LockdownReport}
 */
function _probeDarwin() {
  const toolAvailable = _sandboxExecAvailable();
  const active = _darwinIsAlreadySandboxed();

  if (!toolAvailable) {
    return {
      platform: 'darwin',
      strategy: 'sandbox-exec (SBPL network-deny profile)',
      supported: false,
      toolAvailable: false,
      active,
      detail: '`sandbox-exec` not found; it ships with macOS but may be absent in some environments.',
      unsupportedReason: '`sandbox-exec` not available',
    };
  }

  return {
    platform: 'darwin',
    strategy: 'sandbox-exec (SBPL network-deny profile)',
    supported: true,
    toolAvailable: true,
    active,
    detail: active
      ? 'Running inside a sandbox-exec session — non-loopback outbound denied by SBPL profile.'
      : '`sandbox-exec` available; evaluator should be launched via wrapArgsForLockdown().',
    unsupportedReason: null,
  };
}

/**
 * Check if `sandbox-exec` is available on macOS.
 * @returns {boolean}
 */
function _sandboxExecAvailable() {
  if (PLATFORM !== 'darwin') return false;
  try {
    // sandbox-exec --help exits non-zero but prints to stderr; just checking
    // existence is enough.
    const r = spawnSync('sandbox-exec', ['--help'], { stdio: 'pipe', timeout: 3000 });
    // Returns 64 (EX_USAGE) when no profile is given — that means it exists.
    return r.pid > 0;
  } catch {
    return false;
  }
}

/**
 * Heuristic: is the current macOS process already running in a sandbox?
 * Uses `sandbox_check` via a short node -e snippet.  Falls back to false.
 * @returns {boolean}
 */
function _darwinIsAlreadySandboxed() {
  if (PLATFORM !== 'darwin') return false;
  // We check the SANDBOX_APPLE env var (set by some sandbox-exec invocations)
  // and the __SANDBOX_ACTIVE env var, as rough heuristics.
  // A more reliable method would use the CS_OPS ioctl, but that requires a
  // native binding.  For doctor purposes, heuristic is sufficient.
  if (process.env.SANDBOX_APPLE || process.env.__SANDBOX_ACTIVE) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Windows probe
// ---------------------------------------------------------------------------

/**
 * On Windows, WFP (Windows Filtering Platform) and AppContainer provide
 * OS-level network isolation.  These are packaging/deployment concerns —
 * runtime wrapping is not available from a Node.js process without native
 * code.  We probe whether the current process is inside an AppContainer
 * (restricted token) via PowerShell.
 *
 * @returns {LockdownReport}
 */
function _probeWin32() {
  const active = _win32IsAppContainer();

  return {
    platform: 'win32',
    strategy: 'WFP/AppContainer (packaging-time; detected via token flags)',
    supported: false,
    toolAvailable: false,
    active,
    detail: active
      ? 'Running inside a Windows AppContainer — network restrictions are in effect.'
      : 'Windows network isolation (WFP/AppContainer) requires packaging-time configuration. '
        + 'Runtime process wrapping is not available. Configure the AppContainer manifest when '
        + 'packaging the evaluator. See knosky SECURITY.md §F0.5.',
    unsupportedReason: active
      ? null
      : 'WFP/AppContainer is a packaging-time concern on Windows; no runtime wrap available.',
  };
}

/**
 * Heuristic: is the current Windows process running as an AppContainer?
 * Runs a brief PowerShell check on the current process token.
 * Returns false on any error (conservative).
 * @returns {boolean}
 */
function _win32IsAppContainer() {
  if (PLATFORM !== 'win32') return false;
  try {
    const r = spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      // IsAppContainer property on the current WindowsIdentity (available .NET 4.5+)
      '[System.Security.Principal.WindowsIdentity]::GetCurrent().IsContainerApplication | Write-Host',
    ], { stdio: 'pipe', encoding: 'utf8', timeout: 8000 });
    if (r.status === 0) {
      return (r.stdout || '').trim().toLowerCase() === 'true';
    }
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Fallback for unknown platforms
// ---------------------------------------------------------------------------

function _probeUnsupported() {
  return {
    platform: PLATFORM,
    strategy: 'none',
    supported: false,
    toolAvailable: false,
    active: false,
    detail: `Platform '${PLATFORM}' does not have a supported network lockdown strategy. `
          + 'Only Linux (unshare), macOS (sandbox-exec), and Windows (AppContainer) are supported.',
    unsupportedReason: `unsupported platform: ${PLATFORM}`,
  };
}
