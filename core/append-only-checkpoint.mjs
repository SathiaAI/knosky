// KnoSky F0.2 — Append-only checkpoint (SAT-546).
//
// Writes every ledger event to a secondary JSONL checkpoint file that the
// evaluator process can only append to — it cannot delete or overwrite earlier
// records.  This gives a second source of truth that a privileged local user
// would need to destroy to tamper with the record.
//
// OS-level append-only protection (best-effort, silently skipped when the
// operation is not available or the caller lacks privilege):
//
//   Linux   : chattr +a (requires CAP_LINUX_IMMUTABLE; typically needs root
//             or sudo, but conferred when the daemon is started with elevated
//             rights).  Only sets the attribute — never reads back to verify,
//             so the evaluator itself never needs elevated rights after the
//             initial chattr call.
//   macOS   : chflags uappnd (user-owned append-only flag; can be set by the
//             file's owner without root).
//
// The module NEVER attempts to *remove* the attribute — that would require
// the same elevated rights and would defeat the purpose.
//
// The evaluator calls `appendCheckpointEntry(path, entry)` on every ledger
// write via the optional `checkpointPath` parameter added to `checkAndAdvance`
// (core/ledger.mjs) in SAT-561.  It uses
// `O_WRONLY | O_APPEND | O_CREAT` (no truncation flag) so every open is an
// append even without the OS attribute.  The OS attribute provides the
// additional guarantee that a privileged process using O_WRONLY without
// O_APPEND (or `unlink`) is also blocked.
//
// SEPARATION OF CONCERNS (ticket round-3 clarification; PR #62 review, round
// 5: hardened from a directory-level convention into a PACKAGE-BOUNDARY
// fact -- the export daemon is not just a different folder, it is a
// completely separate package/repo this repo has zero dependency on):
//   - This module is the ONLY checkpoint surface the evaluator touches.
//   - Any export to a remote destination is handled by the separate
//     knosky-export-daemon package (github.com/SathiaAI/knosky-export-daemon)
//     -- an unsandboxed, opt-in daemon an organization must deliberately
//     install; this repo never imports, requires, or ships any part of it,
//     and gains no network capability in any configuration regardless of
//     whether that package is installed elsewhere.
//
// Pure Node stdlib, ESM — no third-party dependencies.

import {
  openSync, appendFileSync, closeSync,
  mkdirSync, existsSync,
} from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

// Platform string, cached at module load.
const PLATFORM = platform();

// ---------------------------------------------------------------------------
// setAppendOnlyAttribute — best-effort OS attribute
// ---------------------------------------------------------------------------

/**
 * Attempt to set the OS append-only attribute on `filePath`.
 *
 * Returns a structured result so callers can log the outcome without the
 * evaluator needing to catch exceptions.  The attribute is advisory — failure
 * does NOT prevent writes via `appendCheckpointEntry`; the O_APPEND open flag
 * already ensures append semantics at the process level.
 *
 * @param {string} filePath  Absolute path to the checkpoint file.
 * @returns {{ ok: boolean, mechanism: string|null, skipped: boolean, error: string|null }}
 */
export function setAppendOnlyAttribute(filePath) {
  // PR #62 round-7 fix: enforce the documented contract (filePath must be an
  // absolute path) before this reaches a privileged child process at all --
  // rejects relative paths, empty strings, and non-string input up front.
  if (typeof filePath !== 'string' || filePath.length === 0 || !isAbsolute(filePath)) {
    return {
      ok: false,
      mechanism: null,
      skipped: true,
      error: 'invalid filePath: must be a non-empty absolute path',
    };
  }

  // PR #62 round-7 fix: distinguish signal-based termination (process was
  // killed) from a plain non-zero exit, so operators can tell them apart
  // instead of a single generic error message.
  const describeFailure = (r, cmdLabel) => {
    if (r.error) return String(r.error.message || r.error);
    if (r.signal !== null) return `${cmdLabel} was terminated by signal ${r.signal}`;
    return `${cmdLabel} exited with status ${r.status}`;
  };

  if (PLATFORM === 'linux') {
    // chattr +a — requires CAP_LINUX_IMMUTABLE; best-effort
    const r = spawnSync('chattr', ['+a', filePath], {
      stdio: 'ignore',
      timeout: 5000,
    });
    if (r.error || r.status !== 0 || r.signal !== null) {
      return {
        ok: false,
        mechanism: 'chattr+a',
        skipped: false,
        error: describeFailure(r, 'chattr'),
      };
    }
    return { ok: true, mechanism: 'chattr+a', skipped: false, error: null };
  }

  if (PLATFORM === 'darwin') {
    // chflags uappnd — settable by the file owner, no root needed
    const r = spawnSync('chflags', ['uappnd', filePath], {
      stdio: 'ignore',
      timeout: 5000,
    });
    if (r.error || r.status !== 0 || r.signal !== null) {
      return {
        ok: false,
        mechanism: 'chflags-uappnd',
        skipped: false,
        error: describeFailure(r, 'chflags'),
      };
    }
    return { ok: true, mechanism: 'chflags-uappnd', skipped: false, error: null };
  }

  // Unsupported platform — skip silently.
  return { ok: false, mechanism: null, skipped: true, error: null };
}

// ---------------------------------------------------------------------------
// openCheckpoint — create & protect the checkpoint file on first use
// ---------------------------------------------------------------------------

/**
 * Ensure the checkpoint file at `checkpointPath` exists, applying the
 * OS append-only attribute immediately after creation.
 *
 * Call this once at process startup (before calling `appendCheckpointEntry`).
 * Safe to call on a file that already exists — the OS attribute is only
 * (re-)applied on first creation, since chattr+a/chflags-uappnd persist on
 * the inode and do not need re-setting on every idempotent re-open.
 *
 * @param {string} checkpointPath  Path to the JSONL checkpoint file.
 * @returns {{ created: boolean, attributeResult: object }}
 *   `created` is true if this call created the file (false if it pre-existed).
 *   `attributeResult` is the result of {@link setAppendOnlyAttribute}.
 */
export function openCheckpoint(checkpointPath) {
  const dir = dirname(checkpointPath);
  mkdirSync(dir, { recursive: true });

  const created = !existsSync(checkpointPath);
  if (created) {
    // O_CREAT | O_WRONLY — create the empty file without truncating anything.
    const fd = openSync(checkpointPath, 'a');
    closeSync(fd);
  }

  // PR #62 round-7 fix: only set the OS attribute on first creation. Both
  // chattr +a and chflags uappnd are persistent flags on the inode -- they
  // do not need re-applying on every idempotent re-open, and doing so spawned
  // an unnecessary child process on every call (flagged as a resource-use
  // concern for a function that may be called repeatedly during a process's
  // lifetime).
  const attributeResult = created
    ? setAppendOnlyAttribute(checkpointPath)
    : { ok: true, mechanism: null, skipped: true, error: null };
  return { created, attributeResult };
}

// ---------------------------------------------------------------------------
// appendCheckpointEntry — the hot-path writer
// ---------------------------------------------------------------------------

/**
 * Append one checkpoint record to the JSONL file.
 *
 * Each record is written as a single JSON line followed by `\n`.  The open
 * mode is always `O_WRONLY | O_APPEND | O_CREAT` (via Node's `'a'` flag) so
 * the process cannot overwrite or truncate the file even if the OS attribute
 * was not successfully applied.
 *
 * The function is intentionally synchronous — checkpoint writes must be
 * durable before the evaluator signals success to the caller.
 *
 * @param {string} checkpointPath  Path to the JSONL checkpoint file.
 * @param {object} entry           Record to append.  Must be JSON-serialisable.
 *   Conventional fields:
 *     `seq`          — ledger sequence number (non-negative integer).
 *     `event`        — event type string (e.g. `'ledger_state'`, `'policy_eval'`).
 *     `ts`           — ISO-8601 timestamp string (caller-supplied; not auto-added).
 *     `payload_hash` — SHA-256 hex of the event payload (for F2 chain linkage).
 * @throws {TypeError}  When `entry` cannot be serialised to JSON.
 * @throws {Error}      On filesystem I/O errors.
 */
export function appendCheckpointEntry(checkpointPath, entry) {
  const line = JSON.stringify(entry) + '\n';
  // 'a' flag = O_WRONLY | O_APPEND | O_CREAT — never truncates.
  appendFileSync(checkpointPath, line, { encoding: 'utf8', flag: 'a' });
}

// ---------------------------------------------------------------------------
// Export-daemon isolation sentinel
// ---------------------------------------------------------------------------

/**
 * Symbolic constant confirming that this module (the evaluator-side checkpoint
 * writer) is intentionally separate from the export daemon.
 *
 * Any code path that imports both this module AND `core/export-daemon.mjs`
 * within the evaluator process is a design violation — the evaluator must
 * never gain network capability.  Tests import this constant to assert the
 * architectural separation.
 */
export const EVALUATOR_NO_NETWORK_SENTINEL = 'f02_evaluator_local_only';
