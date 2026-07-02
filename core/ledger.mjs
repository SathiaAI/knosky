// KnoSky ledger high-water-mark guard (SAT-443 / V13).
//
// Independently persists the highest-seen ledger sequence number in a
// dedicated file (separate from the ledger itself) so that a truncation
// attack that replaces the whole ledger cannot roll back the sequence.
//
// Anti-truncation rule (D-164 TUF-evolution): a ledger state whose sequence
// number is STRICTLY LOWER than the persisted high-water mark is refused.
//
// The HWM file is a minimal JSON document:  { "ledger_hwm": <integer> }
// It is intentionally kept narrow — no ledger content lives here.
//
// Pure Node stdlib, ESM — no third-party dependencies.

import { readFileSync, writeFileSync, renameSync, mkdirSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { dirname } from 'node:path';
import { MAX_PLAUSIBLE_LEDGER_SEQ } from './constants.mjs';

// ---------------------------------------------------------------------------
// HWM file I/O
// ---------------------------------------------------------------------------

/**
 * Read the persisted high-water mark from `hwmPath`.
 * Returns 0 when the file does not exist (first run — any sequence is valid).
 * Throws on I/O errors other than ENOENT, and on malformed content (fail-closed).
 *
 * @param {string} hwmPath  Path to the independently-persisted HWM file.
 * @returns {number}  Stored sequence number (non-negative integer).
 */
export function readHwm(hwmPath) {
  let text;
  try {
    text = readFileSync(hwmPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return 0;
    throw err; // permission error — fail-closed
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`ledger HWM file is not valid JSON: ${hwmPath}`);
  }
  if (!Number.isInteger(parsed.ledger_hwm) || parsed.ledger_hwm < 0) {
    throw new Error(
      `ledger HWM file has invalid ledger_hwm: ${JSON.stringify(parsed.ledger_hwm)} in ${hwmPath}`,
    );
  }
  return parsed.ledger_hwm;
}

/**
 * Persist `seq` as the current high-water mark.
 * Creates parent directories if they do not already exist.
 *
 * @param {string} hwmPath  Path to write.
 * @param {number} seq      New HWM value (non-negative integer).
 */
export function writeHwm(hwmPath, seq) {
  if (!Number.isInteger(seq) || seq < 0) {
    throw new TypeError(
      `ledger_hwm must be a non-negative integer, got: ${JSON.stringify(seq)}`,
    );
  }
  const dir = dirname(hwmPath);
  mkdirSync(dir, { recursive: true });
  // Atomic write: write to a sibling temp file, then rename into place.
  // This prevents a partial/corrupt HWM file on crash or power loss —
  // critical because a corrupt HWM would either silently reset the guard
  // (ENOENT path) or throw (parse error), both of which weaken security.
  const tmp = hwmPath + '.tmp';
  writeFileSync(tmp, JSON.stringify({ ledger_hwm: seq }) + '\n', 'utf8');
  // fsync the temp file's contents before rename — otherwise the rename can
  // land on disk before the data it points to does (SAT-474 hardening review).
  const tmpFd = openSync(tmp, 'r');
  try { fsyncSync(tmpFd); } finally { closeSync(tmpFd); }
  renameSync(tmp, hwmPath);
  // fsync the containing directory so the rename itself (the directory-entry
  // update) is durable — without this, a crash immediately after renameSync
  // can leave the old HWM file name visible on some filesystems/mount options
  // (e.g. ext4 without data=ordered). POSIX-specific guarantee; best-effort
  // on platforms where directory fsync isn't supported.
  try {
    const dirFd = openSync(dir, 'r');
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  } catch { /* best-effort; not all platforms support directory fsync */ }
}

// ---------------------------------------------------------------------------
// checkAndAdvance — the core anti-truncation guard
// ---------------------------------------------------------------------------

/**
 * Enforce the high-water-mark invariant for incoming ledger state.
 *
 * Reads the persisted HWM from `hwmPath`, then applies the anti-truncation
 * rule:
 *   - `seq` STRICTLY LESS than HWM → refuse. The HWM file is NOT updated.
 *   - `seq` EQUAL to HWM           → accept (idempotent replay).  HWM written.
 *   - `seq` GREATER than HWM       → accept and advance.           HWM written.
 *
 * Returning `{ ok: false }` means the caller must treat the incoming ledger
 * state as invalid and stop processing — it must not be applied or surfaced
 * as authoritative.
 *
 * @param {number} seq      Claimed sequence number from the incoming ledger state.
 * @param {string} hwmPath  Path to the independently-persisted HWM file.
 * @returns {{ ok: boolean, seq: number, hwm: number, error?: string }}
 */
// Second layer of defense: enforced here too (not only in
// core/freshness.mjs's extractLedgerSeq) so checkAndAdvance is safe even if
// called directly. Imports the single source of truth from constants.mjs
// (a dependency-free module) so the two layers cannot silently diverge.
export function checkAndAdvance(seq, hwmPath) {
  if (!Number.isInteger(seq) || seq < 0 || seq > MAX_PLAUSIBLE_LEDGER_SEQ) {
    return {
      ok: false,
      seq,
      hwm: -1,
      error: `seq must be a non-negative integer no greater than ${MAX_PLAUSIBLE_LEDGER_SEQ}, got: ${JSON.stringify(seq)}`,
    };
  }

  const hwm = readHwm(hwmPath);

  if (seq < hwm) {
    // Anti-truncation guard: incoming sequence is below the highest-seen mark.
    // Do NOT update the file — the old (higher) mark must remain authoritative.
    return {
      ok: false,
      seq,
      hwm,
      error: `ledger sequence ${seq} is below the high-water mark ${hwm} — refusing (anti-truncation guard)`,
    };
  }

  // seq >= hwm: advance (or re-confirm) the mark.
  writeHwm(hwmPath, seq);
  return { ok: true, seq, hwm };
}
