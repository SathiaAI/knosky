// KnoSky ledger-anchored freshness attestation (SAT-444, SAT-474).
//
// Closes the clock-skew / key-resurrection gap by basing freshness on the
// repository's commit count rather than wall-clock time.  A `ledger_seq`
// is a monotone integer — the number of commits reachable from HEAD —
// which cannot be fabricated by adjusting the system clock and can only
// decrease when history is rewritten (the ledger-truncation attack caught
// by the high-water-mark guard in core/ledger.mjs).
//
// SAT-474: validateFreshnessWithHwm() routes through the *persisted*
// checkAndAdvance() guard (core/ledger.mjs) so that the rollback defence
// survives process restarts.  validateFreshness() is retained for callers
// that manage their own in-memory lastSeq (e.g. protocol-spec validation).
// Pure Node stdlib, ESM — no third-party dependencies.

import { execFileSync } from 'node:child_process';
import { checkAndAdvance } from './ledger.mjs';
import { MAX_PLAUSIBLE_LEDGER_SEQ } from './constants.mjs';

// ---------------------------------------------------------------------------
// extractLedgerSeq — read the ledger_seq stored in a city envelope
// ---------------------------------------------------------------------------

/**
 * Extract the `ledger_seq` from a city envelope or any artifact that carries
 * one.  Returns null when absent, not a non-negative integer, or implausibly
 * large (see MAX_PLAUSIBLE_LEDGER_SEQ).
 *
 * @param {object} obj  City envelope or comparable artifact object.
 * @returns {number|null}
 */
export function extractLedgerSeq(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const seq = obj.ledger_seq;
  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 0) return null;
  if (seq > MAX_PLAUSIBLE_LEDGER_SEQ) return null;
  return seq;
}

// ---------------------------------------------------------------------------
// computeLedgerSeq — derive a ledger_seq from a git repo on disk
// ---------------------------------------------------------------------------

/**
 * Compute the ledger_seq for `root` by counting all commits reachable from
 * HEAD (`git rev-list --count HEAD`).  Returns 0 when git is unavailable or
 * the directory has no commit history (e.g. a brand-new repo with no commits).
 *
 * @param {string} root  Absolute path to the git working tree.
 * @returns {number}  Non-negative integer commit count.
 */
export function computeLedgerSeq(root) {
  try {
    const out = execFileSync(
      'git',
      ['rev-list', '--count', 'HEAD'],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    const n = parseInt(out, 10);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    // No git / no commits / non-repo directory → 0  (safe: sequence starts fresh)
    return 0;
  }
}

// ---------------------------------------------------------------------------
// checkHighWaterMark — V13 guard against ledger-truncation attack
// ---------------------------------------------------------------------------

/**
 * High-water-mark guard (V13).
 *
 * Returns `{ ok: true }` when `newSeq` is strictly greater than `lastSeq`,
 * meaning the city has advanced — its ledger has grown (or this is the first
 * load, indicated by `lastSeq === null`).
 *
 * Returns `{ ok: false, reason }` when `newSeq` is ≤ `lastSeq`, which means
 * the ledger has been truncated or replayed — a potential key-resurrection or
 * rollback attack.  Callers MUST treat stale/equal as suspicious.
 *
 * @param {number|null} lastSeq  Previously accepted ledger_seq, or null on
 *                               first load (unconditionally accepted).
 * @param {number|null} newSeq   Ledger_seq from the incoming artifact, or
 *                               null when absent (treated as 0 — conservative).
 * @returns {{ ok: boolean, reason?: string }}
 */
export function checkHighWaterMark(lastSeq, newSeq) {
  // Treat missing seq as 0 — conservative: an artifact with no ledger anchoring
  // is as trustworthy as a brand-new repo.
  const effective = (typeof newSeq === 'number' && Number.isInteger(newSeq) && newSeq >= 0)
    ? newSeq
    : 0;

  // First load: no last seq to compare against — unconditionally accept.
  if (lastSeq === null || lastSeq === undefined) {
    return { ok: true };
  }

  if (typeof lastSeq !== 'number' || !Number.isInteger(lastSeq) || lastSeq < 0) {
    // Corrupt lastSeq — treat it as 0 (reset the watermark)
    return { ok: true };
  }

  if (effective > lastSeq) {
    return { ok: true };
  }

  // equal: rolled back to same point (replay) or no new commits
  // less: ledger truncation — history was rewritten
  const direction = effective < lastSeq ? 'ledger truncated' : 'ledger not advanced';
  return {
    ok: false,
    reason:
      direction +
      ': incoming ledger_seq ' + effective +
      ' is not greater than last accepted ' + lastSeq +
      ' — possible rollback or key-resurrection attack',
  };
}

// ---------------------------------------------------------------------------
// validateFreshness — full attestation check for an incoming artifact
// ---------------------------------------------------------------------------

/**
 * Validate the freshness of an incoming artifact against an optional stored
 * high-water mark.
 *
 * Combines:
 *  (1) structural check: `ledger_seq` is present and a non-negative integer
 *  (2) V13 high-water-mark guard: `ledger_seq` must exceed the last accepted
 *      value (pass `null` on first load to skip this check)
 *
 * @param {object}      artifact  City envelope or protocol artifact.
 * @param {number|null} lastSeq   Last accepted ledger_seq (null = first load).
 * @returns {{ ok: boolean, ledger_seq: number|null, errors: string[] }}
 */
export function validateFreshness(artifact, lastSeq = null) {
  const errors = [];
  const seq = extractLedgerSeq(artifact);

  if (seq === null) {
    errors.push('ledger_seq is missing or not a non-negative integer');
  }

  const hwm = checkHighWaterMark(lastSeq, seq);
  if (!hwm.ok) {
    errors.push(hwm.reason);
  }

  return { ok: errors.length === 0, ledger_seq: seq, errors };
}

// ---------------------------------------------------------------------------
// validateFreshnessWithHwm — persisted-HWM variant (SAT-474)
// ---------------------------------------------------------------------------

/**
 * Validate freshness through the **persisted** high-water-mark guard
 * (`core/ledger.mjs` `checkAndAdvance`).
 *
 * Unlike `validateFreshness`, this function reads and updates the HWM from
 * `hwmPath` on disk, so the rollback defence is durable across process
 * restarts.  Callers that previously maintained an in-memory `lastSeq` and
 * passed it to `validateFreshness` should migrate to this function and a
 * stable `hwmPath` in their data directory.
 *
 * Semantics of the persisted guard (from `checkAndAdvance`):
 *   - seq STRICTLY LESS than HWM → rejected (anti-truncation guard)
 *   - seq EQUAL to HWM           → accepted (idempotent replay)
 *   - seq GREATER than HWM       → accepted and HWM advanced
 *
 * @param {object} artifact  City envelope or protocol artifact.
 * @param {string} hwmPath   Path to the independently-persisted HWM file.
 * @returns {{ ok: boolean, ledger_seq: number|null, errors: string[] }}
 */
export function validateFreshnessWithHwm(artifact, hwmPath) {
  const errors = [];
  const seq = extractLedgerSeq(artifact);

  if (seq === null) {
    errors.push('ledger_seq is missing or not a non-negative integer');
    // Cannot call checkAndAdvance with a null seq — return early.
    return { ok: false, ledger_seq: null, errors };
  }

  const result = checkAndAdvance(seq, hwmPath);
  if (!result.ok) {
    errors.push(result.error);
  }

  return { ok: errors.length === 0, ledger_seq: seq, errors };
}
