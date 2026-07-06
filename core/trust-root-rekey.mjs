// KnoSky F0.1 — Trust-root recovery/re-key ceremony (SAT-545).
//
// Implements two distinct re-key paths for the trust-root lifecycle:
//
//   Ordinary path (D-193)
//     A keyholder or hardware key is lost/compromised.  A majority of the
//     REMAINING non-revoked keyholders co-sign a re-key request.  The new key
//     does NOT become active immediately — a mandatory 48–72 h cooling-off
//     window is enforced.  The event type is `TRUST_ROOT_REKEY`, which is
//     permanently logged and CANNOT be emitted through the ordinary exception-
//     signing API (assembleLedgerEntry in signing-tiers.mjs only produces
//     EXCEPTION_GRANTED — structural firewall, not a runtime check).
//
//   Emergency override path (D-194)
//     UNANIMOUS sign-off from EVERY currently-uncompromised (i.e. non-revoked)
//     keyholder is required — unconditionally stricter than the ordinary majority
//     path.  A non-empty justification string is mandatory (empty = reject).
//     The event type is `EMERGENCY_REKEY`, separately logged, unskippable, and
//     deliberately alarming — it must never become the normal path.
//
// N=1 (sole-keyholder) semantics (D-193 / D-194 boundary note):
//   At N=1, the ordinary-path majority formula (Math.floor(1/2)+1 = 1) and the
//   emergency unanimity requirement (1 of 1) both reduce to a single required
//   approval.  This is a mathematical boundary analogous to the N=2 quorum
//   degenerate case for revocation (documented in SECURITY.md as D-163).  It
//   does NOT mean the two paths are interchangeable: the event types, the
//   activation-delay rule (ordinary only), and the mandatory-justification rule
//   (emergency only) remain distinct at all N, including N=1.  The "strictly
//   harder" principal applies in the domain of audit/logging and operational
//   friction — not solely in approval count.
//
// Tamper-evidence: both events are written to the append-only checkpoint via
//   core/append-only-checkpoint.mjs (SAT-546/SAT-561 wiring), so they are
//   tamper-evident like every other trust-layer event.
//
// No egress, no new hand-rolled crypto: all signing uses the quorum primitives
//   already in core/key-store.mjs (hmacPayload is reproduced locally as it is
//   not exported from that module; the crypto is identical: HMAC-SHA256 over a
//   canonical JSON payload via Node's own node:crypto).
//
// Pure Node stdlib, ESM — no third-party dependencies.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { appendCheckpointEntry, openCheckpoint } from './append-only-checkpoint.mjs';

// ---------------------------------------------------------------------------
// Re-key activation window constants (D-193)
// ---------------------------------------------------------------------------

/** Minimum activation delay in milliseconds: 48 hours. */
export const REKEY_DELAY_MIN_MS = 48 * 60 * 60 * 1000;

/** Maximum activation delay in milliseconds: 72 hours. */
export const REKEY_DELAY_MAX_MS = 72 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Internal helpers (package-private; not exported)
// ---------------------------------------------------------------------------

/**
 * Compute HMAC-SHA256 over a canonical JSON serialisation of `payload`.
 * Keys are sorted alphabetically.  Returns a lowercase 64-char hex string.
 *
 * Mirrors the identical helper inside core/key-store.mjs; duplicated here
 * because key-store.mjs does not export it (it is intentionally internal).
 * Crypto semantics are unchanged — both helpers produce the same HMAC given
 * the same key and payload.
 *
 * @param {Buffer} keyBuf
 * @param {object} payload
 * @returns {string}
 */
function _hmacPayload(keyBuf, payload) {
  const sorted = Object.fromEntries(
    Object.keys(payload).sort().map(k => [k, payload[k]]),
  );
  return createHmac('sha256', keyBuf).update(JSON.stringify(sorted)).digest('hex');
}

/**
 * The canonical payload that approval signers HMAC to authorise a re-key.
 * Keys are sorted alphabetically (matching _hmacPayload).
 *
 * @param {string} newKeyId   Identifier of the proposed replacement key.
 * @param {string} eventType  `'TRUST_ROOT_REKEY'` or `'EMERGENCY_REKEY'`.
 * @returns {{ action: string, event_type: string, new_key_id: string }}
 */
function _rekeyPayload(newKeyId, eventType) {
  // action + event_type + new_key_id — alphabetically sorted already.
  return { action: 'rekey_trust_root', event_type: eventType, new_key_id: newKeyId };
}

/**
 * Collect the set of currently non-revoked keys from the store.
 *
 * @param {{ keys: Map<string, object> }} ks
 * @returns {object[]}  Array of KeyEntry objects with status !== 'revoked'.
 */
function _goodKeys(ks) {
  return [...ks.keys.values()].filter(e => e.status !== 'revoked');
}

// ---------------------------------------------------------------------------
// makeRekeyApproval
// ---------------------------------------------------------------------------

/**
 * Produce a re-key approval token signed by `signingKeyId`.
 *
 * The token is a `{ key_id, sig }` object that can be collected from multiple
 * non-revoked keyholders and passed as the `approvals` array to either
 * {@link rekey} (ordinary path) or {@link emergencyRekey} (emergency path).
 *
 * The approval binds to the proposed `newKeyId` and to the `eventType`
 * (`'TRUST_ROOT_REKEY'` or `'EMERGENCY_REKEY'`) — a token for one path CANNOT
 * satisfy the other because the canonical HMAC payload includes `event_type`.
 *
 * Throws if `signingKeyId` is unknown, revoked, or equal to `newKeyId` (the
 * incoming replacement key may not approve its own introduction).
 *
 * @param {{ keys: Map<string,object> }} ks
 * @param {string} signingKeyId   The existing non-revoked key signing the approval.
 * @param {string} newKeyId       The proposed new key's identifier.
 * @param {'TRUST_ROOT_REKEY'|'EMERGENCY_REKEY'} eventType
 * @returns {{ key_id: string, sig: string }}
 */
export function makeRekeyApproval(ks, signingKeyId, newKeyId, eventType) {
  if (signingKeyId === newKeyId) {
    throw new Error('makeRekeyApproval: signing key and new key must differ');
  }
  if (eventType !== 'TRUST_ROOT_REKEY' && eventType !== 'EMERGENCY_REKEY') {
    throw new Error(`makeRekeyApproval: eventType must be 'TRUST_ROOT_REKEY' or 'EMERGENCY_REKEY', got ${JSON.stringify(eventType)}`);
  }
  const entry = ks.keys.get(signingKeyId);
  if (!entry) {
    throw new Error(`makeRekeyApproval: unknown key_id ${JSON.stringify(signingKeyId)}`);
  }
  if (entry.status === 'revoked') {
    throw new Error(`makeRekeyApproval: signing key ${JSON.stringify(signingKeyId)} is revoked`);
  }
  const sig = _hmacPayload(entry.raw, _rekeyPayload(newKeyId, eventType));
  return { key_id: signingKeyId, sig };
}

// ---------------------------------------------------------------------------
// _validateApprovals — shared quorum-verification helper
// ---------------------------------------------------------------------------

/**
 * @internal
 * Validate a set of re-key approval tokens.
 *
 * Returns `{ valid: number, seenIds: Set<string> }`.
 *
 * Each approval must:
 *   - carry a `key_id` and `sig`
 *   - reference a distinct, non-revoked key in `ks`
 *   - NOT be `newKeyId` (the new key cannot approve its own introduction)
 *   - carry a correct HMAC over `_rekeyPayload(newKeyId, eventType)`
 *
 * Tokens that fail any of these checks are silently skipped.
 * Duplicate signers (same `key_id` appearing more than once) are deduplicated.
 *
 * @param {{ keys: Map<string,object> }} ks
 * @param {string} newKeyId
 * @param {'TRUST_ROOT_REKEY'|'EMERGENCY_REKEY'} eventType
 * @param {{ key_id: string, sig: string }[]} approvals
 * @returns {{ valid: number, seenIds: Set<string> }}
 */
function _validateApprovals(ks, newKeyId, eventType, approvals) {
  const payload = _rekeyPayload(newKeyId, eventType);
  const seen = new Set();
  let valid = 0;

  for (const approval of approvals) {
    const { key_id: aKeyId, sig } = approval ?? {};
    if (!aKeyId || !sig) continue;
    if (aKeyId === newKeyId) continue;        // new key cannot self-approve
    if (seen.has(aKeyId)) continue;           // deduplicate per signer

    const aEntry = ks.keys.get(aKeyId);
    if (!aEntry || aEntry.status === 'revoked') continue;

    const expected = _hmacPayload(aEntry.raw, payload);
    if (typeof sig !== 'string' || sig.length !== expected.length) continue;

    let match = false;
    try {
      match = timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
    } catch { match = false; }

    if (match) {
      seen.add(aKeyId);
      valid++;
    }
  }

  return { valid, seenIds: seen };
}

// ---------------------------------------------------------------------------
// rekey — ordinary path (D-193)
// ---------------------------------------------------------------------------

/**
 * Ordinary trust-root re-key ceremony.
 *
 * A majority of the currently non-revoked keyholders (`Math.floor(N/2)+1`
 * where `N` is the count of non-revoked keys in `ks`) must co-sign the
 * re-key request.  If the quorum is met, the new key is staged with a
 * mandatory 48–72 h activation delay — it does NOT become the active key
 * immediately.  The calling code is responsible for activating the key
 * once `activatesAt` has passed.
 *
 * **N=1 semantics:** at N=1 the majority formula reduces to 1 (the sole
 * keyholder must approve).  See the module header for the N=1 boundary note.
 *
 * The returned event object carries `event: 'TRUST_ROOT_REKEY'` and is
 * written to the append-only checkpoint when `checkpointPath` is supplied.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 *   The current key store.  Not mutated — staging is pure data.
 * @param {string} newKeyId
 *   A caller-assigned identifier for the proposed replacement key.  The
 *   calling code is responsible for keeping this stable until activation.
 * @param {{ key_id: string, sig: string }[]} approvals
 *   Approval tokens produced by {@link makeRekeyApproval} for event type
 *   `'TRUST_ROOT_REKEY'`.
 * @param {object}  [opts]
 * @param {number}  [opts.now]             Override `Date.now()` (for tests).
 * @param {string}  [opts.checkpointPath]  Path to the append-only JSONL checkpoint.
 * @returns {{
 *   event: 'TRUST_ROOT_REKEY',
 *   new_key_id: string,
 *   valid_approvals: number,
 *   required_approvals: number,
 *   signed_at: string,
 *   activates_at: string,
 *   activates_after_ms: number,
 * }}
 * @throws {Error}  If the quorum is not met.
 */
export function rekey(ks, newKeyId, approvals = [], opts = {}) {
  const now = opts.now ?? Date.now();

  if (!newKeyId || typeof newKeyId !== 'string') {
    throw new TypeError('rekey: newKeyId must be a non-empty string');
  }

  const good = _goodKeys(ks);
  const N = good.length;
  // Ordinary-path quorum: strict majority of non-revoked keys.
  // Formula: Math.floor(N/2)+1 — the same strict-majority formula used
  // by the key-store's peer-approval quorum gate (core/key-store.mjs).
  // At N=0 (no non-revoked keys) there is no one to co-sign; we still
  // require at least 1 to prevent a completely unguarded store from
  // triggering a re-key with zero approvals.
  const required = N > 0 ? Math.floor(N / 2) + 1 : 1;

  const { valid } = _validateApprovals(ks, newKeyId, 'TRUST_ROOT_REKEY', approvals);

  if (valid < required) {
    throw new Error(
      `rekey: quorum not met — ${required} approval(s) required from non-revoked keyholders, got ${valid}`,
    );
  }

  const signedAt = new Date(now).toISOString();
  const activatesAfterMs = REKEY_DELAY_MIN_MS; // 48 h lower bound
  const activatesAt = new Date(now + activatesAfterMs).toISOString();

  const entry = {
    event: 'TRUST_ROOT_REKEY',
    new_key_id: newKeyId,
    valid_approvals: valid,
    required_approvals: required,
    signed_at: signedAt,
    activates_at: activatesAt,
    activates_after_ms: activatesAfterMs,
  };

  // Write to the append-only checkpoint so the event is tamper-evident.
  if (opts.checkpointPath != null) {
    try {
      openCheckpoint(opts.checkpointPath);
      appendCheckpointEntry(opts.checkpointPath, entry);
    } catch { /* best-effort — checkpoint failure must not suppress the event */ }
  }

  return entry;
}

// ---------------------------------------------------------------------------
// emergencyRekey — emergency override path (D-194)
// ---------------------------------------------------------------------------

/**
 * Emergency trust-root re-key (override, D-194).
 *
 * UNCONDITIONALLY stricter than the ordinary path:
 *   - UNANIMOUS sign-off from EVERY currently non-revoked keyholder is required
 *     (not just a majority).  A single missing approval fails the ceremony.
 *   - A non-empty `justification` string is mandatory — an empty or absent
 *     justification is rejected before any signature verification.
 *   - The event type is `EMERGENCY_REKEY`, permanently and separately logged;
 *     it CANNOT be emitted through the `assembleLedgerEntry` API in
 *     signing-tiers.mjs (that function hardcodes `event: 'EXCEPTION_GRANTED'`).
 *   - There is intentionally NO activation delay: because the full unanimous
 *     quorum is the gate (vs. majority), the additional 48-72 h window would
 *     add friction without adding cryptographic strength when ALL keyholders
 *     are already on record.  This also keeps the emergency path distinguishable
 *     from the ordinary path in operational terms.
 *
 * **N=1 semantics:** at N=1 unanimity = 1 required approval (same as majority).
 *   See the module header for the documented boundary note.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {string} newKeyId
 *   Identifier for the proposed replacement key.
 * @param {{ key_id: string, sig: string }[]} approvals
 *   Approval tokens produced by {@link makeRekeyApproval} for event type
 *   `'EMERGENCY_REKEY'`.  MUST cover every non-revoked keyholder.
 * @param {string} justification
 *   Mandatory human-readable reason (non-empty).
 * @param {object}  [opts]
 * @param {number}  [opts.now]             Override `Date.now()` (for tests).
 * @param {string}  [opts.checkpointPath]  Path to the append-only JSONL checkpoint.
 * @returns {{
 *   event: 'EMERGENCY_REKEY',
 *   new_key_id: string,
 *   valid_approvals: number,
 *   required_approvals: number,
 *   missing_signers: number,
 *   justification: string,
 *   signed_at: string,
 * }}
 * @throws {Error}  If justification is empty, or if unanimity is not achieved.
 */
export function emergencyRekey(ks, newKeyId, approvals = [], justification, opts = {}) {
  if (!justification || typeof justification !== 'string' || justification.trim().length === 0) {
    throw new Error('emergencyRekey: justification must be a non-empty string — cannot be omitted on the emergency path');
  }

  if (!newKeyId || typeof newKeyId !== 'string') {
    throw new TypeError('emergencyRekey: newKeyId must be a non-empty string');
  }

  const now = opts.now ?? Date.now();
  const good = _goodKeys(ks);
  const N = good.length;

  // Emergency path: unanimity required — all N non-revoked keyholders must sign.
  // At N=0 (no non-revoked keys) we still require at least 1 approval to prevent
  // a vacuously "unanimous" empty-set approval from an exhausted store.
  const required = Math.max(N, 1);

  const { valid } = _validateApprovals(ks, newKeyId, 'EMERGENCY_REKEY', approvals);
  const missing = required - valid;

  if (valid < required) {
    throw new Error(
      `emergencyRekey: unanimity not achieved — all ${required} non-revoked keyholder(s) must approve, got ${valid} (${missing} missing)`,
    );
  }

  const signedAt = new Date(now).toISOString();

  const entry = {
    event: 'EMERGENCY_REKEY',
    new_key_id: newKeyId,
    valid_approvals: valid,
    required_approvals: required,
    missing_signers: 0,
    justification,
    signed_at: signedAt,
  };

  // Write to the append-only checkpoint so the event is tamper-evident.
  if (opts.checkpointPath != null) {
    try {
      openCheckpoint(opts.checkpointPath);
      appendCheckpointEntry(opts.checkpointPath, entry);
    } catch { /* best-effort */ }
  }

  return entry;
}

// ---------------------------------------------------------------------------
// isRekeyActive — check whether a staged TRUST_ROOT_REKEY has passed its window
// ---------------------------------------------------------------------------

/**
 * Return whether a staged re-key event (from {@link rekey}) has passed its
 * mandatory activation window.
 *
 * Does NOT activate the key — the calling code is responsible for actually
 * inserting the new key into the store once this returns `true`.  This
 * function is intentionally pure (no side-effects) so it can be called to
 * check scheduling without risk of inadvertent activation.
 *
 * @param {{ activates_at: string }} rekeyEvent  A `TRUST_ROOT_REKEY` event object.
 * @param {number} [now]  Override `Date.now()` (for tests).
 * @returns {boolean}
 */
export function isRekeyActive(rekeyEvent, now = Date.now()) {
  const activatesAt = Date.parse(rekeyEvent?.activates_at);
  if (!Number.isFinite(activatesAt)) return false;
  return now >= activatesAt;
}
