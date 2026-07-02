// KnoSky signing-key rotation/revocation lifecycle (SAT-446 / Hardening Addendum 2).
// In-process HMAC-SHA256 key store — local-first, no external KMS, no telemetry.
// Callers own persistence; this module is pure in-memory state + crypto.
// Pure Node stdlib, ESM — no third-party dependencies.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Generate a random 16-byte key id as a 32-char lowercase hex string. */
function newKeyId() {
  return randomBytes(16).toString('hex');
}

/**
 * Compute HMAC-SHA256 over a canonical JSON serialisation of `payload`.
 * "Canonical" = top-level keys sorted alphabetically before serialisation.
 * Returns a lowercase 64-char hex string.
 *
 * @param {Buffer} keyBuf
 * @param {object} payload
 * @returns {string}
 */
function hmacPayload(keyBuf, payload) {
  const sorted = Object.fromEntries(
    Object.keys(payload).sort().map(k => [k, payload[k]]),
  );
  return createHmac('sha256', keyBuf).update(JSON.stringify(sorted)).digest('hex');
}

/**
 * Strip `key_id` and `sig` from a manifest object to get the signing payload.
 * These two fields are metadata added *after* signing and must not be part
 * of the signed content.
 *
 * @param {object} manifest
 * @returns {object}
 */
function signingPayload(manifest) {
  const out = {};
  for (const [k, v] of Object.entries(manifest)) {
    if (k === 'key_id' || k === 'sig') continue;
    out[k] = v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// createKeyStore
// ---------------------------------------------------------------------------

/**
 * Create a new in-memory key store with a single initial active key.
 *
 * The returned object has the following shape:
 * ```
 * {
 *   keys:        Map<key_id, KeyEntry>,
 *   activeKeyId: string | null,
 * }
 * ```
 *
 * where each `KeyEntry` is:
 * ```
 * { key_id: string, status: 'active'|'rotated'|'revoked', created_at: string, raw: Buffer }
 * ```
 *
 * @returns {{ keys: Map<string, object>, activeKeyId: string }}
 */
export function createKeyStore() {
  const ks = { keys: new Map(), activeKeyId: null };
  _issueKey(ks);
  return ks;
}

/**
 * @internal
 * Issue a new active key.  Demotes the current active key to `'rotated'` if
 * one exists (rotated keys remain verifiable; only revoked ones are rejected).
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @returns {string}  The newly-issued key_id.
 */
function _issueKey(ks) {
  // Demote any current active key → 'rotated' (still usable for verification).
  if (ks.activeKeyId !== null) {
    const prev = ks.keys.get(ks.activeKeyId);
    if (prev && prev.status === 'active') prev.status = 'rotated';
  }
  const key_id = newKeyId();
  ks.keys.set(key_id, {
    key_id,
    status: 'active',
    created_at: new Date().toISOString(),
    raw: randomBytes(32),
  });
  ks.activeKeyId = key_id;
  return key_id;
}

// ---------------------------------------------------------------------------
// rotateKey
// ---------------------------------------------------------------------------

/**
 * Rotate the signing key: demote the current active key to `'rotated'` and
 * issue a fresh one.
 *
 * Manifests already signed with the old (now `'rotated'`) key remain
 * verifiable.  Only `'revoked'` keys are rejected by {@link verifyManifest}.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @returns {string}  The new active key_id.
 */
export function rotateKey(ks) {
  return _issueKey(ks);
}

// ---------------------------------------------------------------------------
// revokeKey / makeRevocationApproval
// ---------------------------------------------------------------------------

/**
 * The canonical payload that approval signers HMAC to authorise a revocation.
 * Keys are sorted alphabetically (matching {@link hmacPayload}).
 *
 * @param {string} targetKeyId
 * @returns {{ action: string, target_key_id: string }}
 */
function revocationPayload(targetKeyId) {
  // Return in key-sorted order so hmacPayload produces a deterministic digest.
  return { action: 'revoke_key', target_key_id: targetKeyId };
}

/**
 * Produce a revocation-approval token signed by `signingKeyId`.
 *
 * The token is an `{ key_id, sig }` object that can be collected from multiple
 * non-revoked keys and passed as the `approvals` array to {@link revokeKey}
 * to satisfy the quorum requirement.
 *
 * Throws if `signingKeyId` is unknown, already revoked, or equal to
 * `targetKeyId` (a key may not approve its own revocation).
 *
 * @param {{ keys: Map<string,object> }} ks
 * @param {string} signingKeyId
 * @param {string} targetKeyId
 * @returns {{ key_id: string, sig: string }}
 */
export function makeRevocationApproval(ks, signingKeyId, targetKeyId) {
  if (signingKeyId === targetKeyId) {
    throw new Error('makeRevocationApproval: signing key and target key must differ');
  }
  const entry = ks.keys.get(signingKeyId);
  if (!entry) {
    throw new Error(`makeRevocationApproval: unknown key_id ${JSON.stringify(signingKeyId)}`);
  }
  if (entry.status === 'revoked') {
    throw new Error(`makeRevocationApproval: signing key ${JSON.stringify(signingKeyId)} is revoked`);
  }
  const sig = hmacPayload(entry.raw, revocationPayload(targetKeyId));
  return { key_id: signingKeyId, sig };
}

/**
 * Revoke a key by id.
 *
 * After revocation {@link verifyManifest} rejects any manifest that was
 * signed with the revoked key.  Revocation is permanent within a key-store
 * instance.  The operation is idempotent — revoking an already-revoked key
 * is a no-op.
 *
 * If the revoked key was the active signing key, `activeKeyId` is cleared to
 * `null`; callers must {@link rotateKey} to obtain a new active key.
 *
 * **Authorization / quorum gate (SAT-472)**
 *
 * Let `M` be the number of non-revoked keys other than `keyId`.  The
 * required quorum is `Math.floor(M / 2) + 1` (strict majority of peers).
 * When `M === 0` (the target is the only remaining key) no approvals are
 * needed.  Each approval in the `approvals` array must be a valid
 * {@link makeRevocationApproval} token signed by a distinct, non-revoked key
 * that is not `keyId` itself.
 *
 * This ensures a single compromised key cannot unilaterally revoke all
 * others: it can only contribute one approval, which is always less than
 * the strict majority needed when `M >= 2`.
 *
 * Throws if `keyId` is not present in the store or if the quorum is not met.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {string} keyId
 * @param {{ key_id: string, sig: string }[]} [approvals=[]]
 */
export function revokeKey(ks, keyId, approvals = []) {
  if (!ks.keys.has(keyId)) {
    throw new Error(`revokeKey: unknown key_id ${JSON.stringify(keyId)}`);
  }
  const entry = ks.keys.get(keyId);
  if (entry.status === 'revoked') return; // idempotent

  // Count non-revoked peer keys (all keys except the revocation target).
  const peers = [...ks.keys.values()].filter(
    e => e.key_id !== keyId && e.status !== 'revoked',
  );
  const required = peers.length > 0 ? Math.floor(peers.length / 2) + 1 : 0;

  if (required > 0) {
    // Validate each approval token over the canonical revocation payload.
    const payload = revocationPayload(keyId);
    const seen = new Set();
    let valid = 0;

    for (const approval of approvals) {
      const { key_id: aKeyId, sig } = approval ?? {};
      if (!aKeyId || !sig) continue;
      if (aKeyId === keyId) continue;      // target cannot self-approve
      if (seen.has(aKeyId)) continue;      // deduplicate per signer

      const aEntry = ks.keys.get(aKeyId);
      if (!aEntry || aEntry.status === 'revoked') continue;

      const expected = hmacPayload(aEntry.raw, payload);
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

    if (valid < required) {
      throw new Error(
        `revokeKey: quorum not met — ${required} approval(s) required from peer keys, got ${valid}`,
      );
    }
  }

  entry.status = 'revoked';
  // If the active key was just revoked, clear the active pointer.
  if (ks.activeKeyId === keyId) ks.activeKeyId = null;
}

// ---------------------------------------------------------------------------
// signManifest
// ---------------------------------------------------------------------------

/**
 * Sign a manifest with the store's current active key.
 *
 * Returns a shallow copy of `manifest` with two new fields appended:
 * - `key_id` — identifies the signing key for later verification.
 * - `sig`    — lowercase hex HMAC-SHA256 over the canonical signing payload
 *              (all manifest fields except `key_id` and `sig` themselves,
 *              with top-level keys sorted alphabetically).
 *
 * Throws if there is no active key in the store (e.g. after revoking the
 * active key without rotating first).
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {object} manifest   Typically the result of {@link makeIntentManifest}.
 * @returns {object}          Manifest copy decorated with `key_id` and `sig`.
 */
export function signManifest(ks, manifest) {
  const entry = ks.activeKeyId != null ? ks.keys.get(ks.activeKeyId) : null;
  if (!entry || entry.status !== 'active') {
    throw new Error('signManifest: no active key in store — rotate to obtain one');
  }
  const payload = signingPayload(manifest);
  const sig = hmacPayload(entry.raw, payload);
  return { ...manifest, key_id: entry.key_id, sig };
}

// ---------------------------------------------------------------------------
// verifyManifest
// ---------------------------------------------------------------------------

/**
 * Verify a signed manifest.
 *
 * Returns `{ ok: true }` when the signature is valid and the signing key is
 * present and not revoked.  Otherwise returns `{ ok: false, reason }`.
 *
 * Never throws on malformed input — treats it as a verification failure.
 *
 * | `reason`          | Meaning                                             |
 * |-------------------|-----------------------------------------------------|
 * | `'missing_key_id'`| `key_id` field absent from the manifest.            |
 * | `'unknown_key'`   | `key_id` is not registered in this store.           |
 * | `'key_revoked'`   | The key exists but has been revoked.                |
 * | `'bad_signature'` | HMAC did not match — data was tampered or wrong key.|
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {object} signedManifest
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyManifest(ks, signedManifest) {
  const { key_id, sig } = signedManifest;

  if (!key_id) return { ok: false, reason: 'missing_key_id' };

  const entry = ks.keys.get(key_id);
  if (!entry) return { ok: false, reason: 'unknown_key' };
  if (entry.status === 'revoked') return { ok: false, reason: 'key_revoked' };

  const payload = signingPayload(signedManifest);
  const expected = hmacPayload(entry.raw, payload);

  // Use timingSafeEqual to prevent timing-side-channel leaks.
  // Both buffers must have the same length; a length mismatch is a sig failure.
  const eBuf = Buffer.from(expected, 'hex');
  if (typeof sig !== 'string' || sig.length !== expected.length) {
    return { ok: false, reason: 'bad_signature' };
  }
  const aBuf = Buffer.from(sig, 'hex');
  let match;
  try {
    match = timingSafeEqual(eBuf, aBuf);
  } catch {
    match = false;
  }
  return match ? { ok: true } : { ok: false, reason: 'bad_signature' };
}

// ---------------------------------------------------------------------------
// getKey
// ---------------------------------------------------------------------------

/**
 * Return the metadata for a registered key (without the raw key material).
 * Returns `null` if `keyId` is not in the store.
 *
 * @param {{ keys: Map<string,object> }} ks
 * @param {string} keyId
 * @returns {{ key_id: string, status: string, created_at: string } | null}
 */
export function getKey(ks, keyId) {
  const entry = ks.keys.get(keyId);
  if (!entry) return null;
  // Never expose the raw key material to callers.
  return { key_id: entry.key_id, status: entry.status, created_at: entry.created_at };
}
