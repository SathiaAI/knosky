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
// revokeKey
// ---------------------------------------------------------------------------

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
 * Throws if `keyId` is not present in the store.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {string} keyId
 */
export function revokeKey(ks, keyId) {
  if (!ks.keys.has(keyId)) {
    throw new Error(`revokeKey: unknown key_id ${JSON.stringify(keyId)}`);
  }
  const entry = ks.keys.get(keyId);
  if (entry.status === 'revoked') return; // idempotent
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
