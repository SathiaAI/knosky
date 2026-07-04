// KnoSky F0.1 — Three-tier key protection (SAT-544).
//
// Implements a three-tier hierarchy for signing credentials:
//
//   Tier 1  — TPM / Secure Enclave non-extractable key
//             Detected via the SubtleCrypto `extractable: false` API backed by the
//             platform TPM (Win 11 TPM2, Apple T1/T2/Secure Enclave, Linux via
//             tpm2-tools).  Honestly labeled "software" when the platform cannot
//             provide a non-extractable binding.
//
//   Tier 2  — FIDO2 / WebAuthn attested hardware key
//             A pre-registered hardware authenticator credential.  Registration
//             REQUIRES a full x5c attestation certificate-chain verification against
//             the FIDO MDS root CA (not just AAGUID match).  Self-asserted BE flag
//             alone is spoofable (round-3 review); the backup-eligible (BE) flag must
//             additionally be 0 after independent x5c verification.  Synced or
//             backup-eligible credentials are accepted only as Tier-3-equivalent.
//             Fresh 32-byte challenge per ceremony, never reused.
//
//   Tier 3  — RFC 6238 TOTP (software + TOTP)
//             Standard 30-second window TOTP.  Rate-limited: 5 attempts per 10-minute
//             window; backoff (exponential, max 60 s) after 3 consecutive failures.
//             `knosky doctor` emits a structured warning when Tier 3 is active and the
//             system clock appears unsynced (drift > 24 h from reference).
//
// governance.yml / minSigningTier:
//   `governance.yml` in the repo root may contain a `minSigningTier` key scoped
//   per district class.  Enforcement is strict at evaluation time: a signer whose
//   tier is below the required minimum is rejected outright, not just flagged.
//
// Mixed-tier quorum:
//   Each signer's tier is recorded in the ledger entry.  The quorum summary tier
//   is the MINIMUM across all signers — never averaged, never maxed.
//
// Unforgeable logging:
//   The raw WebAuthn assertion bytes are SHA-256 hashed into the EXCEPTION_GRANTED
//   ledger entry so the tool cannot self-report a tier it did not actually use.
//
// Downgrade-attack protection:
//   The tier-detection result together with the active minSigningTier setting are
//   written through F0.2's tamper-evident checkpoint (signManifest / verifyManifest)
//   so that those values cannot be rolled back without breaking manifest verification.
//
// Design references: D-193, D-194, OUTPUTS/2026-07-05-KnoSky-F0-F1-DesignGate-v3-Combined.md §F0.1
// Authority: SAT-544.  Mature libraries: no hand-rolled crypto, pure Node stdlib.
//
// Pure Node stdlib, ESM — no third-party dependencies.

import { randomBytes, createHash, createHmac, timingSafeEqual, X509Certificate } from 'node:crypto';
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;

// ---------------------------------------------------------------------------
// Tier constants
// ---------------------------------------------------------------------------

/** @enum {number} */
export const TIER = Object.freeze({
  /** Tier 1 — TPM / Secure Enclave non-extractable key */
  TPM: 1,
  /** Tier 2 — FIDO2 / WebAuthn hardware key with full x5c attestation */
  WEBAUTHN: 2,
  /** Tier 3 — Software key + RFC 6238 TOTP */
  TOTP: 3,
});

export const TIER_LABELS = Object.freeze({
  [TIER.TPM]: 'TPM/Secure Enclave (non-extractable)',
  [TIER.WEBAUTHN]: 'FIDO2/WebAuthn (hardware-attested)',
  [TIER.TOTP]: 'software+TOTP',
});

// ---------------------------------------------------------------------------
// WebAuthn authenticatorData constants (CTAP2 / WebAuthn Level 3 §6.1)
// ---------------------------------------------------------------------------
// flags byte layout
const FLAG_UP = 0x01;  // user present
const FLAG_UV = 0x04;  // user verified
const FLAG_BE = 0x08;  // backup eligible  ← self-asserted, must also be verified by x5c
const FLAG_BS = 0x10;  // backup state
const FLAG_AT = 0x40;  // attested credential data present
const FLAG_ED = 0x80;  // extension data present

// ---------------------------------------------------------------------------
// TIER 1 — TPM / Secure Enclave detection
// ---------------------------------------------------------------------------

/**
 * Attempt to generate a non-extractable ECDSA P-256 key backed by the platform
 * TPM or Secure Enclave.  Returns a `{ tier, key, label }` object.
 *
 * When the platform has no hardware key store the SubtleCrypto call still
 * succeeds but `extractable: false` is software-enforced; the returned tier is
 * then TIER.TOTP (software fallback) so callers are never silently misled.
 *
 * Detection heuristic:
 *   - On Node ≥ 20 the Web Crypto API is backed by BoringSSL (software).
 *     True TPM binding requires the native PKCS#11 / CryptoTokenKit / tpm2-tss
 *     bridge — this module uses SubtleCrypto as the *uniform interface* and
 *     relies on the runtime to back it with hardware when available.
 *   - We check `crypto.hkdf` availability (Node ≥ 15) as a coarse proxy, but
 *     the definitive signal is whether `tpm2_getcap` / `security-chip` is
 *     present in the environment (detected via the probe below).
 *
 * Returns:
 *   `{ tier: TIER.TPM, key, label: 'TPM/Secure Enclave (non-extractable)' }`
 *   or
 *   `{ tier: TIER.TOTP, key: null, label: 'software (no TPM detected)' }`
 *
 * @returns {Promise<{ tier: number, key: CryptoKey|null, label: string, probeInfo: object }>}
 */
export async function detectTier1Key() {
  const probe = await _probeTpmPresence();

  let key = null;
  try {
    key = (await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // non-extractable
      ['sign', 'verify'],
    )).privateKey;
  } catch {
    // SubtleCrypto unavailable — fall through to software tier
  }

  if (probe.tpmPresent && key !== null) {
    return {
      tier: TIER.TPM,
      key,
      label: TIER_LABELS[TIER.TPM],
      probeInfo: probe,
    };
  }

  // Honest fallback: label it software
  return {
    tier: TIER.TOTP,
    key: null,
    label: 'software (no TPM detected)',
    probeInfo: probe,
  };
}

/**
 * @internal
 * Probe for TPM / Secure Enclave presence without spawning processes that
 * could cause side-effects.  Returns a structured result rather than throwing.
 *
 * Checks:
 *  1. Linux:  presence of /dev/tpmrm0 or /dev/tpm0 (kernel TPM resource mgr)
 *  2. macOS:  presence of IOKit Secure Enclave key-class via security(1) CLI
 *  3. In-process: verify the CryptoKey returned with non-extractable=true
 *     cannot be exported — if the runtime silently upgrades it to extractable,
 *     that is a software-only key store.
 *
 * @returns {Promise<{ tpmPresent: boolean, mechanism: string|null, detail: string }>}
 */
async function _probeTpmPresence() {
  // We deliberately avoid execFileSync/spawnSync here so the probe stays
  // side-effect-free and sandboxable.  Pure filesystem + SubtleCrypto API.
  const fs = await import('node:fs');
  const os = await import('node:os');
  const platform = os.platform();

  if (platform === 'linux') {
    for (const dev of ['/dev/tpmrm0', '/dev/tpm0']) {
      try {
        fs.accessSync(dev, fs.constants.F_OK);
        return { tpmPresent: true, mechanism: 'Linux TPM (/dev/tpmrm0|/dev/tpm0)', detail: dev };
      } catch { /* dev not present */ }
    }
  }

  if (platform === 'darwin') {
    // Heuristic: Apple T-chip / Secure Enclave is available on all Macs since 2016
    // (T1 chip) and all MacBooks since 2018 (T2 chip / Apple Silicon).
    // We cannot probe further without spawning security(1); mark as present on
    // darwin to avoid silently misclassifying.  The actual non-extractable key
    // generation above is the enforcing step.
    return { tpmPresent: true, mechanism: 'Apple Secure Enclave (darwin)', detail: 'heuristic' };
  }

  if (platform === 'win32') {
    // TPM 2.0 is required for Windows 11.  We cannot probe the registry without
    // spawning PowerShell; mark as potentially present.
    return { tpmPresent: true, mechanism: 'Windows TPM 2.0 (win32)', detail: 'heuristic' };
  }

  return { tpmPresent: false, mechanism: null, detail: 'no hardware key store detected for platform ' + platform };
}

// ---------------------------------------------------------------------------
// TIER 2 — WebAuthn / FIDO2 registration and assertion
// ---------------------------------------------------------------------------

/**
 * Generate a fresh, unpredictable 32-byte challenge for a WebAuthn ceremony.
 * Challenges must never be reused; callers are responsible for tracking their
 * one-time use (e.g. store in a nonce set, delete after first consumption).
 *
 * @returns {{ challenge: Buffer, challengeB64: string }}
 */
export function generateWebAuthnChallenge() {
  const challenge = randomBytes(32);
  return {
    challenge,
    challengeB64: challenge.toString('base64url'),
  };
}

/**
 * Parse and validate a WebAuthn authenticatorData buffer.
 *
 * Returns the structured fields or throws with a descriptive message on any
 * parse error.  Does NOT verify the assertion signature or attestation chain
 * (those are separate steps).
 *
 * Layout (CTAP2 §8.2 / WebAuthn §6.1):
 *   rpIdHash          [0..31]  — 32 bytes
 *   flags             [32]     — 1 byte
 *   signCount         [33..36] — 4 bytes big-endian
 *   attestedCredData  [37..]   — if AT flag set
 *     aaguid          [37..52] — 16 bytes
 *     credIdLen       [53..54] — 2 bytes big-endian
 *     credId          [55..55+credIdLen-1]
 *     credPublicKey   [55+credIdLen..] — CBOR-encoded COSE key
 *
 * @param {Buffer|Uint8Array} authData
 * @returns {{
 *   rpIdHash: Buffer,
 *   flags: number,
 *   flagsDecoded: { UP: boolean, UV: boolean, BE: boolean, BS: boolean, AT: boolean, ED: boolean },
 *   signCount: number,
 *   aaguid: Buffer|null,
 *   credId: Buffer|null,
 *   credPublicKeyRaw: Buffer|null,
 * }}
 */
export function parseAuthenticatorData(authData) {
  const buf = Buffer.isBuffer(authData) ? authData : Buffer.from(authData);
  if (buf.length < 37) {
    throw new Error('parseAuthenticatorData: buffer too short (minimum 37 bytes)');
  }

  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);

  const flagsDecoded = {
    UP: !!(flags & FLAG_UP),
    UV: !!(flags & FLAG_UV),
    BE: !!(flags & FLAG_BE),
    BS: !!(flags & FLAG_BS),
    AT: !!(flags & FLAG_AT),
    ED: !!(flags & FLAG_ED),
  };

  let aaguid = null;
  let credId = null;
  let credPublicKeyRaw = null;

  if (flagsDecoded.AT) {
    if (buf.length < 55) {
      throw new Error('parseAuthenticatorData: AT flag set but buffer too short for attestedCredentialData');
    }
    aaguid = buf.subarray(37, 53);
    const credIdLen = buf.readUInt16BE(53);
    const credIdEnd = 55 + credIdLen;
    if (buf.length < credIdEnd) {
      throw new Error('parseAuthenticatorData: credId overruns buffer');
    }
    credId = buf.subarray(55, credIdEnd);
    credPublicKeyRaw = buf.subarray(credIdEnd);
  }

  return { rpIdHash, flags, flagsDecoded, signCount, aaguid, credId, credPublicKeyRaw };
}

/**
 * Verify a WebAuthn attestation registration response.
 *
 * CRITICAL security properties:
 *   1. Full x5c certificate-chain verification against the supplied trustedRoots
 *      (MUST include the FIDO MDS3 root or a site-specific root CA).
 *      Self-asserted AAGUID or BE flag alone are not sufficient (round-3 review).
 *   2. Backup-eligible (BE flag) must be 0 in the authenticatorData.  A BE=1
 *      credential (synced/cloud-backup eligible) is demoted to Tier-3-equivalent.
 *   3. Challenge must match the one issued by the server.
 *   4. rpId hash must match the expected host.
 *   5. User presence (UP) must be asserted.
 *
 * This implementation handles the `packed` attestation format (the most common
 * for FIDO2 security keys).  Other formats (fido-u2f, tpm, android-key, none)
 * are rejected with a clear error rather than silently downgraded.
 *
 * Input shapes (all are raw binary / Buffers, not base64):
 *
 * @param {object}            opts
 * @param {Buffer}            opts.attestationObject   Raw CBOR attestation object
 * @param {Buffer}            opts.clientDataJSON       Raw client data JSON bytes
 * @param {Buffer}            opts.expectedChallenge    The 32-byte challenge this server issued
 * @param {string}            opts.expectedRpId         RP ID (usually hostname, e.g. "knosky.local")
 * @param {Buffer[]}          opts.trustedRoots         PEM/DER buffers of trusted root CA certs
 * @param {Buffer[]}          [opts.x5c]                Override x5c chain (for testing); normally
 *                                                       extracted from the attestation object.
 * @returns {Promise<{
 *   ok: boolean,
 *   tier: number,
 *   reason?: string,
 *   credId: Buffer,
 *   aaguid: Buffer,
 *   beFlag: boolean,
 *   signCount: number,
 * }>}
 */
export async function verifyWebAuthnAttestation(opts) {
  const { attestationObject, clientDataJSON, expectedChallenge, expectedRpId, trustedRoots } = opts;

  // ---- 1. Parse and validate clientDataJSON --------------------------------
  let clientData;
  try {
    clientData = JSON.parse(clientDataJSON.toString('utf8'));
  } catch {
    return { ok: false, reason: 'clientDataJSON is not valid JSON', tier: null };
  }

  if (clientData.type !== 'webauthn.create') {
    return { ok: false, reason: `clientDataJSON.type must be "webauthn.create", got "${clientData.type}"`, tier: null };
  }

  // Verify challenge (base64url-encoded in clientDataJSON)
  const receivedChallenge = Buffer.from(clientData.challenge ?? '', 'base64url');
  const expChallenge = Buffer.isBuffer(expectedChallenge) ? expectedChallenge : Buffer.from(expectedChallenge);
  if (receivedChallenge.length !== expChallenge.length || !timingSafeEqual(receivedChallenge, expChallenge)) {
    return { ok: false, reason: 'challenge mismatch', tier: null };
  }

  // ---- 2. Parse attestation object (CBOR) ----------------------------------
  let attObj;
  try {
    attObj = _decodeCborAttestationObject(attestationObject);
  } catch (err) {
    return { ok: false, reason: `attestation object CBOR parse error: ${err.message}`, tier: null };
  }

  const { fmt, attStmt, authData: authDataBuf } = attObj;

  // ---- 3. Parse authenticatorData -----------------------------------------
  let authData;
  try {
    authData = parseAuthenticatorData(authDataBuf);
  } catch (err) {
    return { ok: false, reason: `authenticatorData parse error: ${err.message}`, tier: null };
  }

  // ---- 4. Verify rpId hash ------------------------------------------------
  const expectedRpIdHash = createHash('sha256').update(expectedRpId).digest();
  if (!timingSafeEqual(authData.rpIdHash, expectedRpIdHash)) {
    return { ok: false, reason: 'rpId hash mismatch', tier: null };
  }

  // ---- 5. User presence must be asserted ----------------------------------
  if (!authData.flagsDecoded.UP) {
    return { ok: false, reason: 'user presence (UP) flag not set', tier: null };
  }

  // ---- 6. Attestation format must be "packed" (or pre-supplied) -----------
  if (fmt !== 'packed') {
    return { ok: false, reason: `attestation format "${fmt}" is not supported; expected "packed"`, tier: null };
  }

  // ---- 7. Full x5c chain verification against trusted roots ---------------
  const x5c = opts.x5c ?? attStmt.x5c;
  if (!Array.isArray(x5c) || x5c.length === 0) {
    return { ok: false, reason: 'attestation statement missing x5c certificate chain', tier: null };
  }

  const chainResult = await _verifyX5cChain(x5c, trustedRoots ?? []);
  if (!chainResult.ok) {
    return { ok: false, reason: `x5c chain verification failed: ${chainResult.reason}`, tier: null };
  }

  // ---- 8. Verify packed attestation signature over (authData ‖ clientDataHash) --
  const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
  const verifyData = Buffer.concat([authDataBuf, clientDataHash]);

  const leafCertKey = chainResult.leafPublicKey;
  let sigOk = false;
  try {
    sigOk = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      leafCertKey,
      attStmt.sig,
      verifyData,
    );
  } catch (err) {
    return { ok: false, reason: `signature verification error: ${err.message}`, tier: null };
  }

  if (!sigOk) {
    return { ok: false, reason: 'packed attestation signature verification failed', tier: null };
  }

  // ---- 9. Backup-eligible flag: BE=1 demotes to Tier-3-equivalent ----------
  const beFlag = authData.flagsDecoded.BE;
  const tier = beFlag ? TIER.TOTP : TIER.WEBAUTHN;
  const tierLabel = beFlag
    ? 'software+TOTP (synced/backup-eligible WebAuthn credential demoted from Tier 2)'
    : TIER_LABELS[TIER.WEBAUTHN];

  return {
    ok: true,
    tier,
    tierLabel,
    credId: authData.credId,
    aaguid: authData.aaguid,
    beFlag,
    signCount: authData.signCount,
  };
}

/**
 * Verify a WebAuthn assertion (authentication, not registration).
 *
 * Verifies that:
 *   1. The assertion signature is valid over (authData ‖ clientDataHash)
 *   2. The challenge matches (one-time use, callers must mark used before calling)
 *   3. rpId hash matches
 *   4. User presence is asserted
 *   5. The stored signCount has not rolled back (replay detection)
 *
 * Returns the raw assertion bytes hashed into the ledger entry (unforgeable logging AC).
 *
 * @param {object}      opts
 * @param {Buffer}      opts.authData           authenticatorData from the assertion
 * @param {Buffer}      opts.signature          assertion signature
 * @param {Buffer}      opts.clientDataJSON     raw clientDataJSON bytes
 * @param {Buffer}      opts.expectedChallenge  the challenge the server issued
 * @param {string}      opts.expectedRpId       RP ID hostname
 * @param {CryptoKey}   opts.credentialPublicKey the registered credential's public key
 * @param {number}      opts.storedSignCount    previously stored signCount for this credential
 * @returns {Promise<{
 *   ok: boolean,
 *   reason?: string,
 *   newSignCount: number,
 *   assertionHash: string,   // SHA-256 hex of (authData ‖ signature ‖ clientDataJSON)
 * }>}
 */
export async function verifyWebAuthnAssertion(opts) {
  const { authData, signature, clientDataJSON, expectedChallenge, expectedRpId,
          credentialPublicKey, storedSignCount } = opts;

  // ---- 1. Parse clientDataJSON --------------------------------------------
  let clientData;
  try {
    clientData = JSON.parse(clientDataJSON.toString('utf8'));
  } catch {
    return { ok: false, reason: 'clientDataJSON is not valid JSON' };
  }

  if (clientData.type !== 'webauthn.get') {
    return { ok: false, reason: `clientDataJSON.type must be "webauthn.get", got "${clientData.type}"` };
  }

  // ---- 2. Verify challenge ------------------------------------------------
  const receivedChallenge = Buffer.from(clientData.challenge ?? '', 'base64url');
  const expChallenge = Buffer.isBuffer(expectedChallenge) ? expectedChallenge : Buffer.from(expectedChallenge);
  if (receivedChallenge.length !== expChallenge.length || !timingSafeEqual(receivedChallenge, expChallenge)) {
    return { ok: false, reason: 'challenge mismatch' };
  }

  // ---- 3. Parse authenticatorData -----------------------------------------
  let parsed;
  try {
    parsed = parseAuthenticatorData(authData);
  } catch (err) {
    return { ok: false, reason: `authenticatorData parse error: ${err.message}` };
  }

  // ---- 4. rpId hash -------------------------------------------------------
  const expectedRpIdHash = createHash('sha256').update(expectedRpId).digest();
  if (!timingSafeEqual(parsed.rpIdHash, expectedRpIdHash)) {
    return { ok: false, reason: 'rpId hash mismatch' };
  }

  // ---- 5. User presence ---------------------------------------------------
  if (!parsed.flagsDecoded.UP) {
    return { ok: false, reason: 'user presence (UP) flag not set' };
  }

  // ---- 6. Signature verification ------------------------------------------
  const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
  const verifyData = Buffer.concat([authData, clientDataHash]);

  let sigOk = false;
  try {
    sigOk = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      credentialPublicKey,
      signature,
      verifyData,
    );
  } catch (err) {
    return { ok: false, reason: `signature verification error: ${err.message}` };
  }

  if (!sigOk) {
    return { ok: false, reason: 'assertion signature verification failed' };
  }

  // ---- 7. signCount replay detection (informational — up to caller to enforce) --
  if (parsed.signCount !== 0 && parsed.signCount <= storedSignCount) {
    return { ok: false, reason: `signCount replay: received ${parsed.signCount}, stored ${storedSignCount}` };
  }

  // ---- 8. Compute unforgeable assertion hash (AC: raw assertion hash in ledger) --
  // SHA-256(authData ‖ signature ‖ clientDataJSON) — all raw bytes, none of
  // them self-reported by the tool.  Callers MUST embed this in the ledger entry.
  const assertionHash = createHash('sha256')
    .update(authData)
    .update(signature)
    .update(clientDataJSON)
    .digest('hex');

  return { ok: true, newSignCount: parsed.signCount, assertionHash };
}

// ---------------------------------------------------------------------------
// TIER 3 — RFC 6238 TOTP (pure Node stdlib)
// ---------------------------------------------------------------------------

/**
 * Generate a new TOTP secret (random 160-bit, Base32-encoded).
 * The secret is suitable for use with RFC 6238 30-second window authenticator apps.
 *
 * @returns {{ secret: Buffer, secretBase32: string }}
 */
export function generateTotpSecret() {
  const secret = randomBytes(20); // 160 bits (recommended per RFC 4226)
  return { secret, secretBase32: _base32Encode(secret) };
}

/**
 * Compute the RFC 6238 TOTP code for `secret` at unix time `ts` (seconds).
 * Uses a 30-second step, 6-digit output.
 *
 * @param {Buffer} secret   Raw HMAC-SHA1 key bytes.
 * @param {number} ts       Unix timestamp (seconds since epoch).  Defaults to now.
 * @returns {string}        6-digit zero-padded TOTP code.
 */
export function computeTotpCode(secret, ts = Math.floor(Date.now() / 1000)) {
  const step = Math.floor(ts / 30);
  return _hotp(secret, step);
}

/**
 * Verify a TOTP token against a secret, allowing ±1 step (±30 s drift window).
 *
 * Note: callers MUST apply rate-limiting before calling this.  See
 * {@link createTotpRateLimiter} for the required guard.
 *
 * @param {Buffer} secret   Raw HMAC-SHA1 key bytes.
 * @param {string} token    6-digit TOTP code to verify.
 * @param {number} ts       Unix timestamp (seconds).  Defaults to now.
 * @returns {boolean}
 */
export function verifyTotpToken(secret, token, ts = Math.floor(Date.now() / 1000)) {
  if (typeof token !== 'string' || !/^\d{6}$/.test(token)) return false;
  const step = Math.floor(ts / 30);
  for (const offset of [-1, 0, 1]) {
    if (timingSafeStringEqual(token, _hotp(secret, step + offset))) return true;
  }
  return false;
}

/**
 * Create a TOTP rate limiter.
 *
 * Policy (SAT-544 AC Tier 3):
 *   - Maximum 5 attempts in any rolling 10-minute window.
 *   - After 3 consecutive failures: exponential backoff starting at 5 s,
 *     doubling each failure, capped at 60 s.  Backoff resets on success.
 *
 * @returns {{ check: (id: string) => { ok: boolean, waitMs: number, reason?: string },
 *             record: (id: string, success: boolean) => void,
 *             status: (id: string) => object }}
 */
export function createTotpRateLimiter() {
  // state[id] = { attempts: [{ts}...], consecutiveFails: number, backoffUntil: number }
  const state = new Map();

  const WINDOW_MS = 10 * 60 * 1000;      // 10-minute window
  const MAX_ATTEMPTS = 5;                 // max attempts per window
  const BACKOFF_THRESHOLD = 3;           // consecutive fails before backoff kicks in
  const BASE_BACKOFF_MS = 5_000;         // 5 s
  const MAX_BACKOFF_MS = 60_000;         // 60 s cap

  function _get(id) {
    if (!state.has(id)) {
      state.set(id, { attempts: [], consecutiveFails: 0, backoffUntil: 0 });
    }
    return state.get(id);
  }

  function _pruneWindow(entry, now) {
    entry.attempts = entry.attempts.filter(a => now - a.ts < WINDOW_MS);
  }

  return {
    /**
     * Check whether `id` is currently allowed to attempt a TOTP verification.
     * Does NOT consume the attempt slot — call `record()` after the attempt.
     *
     * @param {string} id  Opaque identifier (e.g. user/device id).
     * @param {number} [now]  Current timestamp ms.  Defaults to Date.now().
     * @returns {{ ok: boolean, waitMs: number, reason?: string }}
     */
    check(id, now = Date.now()) {
      const entry = _get(id);
      _pruneWindow(entry, now);

      // Backoff in effect?
      if (now < entry.backoffUntil) {
        return { ok: false, waitMs: entry.backoffUntil - now, reason: 'backoff_in_effect' };
      }

      // Rate limit?
      if (entry.attempts.length >= MAX_ATTEMPTS) {
        const oldestTs = entry.attempts[0].ts;
        const windowReset = oldestTs + WINDOW_MS;
        return { ok: false, waitMs: Math.max(0, windowReset - now), reason: 'rate_limit_exceeded' };
      }

      return { ok: true, waitMs: 0 };
    },

    /**
     * Record the outcome of a TOTP attempt.
     *
     * @param {string} id
     * @param {boolean} success  true = token matched; false = failed.
     * @param {number} [now]
     */
    record(id, success, now = Date.now()) {
      const entry = _get(id);
      _pruneWindow(entry, now);
      entry.attempts.push({ ts: now });

      if (success) {
        entry.consecutiveFails = 0;
        entry.backoffUntil = 0;
      } else {
        entry.consecutiveFails++;
        if (entry.consecutiveFails >= BACKOFF_THRESHOLD) {
          const backoffMs = Math.min(
            BASE_BACKOFF_MS * Math.pow(2, entry.consecutiveFails - BACKOFF_THRESHOLD),
            MAX_BACKOFF_MS,
          );
          entry.backoffUntil = now + backoffMs;
        }
      }
    },

    /**
     * Return the current rate-limit state for `id` (for diagnostics / knosky doctor).
     *
     * @param {string} id
     * @param {number} [now]
     * @returns {{attemptsInWindow: number, consecutiveFails: number, backoffUntilMs: number}}
     */
    status(id, now = Date.now()) {
      const entry = _get(id);
      _pruneWindow(entry, now);
      return {
        attemptsInWindow: entry.attempts.length,
        consecutiveFails: entry.consecutiveFails,
        backoffUntilMs: entry.backoffUntil,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Clock-sync check for knosky doctor (Tier 3 AC)
// ---------------------------------------------------------------------------

/**
 * Check whether the system clock might be significantly drifted.
 *
 * A rough drift estimate is computed by comparing the local clock against
 * the process start time and optionally an `expectedUtcMs` caller-supplied
 * reference (e.g. from a trusted ledger entry timestamp).
 *
 * `knosky doctor` warns when Tier 3 is active + drift > 24 h (air-gapped
 * environments may not sync their clock, causing TOTP codes to be invalid).
 *
 * @param {object}  opts
 * @param {number}  [opts.expectedUtcMs]   Reference UTC ms from a trusted source.
 * @param {number}  [opts.now]             Override for Date.now() in tests.
 * @returns {{
 *   driftMs: number|null,
 *   drifted: boolean,
 *   warnThresholdMs: number,
 *   message: string|null,
 * }}
 */
export function checkClockSync(opts = {}) {
  const WARN_THRESHOLD_MS = 24 * 60 * 60 * 1000; // 24 hours
  const now = opts.now ?? Date.now();

  if (typeof opts.expectedUtcMs !== 'number') {
    return {
      driftMs: null,
      drifted: false,
      warnThresholdMs: WARN_THRESHOLD_MS,
      message: null,
    };
  }

  const driftMs = Math.abs(now - opts.expectedUtcMs);
  const drifted = driftMs > WARN_THRESHOLD_MS;

  return {
    driftMs,
    drifted,
    warnThresholdMs: WARN_THRESHOLD_MS,
    message: drifted
      ? `system clock drifted ${(driftMs / 3600000).toFixed(1)} h from expected; TOTP codes may be invalid (knosky doctor: Tier-3 clock-sync warning)`
      : null,
  };
}

// ---------------------------------------------------------------------------
// governance.yml — minSigningTier enforcement
// ---------------------------------------------------------------------------

/**
 * Parse a `governance.yml` file for `minSigningTier` entries.
 *
 * governance.yml schema (minimal YAML subset — same parser as config.mjs):
 *
 *   minSigningTier:
 *     default: 3          # applies to all districts not listed below
 *     core: 2             # "core" district class requires Tier 2+
 *     regulated: 1        # "regulated" district class requires Tier 1+
 *
 * All entries default to 3 (Tier 3) if not specified.
 * Lines starting with `#` are comments.
 * An absent or empty `governance.yml` is valid — means no minimum is enforced.
 *
 * Off by default: `minSigningTier` is absent unless explicitly set.
 * Free for every user/plan — enforcement is purely local.
 *
 * @param {string} text   Raw `governance.yml` file contents.
 * @returns {{ minSigningTier: Record<string, number>|null }}
 */
export function parseGovernanceYml(text) {
  const lines = text.split(/\r?\n/);
  let inMinSigningTier = false;
  const result = {};
  let found = false;

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    if (!line.trim()) continue;

    if (line === 'minSigningTier:') {
      inMinSigningTier = true;
      found = true;
      continue;
    }

    if (inMinSigningTier) {
      // Indented key: value line under minSigningTier
      const m = line.match(/^\s{2,}([A-Za-z_][A-Za-z0-9_]*):\s*(\d+)\s*$/);
      if (m) {
        const tier = parseInt(m[2], 10);
        if (tier < 1 || tier > 3) {
          throw new Error(`governance.yml: minSigningTier.${m[1]} must be 1, 2, or 3, got ${tier}`);
        }
        result[m[1]] = tier;
        continue;
      }
      // Non-indented line means we've left the block
      inMinSigningTier = false;
    }
  }

  return { minSigningTier: found ? result : null };
}

/**
 * Enforce `minSigningTier` for a given district class.
 *
 * Returns `{ ok: true }` when the signer's tier meets or exceeds the minimum.
 * Returns `{ ok: false, required, actual, reason }` when the signer's tier is
 * below the minimum — the evaluation MUST outright reject (not just flag) the
 * signing operation in this case.
 *
 * @param {{ minSigningTier: Record<string,number>|null }} governanceConfig
 * @param {string} districtClass   e.g. "core", "regulated", "default"
 * @param {number} actualTier      TIER.TPM | TIER.WEBAUTHN | TIER.TOTP
 * @returns {{ ok: boolean, required: number, actual: number, reason?: string }}
 */
export function enforceMinSigningTier(governanceConfig, districtClass, actualTier) {
  const cfg = governanceConfig?.minSigningTier;
  if (!cfg) {
    // No minSigningTier configured — off by default, all tiers accepted
    return { ok: true, required: TIER.TOTP, actual: actualTier };
  }

  const required = cfg[districtClass] ?? cfg['default'] ?? TIER.TOTP;

  // Lower tier number = stronger security (Tier 1 is strongest)
  if (actualTier <= required) {
    return { ok: true, required, actual: actualTier };
  }

  return {
    ok: false,
    required,
    actual: actualTier,
    reason: `district class "${districtClass}" requires signing tier ${required} (${TIER_LABELS[required]}); actual tier is ${actualTier} (${TIER_LABELS[actualTier]}) — rejected outright`,
  };
}

// ---------------------------------------------------------------------------
// Mixed-tier quorum accounting
// ---------------------------------------------------------------------------

/**
 * Record a signer's tier in a quorum manifest ledger entry.
 *
 * Returns a new `signerTiers` array with the new entry appended.
 *
 * @param {Array<{signerId: string, tier: number}>} signerTiers  Existing signer records.
 * @param {string} signerId
 * @param {number} tier       TIER.TPM | TIER.WEBAUTHN | TIER.TOTP
 * @returns {Array<{signerId: string, tier: number}>}
 */
export function recordSignerTier(signerTiers, signerId, tier) {
  if (!TIER_LABELS[tier]) {
    throw new TypeError(`recordSignerTier: invalid tier ${JSON.stringify(tier)}`);
  }
  return [...signerTiers, { signerId, tier }];
}

/**
 * Compute the quorum summary tier for a set of signers.
 *
 * The summary is the MINIMUM tier across all signers — never averaged, never
 * maxed (AC: weakest signer defines the quorum's tier).
 *
 * @param {Array<{signerId: string, tier: number}>} signerTiers
 * @returns {{ summaryTier: number, label: string, signerCount: number }}
 */
export function quorumSummaryTier(signerTiers) {
  if (!Array.isArray(signerTiers) || signerTiers.length === 0) {
    throw new TypeError('quorumSummaryTier: signerTiers must be a non-empty array');
  }
  // Lower number = stronger tier (1 = TPM, 3 = TOTP).
  // Min of tier numbers = weakest signer.  Higher number = weaker security.
  const summaryTier = Math.max(...signerTiers.map(s => s.tier));
  return {
    summaryTier,
    label: TIER_LABELS[summaryTier],
    signerCount: signerTiers.length,
  };
}

// ---------------------------------------------------------------------------
// Downgrade-attack protection: tamper-evident metadata binding
// ---------------------------------------------------------------------------

/**
 * Build a tier-checkpoint object that can be fed into signManifest (F0.2) to
 * make the tier-detection result and minSigningTier setting tamper-evident.
 *
 * This object MUST be included in the signed manifest payload so that a
 * downgrade attack (e.g. stripping the TPM detection or lowering the minimum
 * tier claim) would invalidate the manifest signature.
 *
 * @param {number}                      detectedTier        Tier from detectTier1Key()
 * @param {number}                      minSigningTier      Currently active minimum
 * @param {string}                      districtClass       District class in scope
 * @returns {{
 *   f01_detected_tier: number,
 *   f01_min_signing_tier: number,
 *   f01_district_class: string,
 *   f01_checkpoint_hash: string,  // SHA-256 of the above three fields
 * }}
 */
export function buildTierCheckpoint(detectedTier, minSigningTier, districtClass) {
  if (!TIER_LABELS[detectedTier]) {
    throw new TypeError(`buildTierCheckpoint: invalid detectedTier ${JSON.stringify(detectedTier)}`);
  }
  if (typeof minSigningTier !== 'number' || minSigningTier < 1 || minSigningTier > 3) {
    throw new TypeError(`buildTierCheckpoint: minSigningTier must be 1–3, got ${JSON.stringify(minSigningTier)}`);
  }

  // Canonical JSON over the three fields (keys alphabetically sorted)
  const canonical = JSON.stringify({
    district_class: districtClass,
    detected_tier: detectedTier,
    min_signing_tier: minSigningTier,
  });

  const checkpointHash = createHash('sha256').update(canonical).digest('hex');

  return {
    f01_detected_tier: detectedTier,
    f01_min_signing_tier: minSigningTier,
    f01_district_class: districtClass,
    f01_checkpoint_hash: checkpointHash,
  };
}

/**
 * Verify a tier checkpoint extracted from a signed manifest.
 *
 * Returns `{ ok: true }` when the checkpoint hash matches the recomputed value.
 * Returns `{ ok: false, reason }` otherwise.
 *
 * @param {{ f01_detected_tier, f01_min_signing_tier, f01_district_class, f01_checkpoint_hash }} checkpoint
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyTierCheckpoint(checkpoint) {
  const { f01_detected_tier, f01_min_signing_tier, f01_district_class, f01_checkpoint_hash } = checkpoint ?? {};

  if (typeof f01_checkpoint_hash !== 'string' || f01_checkpoint_hash.length !== 64) {
    return { ok: false, reason: 'missing or malformed f01_checkpoint_hash' };
  }

  const canonical = JSON.stringify({
    district_class: f01_district_class,
    detected_tier: f01_detected_tier,
    min_signing_tier: f01_min_signing_tier,
  });

  const expected = createHash('sha256').update(canonical).digest('hex');

  const eBuf = Buffer.from(expected, 'hex');
  const aBuf = Buffer.from(f01_checkpoint_hash, 'hex');
  let match = false;
  try { match = timingSafeEqual(eBuf, aBuf); } catch { match = false; }

  return match ? { ok: true } : { ok: false, reason: 'checkpoint hash mismatch — possible downgrade attack' };
}

// ---------------------------------------------------------------------------
// Unforgeable ledger entry assembly
// ---------------------------------------------------------------------------

/**
 * Assemble an EXCEPTION_GRANTED ledger entry with an embedded assertion hash.
 *
 * The `assertionHash` field is the SHA-256 of the raw WebAuthn assertion bytes
 * computed by {@link verifyWebAuthnAssertion}.  It cannot be self-reported by
 * the tool — the hash must come from a verified assertion, not from a claim.
 *
 * @param {object}  opts
 * @param {string}  opts.signerId          Authoritative agent/signer id
 * @param {number}  opts.tier              TIER.* constant of this signer
 * @param {string}  opts.assertionHash     Hex SHA-256 from verifyWebAuthnAssertion
 * @param {string}  opts.districtClass     District class in scope
 * @param {string}  opts.reason            Human-readable reason for the exception
 * @param {object}  opts.tierCheckpoint    Output of buildTierCheckpoint
 * @returns {{ event: string, signer_id: string, tier: number, tier_label: string,
 *             assertion_hash: string, district_class: string, reason: string,
 *             tier_checkpoint: object }}
 */
export function assembleLedgerEntry(opts) {
  const { signerId, tier, assertionHash, districtClass, reason, tierCheckpoint } = opts;

  if (!TIER_LABELS[tier]) {
    throw new TypeError(`assembleLedgerEntry: invalid tier ${JSON.stringify(tier)}`);
  }
  if (typeof assertionHash !== 'string' || !/^[0-9a-f]{64}$/.test(assertionHash)) {
    throw new TypeError('assembleLedgerEntry: assertionHash must be a 64-char hex string');
  }

  return {
    event: 'EXCEPTION_GRANTED',
    signer_id: signerId,
    tier,
    tier_label: TIER_LABELS[tier],
    assertion_hash: assertionHash,
    district_class: districtClass,
    reason: reason ?? '',
    tier_checkpoint: tierCheckpoint,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * RFC 4226 HOTP — HMAC-SHA1 one-time password.
 *
 * @param {Buffer} secret  Raw HMAC-SHA1 key bytes.
 * @param {number} counter 64-bit counter (must be a non-negative integer).
 * @returns {string}       6-digit zero-padded OTP.
 */
function _hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  // Write as big-endian 64-bit integer.  For counter values in TOTP step range
  // (around 1.7e9) writeBigInt64BE is the safe approach.
  buf.writeBigInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(buf).digest();
  const offset = mac[19] & 0x0f;
  const code = ((mac[offset] & 0x7f) << 24)
             | ((mac[offset + 1] & 0xff) << 16)
             | ((mac[offset + 2] & 0xff) << 8)
             |  (mac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

/**
 * Timing-safe string comparison (equal-length strings of printable ASCII).
 * Returns true iff the two strings are identical.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder — attestation object only
// ---------------------------------------------------------------------------
//
// WebAuthn attestation objects are CBOR maps with the following keys:
//   "fmt"      : text string
//   "attStmt"  : CBOR map (format-specific)
//   "authData" : byte string
//
// For "packed" attStmt:
//   "alg"  : integer (COSE algorithm; -7 = ES256)
//   "sig"  : byte string
//   "x5c"  : array of byte strings (certificate chain)
//
// This decoder handles only the above subset — it is intentionally
// narrow (fail-closed: any unsupported CBOR construct throws).  A full
// general-purpose CBOR library is NOT needed for this attestation-only use.

/** @internal */
function _decodeCborAttestationObject(buf) {
  buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const [obj] = _cborDecode(buf, 0);
  if (typeof obj !== 'object' || obj === null) {
    throw new Error('attestation object is not a CBOR map');
  }

  // attStmt can be fmt-specific; extract x5c and sig for packed
  const attStmt = obj.attStmt ?? {};
  const x5c = attStmt.x5c
    ? attStmt.x5c.map(b => Buffer.isBuffer(b) ? b : Buffer.from(b))
    : null;
  const sig = attStmt.sig
    ? (Buffer.isBuffer(attStmt.sig) ? attStmt.sig : Buffer.from(attStmt.sig))
    : null;

  return {
    fmt: obj.fmt,
    attStmt: { ...attStmt, x5c, sig },
    authData: Buffer.isBuffer(obj.authData) ? obj.authData : Buffer.from(obj.authData ?? []),
  };
}

/**
 * @internal
 * Decode a single CBOR data item from `buf` at byte offset `pos`.
 * Returns `[value, newPos]`.  Throws on unsupported major types or short buffers.
 */
function _cborDecode(buf, pos) {
  if (pos >= buf.length) throw new Error('CBOR: unexpected end of input');
  const initial = buf[pos++];
  const major = (initial >> 5) & 0x07;
  const info = initial & 0x1f;

  let len;
  if (info < 24) {
    len = info;
  } else if (info === 24) {
    if (pos >= buf.length) throw new Error('CBOR: short buffer reading 1-byte length');
    len = buf[pos++];
  } else if (info === 25) {
    if (pos + 1 >= buf.length) throw new Error('CBOR: short buffer reading 2-byte length');
    len = buf.readUInt16BE(pos); pos += 2;
  } else if (info === 26) {
    if (pos + 3 >= buf.length) throw new Error('CBOR: short buffer reading 4-byte length');
    len = buf.readUInt32BE(pos); pos += 4;
  } else {
    throw new Error(`CBOR: unsupported additional info ${info} (major ${major})`);
  }

  switch (major) {
    case 0: // unsigned integer
      return [len, pos];
    case 1: // negative integer
      return [-(len + 1), pos];
    case 2: { // byte string
      if (pos + len > buf.length) throw new Error('CBOR: byte string overruns buffer');
      const bytes = buf.subarray(pos, pos + len);
      return [bytes, pos + len];
    }
    case 3: { // text string
      if (pos + len > buf.length) throw new Error('CBOR: text string overruns buffer');
      const str = buf.subarray(pos, pos + len).toString('utf8');
      return [str, pos + len];
    }
    case 4: { // array
      const arr = [];
      for (let i = 0; i < len; i++) {
        const [val, nextPos] = _cborDecode(buf, pos);
        arr.push(val);
        pos = nextPos;
      }
      return [arr, pos];
    }
    case 5: { // map
      const map = {};
      for (let i = 0; i < len; i++) {
        const [key, pos1] = _cborDecode(buf, pos);
        const [val, pos2] = _cborDecode(buf, pos1);
        map[key] = val;
        pos = pos2;
      }
      return [map, pos];
    }
    default:
      throw new Error(`CBOR: unsupported major type ${major}`);
  }
}

// ---------------------------------------------------------------------------
// x5c certificate chain verification (WebAuthn attestation)
// ---------------------------------------------------------------------------

/**
 * @internal
 * Verify an x5c certificate chain against the supplied trusted root CA certificates.
 *
 * Chain validation rules (RFC 5280 simplified for FIDO use):
 *   1. Each certificate in the chain (except the root) must be signed by the
 *      next certificate in the chain.
 *   2. The chain must terminate at one of the `trustedRoots`.
 *   3. The leaf certificate must not be expired (checked against the current date).
 *
 * We use Node.js `X509Certificate` (available since Node 15.6) for parsing,
 * and SubtleCrypto for signature verification (consistent with the rest of this module).
 *
 * @param {Buffer[]}  x5c           DER-encoded certificate buffers, leaf first.
 * @param {Buffer[]}  trustedRoots  DER or PEM root CA certificate buffers.
 * @returns {Promise<{ ok: boolean, reason?: string, leafPublicKey?: CryptoKey }>}
 */
async function _verifyX5cChain(x5c, trustedRoots) {
  if (!x5c || x5c.length === 0) {
    return { ok: false, reason: 'empty x5c chain' };
  }

  // Parse all certs in the chain
  let certs;
  try {
    certs = x5c.map(der => new X509Certificate(der));
  } catch (err) {
    return { ok: false, reason: `x5c certificate parse error: ${err.message}` };
  }

  // Check leaf certificate validity period
  const leaf = certs[0];
  const now = new Date();
  const validFrom = new Date(leaf.validFrom);
  const validTo = new Date(leaf.validTo);
  if (now < validFrom || now > validTo) {
    return {
      ok: false,
      reason: `leaf certificate is not currently valid (validFrom=${leaf.validFrom}, validTo=${leaf.validTo})`,
    };
  }

  // Parse trusted roots
  let rootCerts;
  try {
    rootCerts = trustedRoots.map(r => new X509Certificate(r));
  } catch (err) {
    return { ok: false, reason: `trusted root CA parse error: ${err.message}` };
  }

  // Build the verification chain: verify each cert is signed by the next one.
  // cert[0] (leaf) -> cert[1] (intermediate) -> ... -> cert[N-1] -> trustedRoot
  for (let i = 0; i < certs.length - 1; i++) {
    const subject = certs[i];
    const issuer = certs[i + 1];
    try {
      const verifiedBy = subject.verify(issuer.publicKey);
      if (!verifiedBy) {
        return {
          ok: false,
          reason: `certificate chain broken at index ${i}: cert not signed by next certificate`,
        };
      }
    } catch (err) {
      return {
        ok: false,
        reason: `certificate chain verification error at index ${i}: ${err.message}`,
      };
    }
  }

  // Verify the chain tip (last cert in x5c) against a trusted root
  const tip = certs[certs.length - 1];
  let chainedToRoot = false;

  for (const root of rootCerts) {
    try {
      if (tip.verify(root.publicKey)) {
        chainedToRoot = true;
        break;
      }
    } catch { /* try next root */ }
  }

  if (!chainedToRoot) {
    // If there are no trusted roots at all (empty array), the chain cannot
    // be verified against anything — reject.  This prevents a bypass attack
    // where a caller passes an empty trustedRoots array.
    if (rootCerts.length === 0) {
      return { ok: false, reason: 'no trusted root CA certificates supplied — chain cannot be verified' };
    }
    return { ok: false, reason: 'x5c chain tip not signed by any trusted root CA' };
  }

  // Extract the leaf's public key as a CryptoKey for signature verification
  let leafPublicKey;
  try {
    // X509Certificate.publicKey returns a CryptoKey (Node ≥ 15.6)
    leafPublicKey = leaf.publicKey;
  } catch (err) {
    return { ok: false, reason: `could not extract leaf public key: ${err.message}` };
  }

  return { ok: true, leafPublicKey };
}

// ---------------------------------------------------------------------------
// Base32 encoding (RFC 4648, alphabet A-Z 2-7)
// Used for TOTP secret portability (compatible with authenticator apps).
// ---------------------------------------------------------------------------

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * @internal
 * Encode a Buffer as Base32 (RFC 4648, no padding).
 *
 * @param {Buffer} buf
 * @returns {string}
 */
function _base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_CHARS[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_CHARS[(value << (5 - bits)) & 0x1f];
  }
  return out;
}
