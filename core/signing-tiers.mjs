// KnoSky F0.1 — Three-tier key protection (SAT-544).
//
// Implements a three-tier hierarchy for signing credentials:
//
//   Tier 1  — TPM / Secure Enclave non-extractable key
//             Detected via the SubtleCrypto `extractable: false` API. Honestly
//             labeled "software" whenever hardware backing cannot be positively
//             confirmed — this module never assumes a platform has a TPM/Secure
//             Enclave just because the OS could theoretically have one.
//
//   Tier 2  — FIDO2 / WebAuthn attested hardware key
//             A pre-registered hardware authenticator credential, verified with
//             @simplewebauthn/server (full x5c attestation certificate-chain
//             verification against caller-supplied trusted root CAs, FIDO
//             conformance-level certificate field checks, AAGUID cross-check).
//             Self-asserted "backup eligible" flag alone is spoofable; a
//             synced/backup-eligible credential (independently confirmed via
//             the verified attestation, not a self-report) is demoted to
//             Tier-3-equivalent. Fresh 32-byte challenge per ceremony, never
//             reused.
//
//   Tier 3  — RFC 6238 TOTP (software + TOTP)
//             Standard 30-second window TOTP via otplib, backed by Node's own
//             `node:crypto` HMAC (no additional crypto implementation pulled
//             in — @otplib/plugin-crypto-node is a thin wrapper over
//             `createHmac`/`randomBytes`/`timingSafeEqual`). Rate-limited: 5
//             attempts per 10-minute window; backoff (exponential, max 60 s)
//             after 3 consecutive failures. `knosky doctor` emits a structured
//             warning when Tier 3 is active and the system clock appears
//             unsynced (drift > 24 h from reference).
//
// governance.yml / minSigningTier:
//   `governance.yml` in the repo root may contain a `minSigningTier` key scoped
//   per district class.  Enforcement is strict at evaluation time: a signer whose
//   tier is below the required minimum is rejected outright, not just flagged.
//
// Mixed-tier quorum:
//   Each signer's tier is recorded in the ledger entry.  The quorum summary tier
//   is the WEAKEST tier across all signers (the highest TIER.* number, since
//   lower numbers are stronger) — never averaged, never strengthened by a
//   stronger co-signer.
//
// Unforgeable logging:
//   The raw WebAuthn assertion bytes are SHA-256 hashed into the EXCEPTION_GRANTED
//   ledger entry so the tool cannot self-report a tier it did not actually use.
//
// Downgrade-attack protection:
//   The tier-detection result together with the active minSigningTier setting are
//   hashed into a checkpoint (buildTierCheckpoint/verifyTierCheckpoint) and signed
//   via signManifest/verifyManifest (key-store.mjs) so those values cannot be
//   rolled back without invalidating the manifest signature.  The wiring is in
//   signTierCheckpoint / verifySignedTierCheckpoint (SAT-562, this module).
//
// Design references: D-193, D-194, OUTPUTS/2026-07-05-KnoSky-F0-F1-DesignGate-v3-Combined.md §F0.1
// Authority: SAT-544.
//
// Mature libraries, no hand-rolled crypto/CBOR/X.509 parsing:
//   - @simplewebauthn/server — WebAuthn attestation + assertion verification,
//     CBOR decoding, X.509 chain validation (Tier 2).
//   - otplib (TOTP class) + @otplib/plugin-crypto-node (Node-native HMAC via
//     node:crypto, zero extra crypto dependency) + @otplib/plugin-base32-scure
//     (audited, zero-dependency Base32) — RFC 6238 TOTP (Tier 3).
// Requires Node >= 20 (SettingsService/verifyRegistrationResponse's engines
// floor; this raised the package's overall `engines.node` from >=18 — flagged
// for Paul's awareness since it affects every knosky user, not just F0).

import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';

import { signManifest, verifyManifest } from './key-store.mjs';

import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  SettingsService,
} from '@simplewebauthn/server';
import { TOTP, ScureBase32Plugin } from 'otplib';
import { NodeCryptoPlugin } from '@otplib/plugin-crypto-node';
import { decodeCBOR } from '@levischuck/tiny-cbor';
import { X509Certificate as PeculiarX509Certificate, CRLDistributionPointsExtension } from '@peculiar/x509';


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
// TIER 1 — TPM / Secure Enclave detection
// ---------------------------------------------------------------------------

/**
 * Attempt to generate a non-extractable ECDSA P-256 key backed by the platform
 * TPM or Secure Enclave.  Returns a `{ tier, key, label }` object.
 *
 * When the platform's hardware key store presence cannot be POSITIVELY
 * confirmed, this function reports `tpmPresent: false` and falls back to
 * TIER.TOTP (software), regardless of which OS is running. This module never
 * infers "this OS version normally ships with a TPM" as a substitute for an
 * actual, verifiable signal — that inference is exactly the failure mode the
 * ticket's "honestly labeled software fallback when absent" requirement
 * exists to prevent.
 *
 * Only Linux is currently probed with a real signal (kernel TPM resource
 * manager device node). macOS (Secure Enclave) and Windows (TPM 2.0) require
 * either a native binding or spawning a platform CLI (`security(1)`,
 * PowerShell's `Get-Tpm`) to positively confirm hardware presence — this
 * module deliberately avoids spawning processes to stay side-effect-free and
 * sandboxable, so those platforms always report `tpmPresent: false` today.
 * This is a known, intentional gap (fails safe: it can only under-claim tier
 * strength, never over-claim it) — see the follow-up ticket for native/CLI
 * probes on those platforms.
 *
 * @returns {Promise<{ tier: number, key: CryptoKey|null, label: string, probeInfo: object }>}
 */
export async function detectTier1Key() {
  const probe = await _probeTpmPresence();

  let key = null;
  try {
    const { webcrypto } = await import('node:crypto');
    key = (await webcrypto.subtle.generateKey(
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
 * Probe for TPM presence without spawning processes that could cause
 * side-effects.  Returns a structured result rather than throwing.
 *
 * Only reports `tpmPresent: true` when a real, verifiable signal exists.
 * Currently that means: Linux kernel TPM resource-manager device node.
 * Every other platform (including macOS and Windows, which MAY have a TPM/
 * Secure Enclave) honestly reports `tpmPresent: false` because this module
 * has no side-effect-free way to positively confirm it on those platforms.
 *
 * @returns {Promise<{ tpmPresent: boolean, mechanism: string|null, detail: string }>}
 */
async function _probeTpmPresence() {
  const platform = os.platform();

  if (platform === 'linux') {
    for (const dev of ['/dev/tpmrm0', '/dev/tpm0']) {
      try {
        fs.accessSync(dev, fs.constants.F_OK);
        return { tpmPresent: true, mechanism: 'Linux TPM (/dev/tpmrm0|/dev/tpm0)', detail: dev };
      } catch { /* dev not present */ }
    }
    return { tpmPresent: false, mechanism: null, detail: 'no /dev/tpmrm0 or /dev/tpm0 device node found' };
  }

  if (platform === 'darwin') {
    return {
      tpmPresent: false,
      mechanism: null,
      detail: 'Secure Enclave presence cannot be confirmed without spawning security(1) or a native IOKit binding; this module does not spawn processes, so darwin always reports software fallback',
    };
  }

  if (platform === 'win32') {
    return {
      tpmPresent: false,
      mechanism: null,
      detail: 'TPM 2.0 presence cannot be confirmed without a native binding or spawning PowerShell (Get-Tpm); this module does not spawn processes, so win32 always reports software fallback',
    };
  }

  return { tpmPresent: false, mechanism: null, detail: 'no hardware key store detection implemented for platform ' + platform };
}

// ---------------------------------------------------------------------------
// TIER 2 — WebAuthn / FIDO2 registration and assertion (@simplewebauthn/server)
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

/** @internal base64url-encode raw bytes for the wire-format envelope the library expects. */
function _b64u(bufLike) {
  return Buffer.isBuffer(bufLike) ? bufLike.toString('base64url') : Buffer.from(bufLike).toString('base64url');
}

/** @internal constant-time challenge comparator, used as the library's `expectedChallenge` function-form. */
function _makeChallengeComparator(expectedChallenge) {
  const expB64 = typeof expectedChallenge === 'string' ? expectedChallenge : _b64u(expectedChallenge);
  return (receivedChallengeB64) => {
    try {
      const a = Buffer.from(receivedChallengeB64, 'base64url');
      const b = Buffer.from(expB64, 'base64url');
      return a.length === b.length && timingSafeEqual(a, b);
    } catch {
      return false;
    }
  };
}

// Placeholder credential id/rawId used only to satisfy the library's
// RegistrationResponseJSON/AuthenticationResponseJSON shape. The library does
// NOT cross-validate this against the credential id embedded in the
// attestation object/authenticatorData for either verification path — it only
// requires `id === rawId` and both being present. The authoritative
// credential id is `result.registrationInfo.credential.id`, derived by the
// library from the parsed authenticatorData itself.
const _PLACEHOLDER_CRED_ID = Buffer.from('knosky-f01-placeholder-credential-id').toString('base64url');

/**
 * @internal
 * KnoSky is a no-egress tool (SECURITY.md). @simplewebauthn/server's x5c
 * chain validation (`validateCertificatePath` -> `isCertRevoked`) performs a
 * real outbound `fetch()` to a certificate's CRL Distribution Point URL IF
 * the presented certificate embeds one — this is attacker/authenticator-
 * influenced input, not something KnoSky's own code chooses to do. Real FIDO
 * authenticator attestation certs conventionally omit CRL distribution
 * points, but nothing stops a crafted attestation from including one.
 *
 * To preserve the no-egress guarantee unconditionally, this module decodes
 * the attestation object's x5c chain itself (via the same mature CBOR/X.509
 * libraries @simplewebauthn/server already depends on — no hand-rolled
 * parsing) and rejects outright, before ever calling into the library, if any
 * certificate in the chain carries a CRL Distribution Points extension.
 *
 * @param {Buffer} attestationObjectBytes
 * @returns {string|null} a rejection reason, or null if no CRL extension was found
 */
function _rejectIfCrlDistributionPoint(attestationObjectBytes) {
  let decoded;
  try {
    decoded = decodeCBOR(new Uint8Array(attestationObjectBytes));
  } catch {
    // Malformed CBOR — let verifyRegistrationResponse's own parsing produce
    // the real, user-facing error message for this case.
    return null;
  }

  const attStmt = decoded instanceof Map ? decoded.get('attStmt') : null;
  const x5c = attStmt instanceof Map ? attStmt.get('x5c') : null;
  if (!Array.isArray(x5c)) return null;

  for (const certDer of x5c) {
    try {
      const bytes = certDer instanceof Uint8Array ? certDer : new Uint8Array(certDer);
      const cert = new PeculiarX509Certificate(bytes);
      const hasCrlExtension = cert.extensions.some(ext => ext instanceof CRLDistributionPointsExtension);
      if (hasCrlExtension) {
        return 'certificate in x5c embeds a CRL Distribution Points extension; rejected to preserve KnoSky\'s no-egress guarantee (no revocation-check network fetch is ever performed)';
      }
    } catch {
      // Malformed certificate — let the real verification path's own parsing
      // surface this error with better context than we could here.
      continue;
    }
  }
  return null;
}

/**
 * @internal
 * @simplewebauthn/server's SettingsService.setRootCertificates is process-wide
 * state, not per-call. Two concurrent verifyWebAuthnAttestation calls with
 * DIFFERENT trustedRoots could otherwise race: call A sets its roots, call B
 * overwrites them with its own before A's verifyRegistrationResponse actually
 * reads them, and A ends up verifying against B's trust anchors. This
 * serializes every call through this single async chain so the
 * "set roots -> verify" critical section can never interleave, regardless of
 * how many verifyWebAuthnAttestation calls are in flight at once. A failed
 * ceremony does not wedge the chain for later callers.
 * @type {Promise<void>}
 */
let _attestationLockChain = Promise.resolve();

/** @internal Run `fn` after any in-flight attestation verification has finished. */
function _withAttestationLock(fn) {
  const run = _attestationLockChain.then(fn, fn);
  _attestationLockChain = run.then(() => undefined, () => undefined);
  return run;
}

/**
 * Verify a WebAuthn attestation registration response.
 *
 * Delegates all CBOR/X.509/COSE parsing and signature verification to
 * @simplewebauthn/server's `verifyRegistrationResponse`. This module's job is
 * limited to: (1) adapting KnoSky's raw-buffer inputs into the wire-format
 * envelope the library expects, (2) configuring the library's trusted-root
 * store per call from caller-supplied `trustedRoots`, (3) applying KnoSky's
 * own tier-demotion rule for backup-eligible credentials, and (4) mapping the
 * library's thrown errors into this module's `{ ok: false, reason }` contract
 * so callers never need a try/catch of their own.
 *
 * Security properties enforced by the library (all real chain/field checks,
 * not self-asserted flags):
 *   1. Full x5c certificate-chain verification against the supplied
 *      trustedRoots, including certificate OU/O/C field conformance,
 *      basicConstraints, validity window, and AAGUID cross-check against the
 *      leaf certificate's extension.
 *   2. Backup-eligible credentials (independently confirmed via the verified
 *      attestation's `credentialDeviceType === 'multiDevice'`, derived from
 *      the authenticatorData BE bit — not a self-report) are demoted to
 *      Tier-3-equivalent.
 *   3. Challenge match (constant-time, via a custom comparator — see below).
 *   4. rpID match.
 *   5. Origin match (NEW vs. the pre-rework implementation, which never
 *      checked origin at all — a real gap this rework closes).
 *   6. User presence (UP) must be asserted.
 *
 * This implementation supports whichever attestation formats
 * @simplewebauthn/server supports (packed, fido-u2f, android-safetynet,
 * android-key, tpm, apple, none) rather than hand-rolling support for only
 * "packed" as the pre-rework code did.
 *
 * @param {object}   opts
 * @param {Buffer}   opts.attestationObject   Raw CBOR attestation object
 * @param {Buffer}   opts.clientDataJSON      Raw client data JSON bytes
 * @param {Buffer|string} opts.expectedChallenge  The 32-byte challenge this server issued
 * @param {string}   opts.expectedRpId        RP ID (usually hostname, e.g. "knosky.local")
 * @param {string}   opts.expectedOrigin      Origin the ceremony must have occurred on
 *                                            (REQUIRED — new vs. pre-rework, which never
 *                                            validated origin)
 * @param {Buffer[]} opts.trustedRoots        PEM or DER buffers of trusted root CA certs
 * @returns {Promise<{
 *   ok: boolean,
 *   tier: number|null,
 *   reason?: string,
 *   credId: string,               // base64url credential id (was a raw Buffer pre-rework)
 *   credentialPublicKey: Uint8Array, // COSE-encoded public key — needed for later assertion
 *                                     // verification; the pre-rework code never returned this
 *                                     // at all, which meant the assertion step had no way to
 *                                     // retrieve the key it needed.
 *   aaguid: string,               // formatted AAGUID string (was a raw 16-byte Buffer pre-rework)
 *   beFlag: boolean,
 *   signCount: number,
 * }>}
 */
export async function verifyWebAuthnAttestation(opts) {
  const { attestationObject, clientDataJSON, expectedChallenge, expectedRpId, expectedOrigin, trustedRoots } = opts;

  if (!expectedOrigin || typeof expectedOrigin !== 'string') {
    return { ok: false, reason: 'expectedOrigin is required (the origin the WebAuthn ceremony occurred on)', tier: null };
  }

  if (!Array.isArray(trustedRoots) || trustedRoots.length === 0) {
    return { ok: false, reason: 'no trusted root CA certificates supplied', tier: null };
  }

  const attestationObjectBuf = Buffer.isBuffer(attestationObject) ? attestationObject : Buffer.from(attestationObject);
  const crlRejectReason = _rejectIfCrlDistributionPoint(attestationObjectBuf);
  if (crlRejectReason) {
    return { ok: false, reason: crlRejectReason, tier: null };
  }

  // Root certs are a process-wide setting in @simplewebauthn/server, keyed
  // by attestation format identifier — set immediately before the verify
  // call, both serialized through _withAttestationLock so no other
  // verifyWebAuthnAttestation call can interleave and overwrite these roots
  // before this call's verifyRegistrationResponse has read them.
  const pemRoots = trustedRoots.map(r => (Buffer.isBuffer(r) ? r : Buffer.from(r)));

  const response = {
    id: _PLACEHOLDER_CRED_ID,
    rawId: _PLACEHOLDER_CRED_ID,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: _b64u(clientDataJSON),
      attestationObject: _b64u(attestationObject),
    },
  };

  let result;
  try {
    result = await _withAttestationLock(async () => {
      for (const fmt of ['packed', 'fido-u2f', 'android-key', 'android-safetynet', 'tpm', 'apple']) {
        SettingsService.setRootCertificates({ identifier: fmt, certificates: pemRoots });
      }
      return verifyRegistrationResponse({
        response,
        expectedChallenge: _makeChallengeComparator(expectedChallenge),
        expectedOrigin,
        expectedRPID: expectedRpId,
        expectedType: 'webauthn.create',
        requireUserPresence: true,
        requireUserVerification: false,
      });
    });
  } catch (err) {
    return { ok: false, reason: err.message, tier: null };
  }

  if (!result.verified) {
    return { ok: false, reason: 'attestation verification failed', tier: null };
  }

  const info = result.registrationInfo;
  // "Backup eligible" (BE, WebAuthn authenticatorData bit 3) means the
  // credential CAN be synced/multi-device; the library surfaces this as
  // credentialDeviceType === 'multiDevice'. This is distinct from BS
  // ("backup state" — IS it currently backed up right now, surfaced as
  // credentialBackedUp), which is not what the ticket's AC is about: a
  // synced-CAPABLE credential is the downgrade risk regardless of whether
  // it happens to be backed up at this exact moment.
  const beFlag = info.credentialDeviceType === 'multiDevice';
  const tier = beFlag ? TIER.TOTP : TIER.WEBAUTHN;
  const tierLabel = beFlag
    ? 'software+TOTP (synced/backup-eligible WebAuthn credential demoted from Tier 2)'
    : TIER_LABELS[TIER.WEBAUTHN];

  return {
    ok: true,
    tier,
    tierLabel,
    credId: info.credential.id,
    credentialPublicKey: info.credential.publicKey,
    aaguid: info.aaguid,
    beFlag,
    signCount: info.credential.counter,
  };
}

/**
 * Verify a WebAuthn assertion (authentication, not registration).
 *
 * Delegates to @simplewebauthn/server's `verifyAuthenticationResponse`, which
 * verifies the assertion signature, challenge, rpID, origin, user presence,
 * and signCount replay detection (throws if the reported counter did not
 * advance past the stored value), then returns the raw assertion bytes hashed
 * into the ledger entry (unforgeable logging AC).
 *
 * @param {object}    opts
 * @param {Buffer}    opts.authData             authenticatorData from the assertion
 * @param {Buffer}    opts.signature            assertion signature
 * @param {Buffer}    opts.clientDataJSON       raw clientDataJSON bytes
 * @param {Buffer|string} opts.expectedChallenge the challenge the server issued
 * @param {string}    opts.expectedRpId         RP ID hostname
 * @param {string}    opts.expectedOrigin       origin the ceremony must have occurred on (REQUIRED)
 * @param {Uint8Array} opts.credentialPublicKey the registered credential's COSE public key
 *                                              (from verifyWebAuthnAttestation's return value)
 * @param {string}    [opts.credentialId]       base64url credential id, if the caller tracks
 *                                              multiple credentials per principal (not
 *                                              cross-validated by the library; informational)
 * @param {number}    opts.storedSignCount      previously stored signCount for this credential
 * @returns {Promise<{
 *   ok: boolean,
 *   reason?: string,
 *   newSignCount: number,
 *   assertionHash: string,   // SHA-256 hex of (authData ‖ signature ‖ clientDataJSON)
 * }>}
 */
export async function verifyWebAuthnAssertion(opts) {
  const {
    authData, signature, clientDataJSON, expectedChallenge, expectedRpId, expectedOrigin,
    credentialPublicKey, credentialId, storedSignCount,
  } = opts;

  if (!expectedOrigin || typeof expectedOrigin !== 'string') {
    return { ok: false, reason: 'expectedOrigin is required (the origin the WebAuthn ceremony occurred on)' };
  }

  const idB64 = typeof credentialId === 'string' && credentialId ? credentialId : _PLACEHOLDER_CRED_ID;

  const response = {
    id: idB64,
    rawId: idB64,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: _b64u(clientDataJSON),
      authenticatorData: _b64u(authData),
      signature: _b64u(signature),
    },
  };

  const credential = {
    id: idB64,
    publicKey: credentialPublicKey instanceof Uint8Array ? credentialPublicKey : new Uint8Array(Buffer.from(credentialPublicKey)),
    counter: storedSignCount,
  };

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: _makeChallengeComparator(expectedChallenge),
      expectedOrigin,
      expectedRPID: expectedRpId,
      expectedType: 'webauthn.get',
      credential,
      requireUserVerification: false,
    });
  } catch (err) {
    return { ok: false, reason: err.message };
  }

  if (!result.verified) {
    return { ok: false, reason: 'assertion signature verification failed' };
  }

  const assertionHash = createHash('sha256')
    .update(Buffer.isBuffer(authData) ? authData : Buffer.from(authData))
    .update(Buffer.isBuffer(signature) ? signature : Buffer.from(signature))
    .update(Buffer.isBuffer(clientDataJSON) ? clientDataJSON : Buffer.from(clientDataJSON))
    .digest('hex');

  return { ok: true, newSignCount: result.authenticationInfo.newCounter, assertionHash };
}

// ---------------------------------------------------------------------------
// TIER 3 — RFC 6238 TOTP (otplib + @otplib/plugin-crypto-node)
// ---------------------------------------------------------------------------

const _totpCrypto = new NodeCryptoPlugin();
const _totpBase32 = new ScureBase32Plugin();

/** @internal Build a TOTP instance sharing KnoSky's fixed algorithm/digit/period policy. */
function _makeTotp() {
  return new TOTP({
    crypto: _totpCrypto,
    base32: _totpBase32,
    algorithm: 'sha1', // RFC 6238 default; matches the pre-rework HMAC-SHA1 implementation
    digits: 6,
    period: 30,
  });
}

/**
 * Generate a new TOTP secret (random 160-bit, Base32-encoded).
 * The secret is suitable for use with RFC 6238 30-second window authenticator apps.
 *
 * @returns {{ secret: Buffer, secretBase32: string }}
 */
export function generateTotpSecret() {
  const secret = randomBytes(20); // 160 bits (recommended per RFC 4226)
  return { secret, secretBase32: _totpBase32.encode(secret) };
}

/**
 * Compute the RFC 6238 TOTP code for `secret` at unix time `ts` (seconds).
 * Uses a 30-second step, 6-digit output.
 *
 * NOTE: this function is now async (it was synchronous pre-rework). otplib's
 * TOTP class is async-first so the same code path works uniformly whether the
 * configured crypto plugin is synchronous (ours is, via node:crypto) or not.
 * No production call site in this repo currently calls this function
 * synchronously — verified via a full-repo search before making this change.
 *
 * @param {Buffer} secret   Raw HMAC-SHA1 key bytes.
 * @param {number} ts       Unix timestamp (seconds since epoch).  Defaults to now.
 * @returns {Promise<string>}   6-digit zero-padded TOTP code.
 */
export async function computeTotpCode(secret, ts = Math.floor(Date.now() / 1000)) {
  const totp = _makeTotp();
  return totp.generate({ secret, epoch: ts });
}

/**
 * Verify a TOTP token against a secret, allowing ±1 step (±30 s drift window,
 * checked both into the past and the future — symmetric tolerance).
 *
 * Note: callers MUST apply rate-limiting before calling this.  See
 * {@link createTotpRateLimiter} for the required guard.
 *
 * @param {Buffer} secret   Raw HMAC-SHA1 key bytes.
 * @param {string} token    6-digit TOTP code to verify.
 * @param {number} ts       Unix timestamp (seconds).  Defaults to now.
 * @returns {Promise<boolean>}
 */
export async function verifyTotpToken(secret, token, ts = Math.floor(Date.now() / 1000)) {
  if (typeof token !== 'string' || !/^\d{6}$/.test(token)) return false;
  const totp = _makeTotp();
  const result = await totp.verify(token, { secret, epoch: ts, epochTolerance: 30 });
  return result.valid;
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
 * TIER.* numbers run strongest-to-weakest (1 = TPM, 2 = WebAuthn, 3 = TOTP),
 * so the quorum's overall tier is the WEAKEST signer, i.e. the numerically
 * HIGHEST tier value — `Math.max()` over the tier numbers. This is
 * intentional: a quorum is only as strong as its weakest signer, and it must
 * never be reported as stronger than that just because other signers used a
 * better tier. (The pre-rework module's own comments here said "MINIMUM
 * across all signers" while the code correctly did `Math.max()` — that
 * comment was simply wrong relative to the numeric encoding and has been
 * corrected in place; the behavior is unchanged.)
 *
 * @param {Array<{signerId: string, tier: number}>} signerTiers
 * @returns {{ summaryTier: number, label: string, signerCount: number }}
 */
export function quorumSummaryTier(signerTiers) {
  if (!Array.isArray(signerTiers) || signerTiers.length === 0) {
    throw new TypeError('quorumSummaryTier: signerTiers must be a non-empty array');
  }
  // Weakest signer defines the quorum. Since lower TIER.* numbers are
  // stronger, the weakest signer has the numerically highest tier value —
  // Math.max() over the tier numbers is correct.
  const summaryTier = Math.max(...signerTiers.map(s => s.tier));
  return {
    summaryTier,
    label: TIER_LABELS[summaryTier],
    signerCount: signerTiers.length,
  };
}

// ---------------------------------------------------------------------------
// Downgrade-attack protection: tier-checkpoint hash
// ---------------------------------------------------------------------------

/**
 * Build a tier-checkpoint object that can be fed into signManifest (F0.2) so
 * the tier-detection result and minSigningTier setting cannot be silently
 * rolled back (e.g. stripping the TPM detection or lowering the minimum tier
 * claim) without invalidating the manifest signature.
 *
 * This object MUST be included in the signed manifest payload for that
 * protection to apply. Use {@link signTierCheckpoint} to produce a manifest
 * signed by the key store, and {@link verifySignedTierCheckpoint} to verify
 * it before trusting the claimed tier.
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

/**
 * Sign a tier-checkpoint by wrapping it in a manifest and calling
 * {@link signManifest} from the key store.
 *
 * Returns a signed manifest object (all checkpoint fields + `key_id` + `sig`)
 * that can be persisted or transmitted.  Consumers MUST call
 * {@link verifySignedTierCheckpoint} before trusting the claimed tier.
 *
 * Throws if there is no active key in the store (same contract as
 * {@link signManifest}).
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks  Key store
 * @param {number} detectedTier      Tier from {@link detectTier1Key}
 * @param {number} minSigningTier    Currently active minimum tier
 * @param {string} districtClass     District class in scope
 * @returns {object}  Signed manifest: tier-checkpoint fields + `key_id` + `sig`
 */
export function signTierCheckpoint(ks, detectedTier, minSigningTier, districtClass) {
  const checkpoint = buildTierCheckpoint(detectedTier, minSigningTier, districtClass);
  return signManifest(ks, checkpoint);
}

/**
 * Verify a signed tier-checkpoint produced by {@link signTierCheckpoint}.
 *
 * Performs two independent checks in order:
 *   1. {@link verifyManifest} — confirms the HMAC-SHA256 signature is valid and
 *      the signing key is present and not revoked in the store.
 *   2. {@link verifyTierCheckpoint} — confirms the embedded SHA-256 checkpoint
 *      hash is internally consistent (downgrade-attack guard).
 *
 * Returns `{ ok: true }` only when both checks pass.
 * Returns `{ ok: false, reason }` for any failure, with the `reason` from
 * whichever check failed first.
 *
 * Never throws on malformed input (inherits that contract from
 * {@link verifyManifest}).
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {object} signedCheckpoint  Value returned by {@link signTierCheckpoint}
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifySignedTierCheckpoint(ks, signedCheckpoint) {
  const manifestResult = verifyManifest(ks, signedCheckpoint);
  if (!manifestResult.ok) return manifestResult;

  const checkpointResult = verifyTierCheckpoint(signedCheckpoint);
  if (!checkpointResult.ok) return checkpointResult;

  return { ok: true };
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
 * This function intentionally performs no authorization/quorum check of its
 * own — that is out of scope here and belongs at the real ledger-write call
 * site (not yet wired in this diff; tracked separately, same pattern as
 * SAT-561 for the append-only checkpoint module).
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
