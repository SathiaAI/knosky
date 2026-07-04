// KnoSky F0.3 — Build provenance: in-toto/DSSE attestation (SAT-547).
//
// Produces a signed DSSE (Dead Simple Signing Envelope) wrapping an
// in-toto provenance statement that binds:
//   - the published npm artifact (name + version + file digest)
//   - the source commit that produced it
//   - the package-lock.json digest (lockfile integrity)
//
// This extends the GitHub Actions OIDC → npm Trusted Publishing pipeline
// (D-162/EPIC Q) with a repo-local attestation: the attestation is signed
// by the project's own release key (the KnoSky key-store, core/key-store.mjs),
// NOT by Sigstore/Fulcio/Rekor — consistent with the project's strict
// no-egress design principle (see SECURITY.md and test/no-egress-v21.test.mjs).
//
// DSSE envelope shape (https://github.com/secure-systems-lab/dsse):
// {
//   payloadType: "application/vnd.in-toto+json",
//   payload:     <base64url(utf8(JSON(statementV1)))>,
//   signatures:  [{ keyid: <key_id>, sig: <base64url(hex-hmac)> }],
// }
//
// in-toto Statement v1 (https://in-toto.io/Statement/v1):
// {
//   _type:   "https://in-toto.io/Statement/v1",
//   subject: [{ name: "<pkg>@<ver>", digest: { sha256: "<hex>" } }],
//   predicateType: "https://slsa.dev/provenance/v1",
//   predicate: {
//     buildDefinition: {
//       buildType: "https://knosky.com/provenance/build/v1",
//       externalParameters: {
//         source_commit: <git-commit-sha>,
//         lockfile_sha256: <hex-sha256-of-package-lock.json>,
//       },
//     },
//     runDetails: {
//       builder:   { id: "https://knosky.com/builders/release-key/v1" },
//       metadata:  { invocationId: <key_id>, finishedOn: <ISO-8601> },
//     },
//   },
// }
//
// Signature PAE (Pre-Authentication Encoding) exactly follows DSSE § 4.2:
//   DSSEv1 + SP + len(payloadType) + SP + payloadType + SP + len(payload) + SP + payload
// where "len" is the decimal byte-length of the UTF-8 encoding.
//
// All inputs are pure in-process data: no file-system access, no network.
// Callers are responsible for reading the source commit and lockfile digest
// from the environment or the filesystem and passing them as plain strings.
//
// Pure Node stdlib, ESM — no third-party dependencies.

import { createHmac } from 'node:crypto';
import { signManifest, verifyManifest } from './key-store.mjs';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** in-toto Statement type URI (v1). */
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';

/** SLSA provenance predicate type URI (v1). */
export const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';

/** KnoSky-specific build type URI (repo-local, no-egress signer). */
export const BUILD_TYPE = 'https://knosky.com/provenance/build/v1';

/** DSSE payload type for in-toto statements. */
export const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

// ---------------------------------------------------------------------------
// makeProvenanceStatement
// ---------------------------------------------------------------------------

/**
 * Construct an in-toto Statement v1 / SLSA Provenance v1 predicate object
 * (plain JS object — not yet encoded or signed).
 *
 * @param {object}  opts
 * @param {string}  opts.packageName      npm package name (e.g. "knosky").
 * @param {string}  opts.packageVersion   npm package version (e.g. "0.6.3").
 * @param {string}  opts.artifactDigest   hex-encoded SHA-256 of the published tarball.
 * @param {string}  opts.sourceCommit     git commit SHA that produced this release.
 * @param {string}  opts.lockfileDigest   hex-encoded SHA-256 of package-lock.json.
 * @param {string}  opts.keyId            `key_id` of the signing key (recorded in runDetails).
 * @param {string}  opts.finishedOn       ISO-8601 timestamp for the attestation (caller-supplied).
 * @returns {object}  A plain JS in-toto Statement v1 object.
 */
export function makeProvenanceStatement({
  packageName,
  packageVersion,
  artifactDigest,
  sourceCommit,
  lockfileDigest,
  keyId,
  finishedOn,
}) {
  if (!packageName || typeof packageName !== 'string') {
    throw new TypeError('makeProvenanceStatement: packageName must be a non-empty string');
  }
  if (!packageVersion || typeof packageVersion !== 'string') {
    throw new TypeError('makeProvenanceStatement: packageVersion must be a non-empty string');
  }
  if (!artifactDigest || !/^[0-9a-f]{64}$/i.test(artifactDigest)) {
    throw new TypeError('makeProvenanceStatement: artifactDigest must be a 64-char hex SHA-256');
  }
  if (!sourceCommit || !/^[0-9a-f]{7,64}$/i.test(sourceCommit)) {
    throw new TypeError('makeProvenanceStatement: sourceCommit must be a hex git SHA (7-64 chars)');
  }
  if (!lockfileDigest || !/^[0-9a-f]{64}$/i.test(lockfileDigest)) {
    throw new TypeError('makeProvenanceStatement: lockfileDigest must be a 64-char hex SHA-256');
  }
  if (!keyId || typeof keyId !== 'string') {
    throw new TypeError('makeProvenanceStatement: keyId must be a non-empty string');
  }
  if (!finishedOn || typeof finishedOn !== 'string') {
    throw new TypeError('makeProvenanceStatement: finishedOn must be a non-empty ISO-8601 string');
  }

  return {
    _type: STATEMENT_TYPE,
    subject: [
      {
        name: `${packageName}@${packageVersion}`,
        digest: { sha256: artifactDigest.toLowerCase() },
      },
    ],
    predicateType: PREDICATE_TYPE,
    predicate: {
      buildDefinition: {
        buildType: BUILD_TYPE,
        externalParameters: {
          source_commit:   sourceCommit.toLowerCase(),
          lockfile_sha256: lockfileDigest.toLowerCase(),
        },
      },
      runDetails: {
        builder: { id: 'https://knosky.com/builders/release-key/v1' },
        metadata: {
          invocationId: keyId,
          finishedOn,
        },
      },
    },
  };
}

// ---------------------------------------------------------------------------
// dssePreAuthEncoding
// ---------------------------------------------------------------------------

/**
 * Compute the DSSE Pre-Authentication Encoding (PAE) for the given
 * payload type and payload bytes (DSSE spec § 4.2):
 *
 *   "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
 *
 * where `len` is the decimal UTF-8 byte-length of the corresponding value.
 *
 * @param {string} payloadType  e.g. "application/vnd.in-toto+json"
 * @param {Buffer|string} payload  The raw payload bytes (or UTF-8 string).
 * @returns {Buffer}
 */
export function dssePreAuthEncoding(payloadType, payload) {
  const ptBuf   = Buffer.from(payloadType, 'utf8');
  const payBuf  = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  // "DSSEv1" SP len(pt) SP pt SP len(pay) SP pay
  const prefix  = Buffer.from(`DSSEv1 ${ptBuf.length} `, 'utf8');
  const middle  = Buffer.from(` ${payBuf.length} `, 'utf8');
  return Buffer.concat([prefix, ptBuf, middle, payBuf]);
}

// ---------------------------------------------------------------------------
// buildDsseEnvelope
// ---------------------------------------------------------------------------

/**
 * Build a signed DSSE envelope wrapping a KnoSky build-provenance statement.
 *
 * The statement is signed using the project's own HMAC-SHA256 release key
 * (via `signManifest` from `core/key-store.mjs`).  No Sigstore, no Fulcio,
 * no Rekor — consistent with KnoSky's no-egress design principle.
 *
 * Signing is done over the DSSE PAE of the JSON-serialised statement:
 *   PAE(DSSE_PAYLOAD_TYPE, JSON.stringify(statement))
 * The resulting HMAC hex digest is base64url-encoded as the `sig` field
 * inside `signatures[0]`.
 *
 * The envelope also carries the raw `_ks_sig` object (output of
 * `signManifest`) so that `verifyDsseEnvelope` can verify it using only
 * the in-process key store — no external verifier required.
 *
 * Envelope shape:
 * ```json
 * {
 *   "payloadType": "application/vnd.in-toto+json",
 *   "payload":     "<base64url(utf8(JSON(statement)))>",
 *   "signatures": [{ "keyid": "<key_id>", "sig": "<base64url(hmac-hex)>" }],
 *   "_ks_sig":    { "key_id": "...", "sig": "...", "_type": "...", ... }
 * }
 * ```
 *
 * `_ks_sig` is a KnoSky-internal field (prefix `_`) carrying the raw
 * `signManifest` output so the envelope is self-verifying against the
 * key store without any additional state.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 *   The KnoSky key store with an active signing key.
 * @param {object} statement
 *   The in-toto Statement object from {@link makeProvenanceStatement}.
 * @returns {object}  The signed DSSE envelope.
 */
export function buildDsseEnvelope(ks, statement) {
  const payloadJson = JSON.stringify(statement);
  const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64url');

  // Build the PAE over which the HMAC is computed.
  const pae = dssePreAuthEncoding(DSSE_PAYLOAD_TYPE, payloadJson);

  // signManifest expects a plain object; wrap the PAE hash as a signing payload.
  // We sign a minimal manifest that carries the PAE digest so all the
  // key-store machinery (key lookup, sig format, revocation checks) is reused
  // unchanged.  The PAE digest is included as `pae_sha256` in the manifest.
  const paeDigest = createHmac('sha256', Buffer.alloc(0))
    .update(pae)
    .digest('hex');

  // Use signManifest with a synthetic manifest that includes the PAE digest.
  // The manifest's sig covers: artifact_type, pae_sha256 (sorted keys →
  // canonical JSON).  This ties the DSSE signature check back to the
  // key-store verification path used everywhere else.
  const signingManifest = {
    artifact_type: 'dsse-provenance',
    pae_sha256: paeDigest,
  };
  const ksSigned = signManifest(ks, signingManifest);

  // DSSE `sig` field: base64url of the HMAC hex bytes (per DSSE § 4.2 —
  // "base64-encoded bytes of the signature").  Node's HMAC outputs 32
  // raw bytes (hex = 64 chars); we encode the raw bytes directly.
  const sigBytes = Buffer.from(ksSigned.sig, 'hex');
  const sigBase64 = sigBytes.toString('base64url');

  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload: payloadBase64,
    signatures: [
      { keyid: ksSigned.key_id, sig: sigBase64 },
    ],
    // Internal field: raw signManifest output for self-verifying with the key store.
    _ks_sig: ksSigned,
  };
}

// ---------------------------------------------------------------------------
// verifyDsseEnvelope
// ---------------------------------------------------------------------------

/**
 * Verify a KnoSky DSSE provenance envelope against the key store.
 *
 * Checks:
 *   1. The envelope is structurally valid (required fields present).
 *   2. The payload decodes to valid JSON containing an in-toto Statement v1.
 *   3. The `_ks_sig` internal token is valid (key present, not revoked, HMAC correct).
 *   4. The PAE digest recorded in `_ks_sig.pae_sha256` matches the PAE of the
 *      current payload — ensuring the payload has not been swapped after signing.
 *
 * Returns `{ ok: true, statement }` on success, or
 * `{ ok: false, reason: string }` on any failure.  Never throws on malformed input.
 *
 * @param {{ keys: Map<string,object>, activeKeyId: string|null }} ks
 * @param {object} envelope  A signed DSSE envelope from {@link buildDsseEnvelope}.
 * @returns {{ ok: boolean, statement?: object, reason?: string }}
 */
export function verifyDsseEnvelope(ks, envelope) {
  // (1) Structural check.
  if (!envelope || typeof envelope !== 'object') {
    return { ok: false, reason: 'envelope_not_object' };
  }
  const { payloadType, payload, _ks_sig } = envelope;
  if (payloadType !== DSSE_PAYLOAD_TYPE) {
    return { ok: false, reason: 'wrong_payload_type' };
  }
  if (typeof payload !== 'string' || payload.length === 0) {
    return { ok: false, reason: 'missing_payload' };
  }
  if (!_ks_sig || typeof _ks_sig !== 'object') {
    return { ok: false, reason: 'missing_ks_sig' };
  }

  // (2) Decode and parse the statement.
  let payloadJson;
  let statement;
  try {
    payloadJson = Buffer.from(payload, 'base64url').toString('utf8');
    statement   = JSON.parse(payloadJson);
  } catch {
    return { ok: false, reason: 'payload_not_valid_json' };
  }
  if (statement._type !== STATEMENT_TYPE) {
    return { ok: false, reason: 'wrong_statement_type' };
  }

  // (3) Verify the _ks_sig token against the key store.
  const ksResult = verifyManifest(ks, _ks_sig);
  if (!ksResult.ok) {
    return { ok: false, reason: `ks_sig_invalid:${ksResult.reason}` };
  }

  // (4) Check the PAE digest.  Re-derive it from the current payload and
  //     compare against what was recorded when the envelope was built.
  const pae         = dssePreAuthEncoding(DSSE_PAYLOAD_TYPE, payloadJson);
  const paeDigest   = createHmac('sha256', Buffer.alloc(0)).update(pae).digest('hex');
  if (_ks_sig.pae_sha256 !== paeDigest) {
    return { ok: false, reason: 'pae_digest_mismatch' };
  }

  return { ok: true, statement };
}
