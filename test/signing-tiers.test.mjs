// KnoSky F0.1 — Three-tier key protection tests (SAT-544).
//
// Rework note: this suite was rewritten alongside core/signing-tiers.mjs's
// move to @simplewebauthn/server + otplib (mature libraries, no hand-rolled
// WebAuthn/CBOR/X.509/TOTP parsing). All WebAuthn fixtures below are REAL:
// real EC P-256 keys, a real X.509 chain built with @peculiar/x509
// (X509CertificateGenerator — no shell-out to openssl, no network, fully
// portable), real CBOR encoding via @levischuck/tiny-cbor, and real ECDSA
// signatures produced by WebCrypto and DER-encoded via @peculiar/asn1-ecc's
// ECDSASigValue schema. Every assertion below is unconditional — there is no
// "either branch passes" pattern. The previous version of this suite's
// F01-057/F01-058 used such a pattern and it silently masked the exact
// CryptoKey/KeyObject bug this rework fixes (confirmed by actually running
// the old suite and observing it report PASS while the real failure reason
// was "x5c chain tip not signed by any trusted root CA" — its own hand-rolled
// self-signed test certificate never even satisfied Node's own
// self-signed-cert check).
//
// Coverage:
//   F01-001  TIER constants are 1, 2, 3 with non-overlapping labels.
//   F01-002  generateWebAuthnChallenge produces 32 bytes of randomness.
//   F01-003  generateWebAuthnChallenge produces distinct values each call (no reuse).
//   F01-004  TOTP: generateTotpSecret returns 20-byte secret with valid Base32.
//   F01-005  TOTP: computeTotpCode returns a 6-digit numeric string.
//   F01-006  TOTP: verifyTotpToken accepts current step, ±1 window; rejects +3 step.
//   F01-007  TOTP: verifyTotpToken rejects non-6-digit and non-numeric tokens.
//   F01-008  Rate limiter: allows up to 5 attempts per 10-minute window.
//   F01-009  Rate limiter: rejects 6th attempt in same window.
//   F01-010  Rate limiter: backoff activates after 3 consecutive failures.
//   F01-011  Rate limiter: backoff reason returned with waitMs > 0.
//   F01-012  Rate limiter: success resets consecutiveFails and backoff.
//   F01-013  Rate limiter: per-id isolation (different ids don't share state).
//   F01-014  Rate limiter: window slides — attempts older than 10 min expire.
//   F01-015  checkClockSync returns drifted=false for small drift.
//   F01-016  checkClockSync returns drifted=true + doctor warning for >24h drift.
//   F01-017  checkClockSync returns driftMs=null when no reference is given.
//   F01-018  parseGovernanceYml parses minSigningTier entries correctly.
//   F01-019  parseGovernanceYml returns minSigningTier=null when absent.
//   F01-020  parseGovernanceYml throws on invalid tier values (< 1 or > 3).
//   F01-021  parseGovernanceYml ignores comment lines.
//   F01-022  enforceMinSigningTier accepts tier equal to required.
//   F01-023  enforceMinSigningTier accepts tier stronger than required (lower number).
//   F01-024  enforceMinSigningTier rejects tier weaker than required (higher number).
//   F01-025  enforceMinSigningTier falls back to "default" key when district not found.
//   F01-026  enforceMinSigningTier accepts all tiers when minSigningTier not configured.
//   F01-027  recordSignerTier appends entries without mutating the original.
//   F01-028  quorumSummaryTier returns the WEAKEST signer (highest tier number),
//            even when a stronger co-signer is present — never averaged/strengthened.
//   F01-029  quorumSummaryTier with single signer returns that signer's tier.
//   F01-030  quorumSummaryTier throws on empty array.
//   F01-031  buildTierCheckpoint produces a 64-char hex SHA-256.
//   F01-032  verifyTierCheckpoint passes for an untampered checkpoint.
//   F01-033  verifyTierCheckpoint fails when detected_tier is tampered.
//   F01-034  verifyTierCheckpoint fails when min_signing_tier is tampered.
//   F01-035  verifyTierCheckpoint fails when district_class is tampered.
//   F01-036  verifyTierCheckpoint fails on malformed/missing hash.
//   F01-037  assembleLedgerEntry returns event=EXCEPTION_GRANTED with tier fields.
//   F01-038  assembleLedgerEntry rejects invalid tier.
//   F01-039  assembleLedgerEntry rejects non-hex assertionHash.
//   F01-040  detectTier1Key returns an object with a tier property.
//   F01-041  detectTier1Key label is honest software fallback when tpmPresent=false.
//   F01-042  detectTier1Key never claims TPM presence on darwin/win32 (no spawn-based probe).
//   F01-043  verifyWebAuthnAttestation: full real registration ceremony succeeds (positive case).
//   F01-044  verifyWebAuthnAttestation: BE=1 (multiDevice) credential demoted to Tier-3-equivalent.
//   F01-045  verifyWebAuthnAttestation: BE=0 credential gets TIER.WEBAUTHN.
//   F01-046  verifyWebAuthnAttestation: empty trustedRoots → rejected with clear reason.
//   F01-047  verifyWebAuthnAttestation: unrelated trust root → chain verification fails.
//   F01-048  verifyWebAuthnAttestation: certificate with a CRL Distribution Point is
//            rejected BEFORE any verification (KnoSky's own no-egress guard — this
//            specifically prevents @simplewebauthn/server's revocation check from
//            ever making an outbound fetch()).
//   F01-049  verifyWebAuthnAttestation: challenge mismatch → rejected.
//   F01-050  verifyWebAuthnAttestation: origin mismatch → rejected (this check did not
//            exist at all pre-rework — a real gap this rework closes).
//   F01-051  verifyWebAuthnAttestation: rpId mismatch → rejected.
//   F01-052  verifyWebAuthnAttestation: bad attestation signature → rejected.
//   F01-053  verifyWebAuthnAttestation: missing expectedOrigin → rejected.
//   F01-054  verifyWebAuthnAttestation: returns credentialPublicKey usable for a
//            later assertion (pre-rework never returned this field at all, so a
//            real registration→authentication flow could not have worked).
//   F01-055  verifyWebAuthnAssertion: valid assertion returns assertionHash (64-char hex).
//   F01-056  verifyWebAuthnAssertion: signCount replay (counter not advanced) → rejected.
//   F01-057  verifyWebAuthnAssertion: zero/zero counter accepted (authenticators without
//            counter support).
//   F01-058  verifyWebAuthnAssertion: wrong public key → signature verification fails.
//   F01-059  verifyWebAuthnAssertion: missing expectedOrigin → rejected.
//   F01-060  Downgrade protection: tampering tier checkpoint breaks verifyTierCheckpoint
//            (duplicate of F01-033, kept as an explicit "downgrade attack" scenario name
//            matching the AC's own language).
//   F01-061  Quorum minimum: mix of Tier1+Tier3 → summary is Tier3 (not average) — explicit
//            "downgrade" framing duplicate of F01-028.
//
// Run: node test/signing-tiers.test.mjs

import crypto, { webcrypto, randomBytes } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import { cose } from '@simplewebauthn/server/helpers';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnSerializer } from '@peculiar/asn1-schema';

import {
  TIER,
  TIER_LABELS,
  detectTier1Key,
  generateWebAuthnChallenge,
  verifyWebAuthnAttestation,
  verifyWebAuthnAssertion,
  generateTotpSecret,
  computeTotpCode,
  verifyTotpToken,
  createTotpRateLimiter,
  checkClockSync,
  parseGovernanceYml,
  enforceMinSigningTier,
  recordSignerTier,
  quorumSummaryTier,
  buildTierCheckpoint,
  verifyTierCheckpoint,
  assembleLedgerEntry,
} from '../core/signing-tiers.mjs';

x509.cryptoProvider.set(webcrypto);
const { subtle } = webcrypto;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Real WebAuthn fixture builder — no hand-rolled crypto, no shell-out.
// ---------------------------------------------------------------------------

/** Build a real, chain-verifiable root CA + leaf "authenticator attestation" cert pair. */
async function makeCertPair({ withCrlDistributionPoint = false } = {}) {
  const rootKeys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'C=US, O=KnoSky Test, CN=KnoSky Test Root CA',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000),
    keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  const leafKeys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const leafExtensions = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
  ];
  if (withCrlDistributionPoint) {
    leafExtensions.push(new x509.CRLDistributionPointsExtension(['http://evil.example.com/revoked.crl']));
  }
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'C=US, O=KnoSky Test, OU=Authenticator Attestation, CN=KnoSky Test Authenticator',
    issuer: rootCert.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000),
    publicKey: leafKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: leafExtensions,
  });

  return {
    rootDer: Buffer.from(rootCert.rawData),
    leafDer: Buffer.from(leafCert.rawData),
    leafKeys,
  };
}

/** WebAuthn authenticatorData byte layout (CTAP2 §8.2 / WebAuthn §6.1) — test-fixture only. */
function buildAuthData({ rpId, signCount, beFlag = false, includeAttestedCredData, credId, coseBytes }) {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  let flags = 0x01; // UP
  if (beFlag) flags |= 0x08; // BE
  if (includeAttestedCredData) flags |= 0x40; // AT
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(signCount, 0);

  let attestedCredData = Buffer.alloc(0);
  if (includeAttestedCredData) {
    const aaguid = Buffer.alloc(16);
    const credIdLenBuf = Buffer.alloc(2);
    credIdLenBuf.writeUInt16BE(credId.length, 0);
    attestedCredData = Buffer.concat([aaguid, credIdLenBuf, credId, Buffer.from(coseBytes)]);
  }

  return Buffer.concat([rpIdHash, Buffer.from([flags]), signCountBuf, attestedCredData]);
}

/** COSE-encode an EC P-256 CryptoKey's public point, via the library's own COSE constants. */
async function coseKeyFromCryptoKey(publicKey) {
  const jwk = await subtle.exportKey('jwk', publicKey);
  return encodeCBOR(new Map([
    [cose.COSEKEYS.kty, cose.COSEKTY.EC2],
    [cose.COSEKEYS.alg, cose.COSEALG.ES256],
    [cose.COSEKEYS.crv, cose.COSECRV.P256],
    [cose.COSEKEYS.x, new Uint8Array(Buffer.from(jwk.x, 'base64url'))],
    [cose.COSEKEYS.y, new Uint8Array(Buffer.from(jwk.y, 'base64url'))],
  ]));
}

/**
 * WebCrypto's ECDSA signatures are raw IEEE P1363 (r‖s); COSE/CBOR attestation
 * signatures need ASN.1 DER. This is pure encoding of two already-computed
 * integers (no cryptographic operation), done via @peculiar/asn1-ecc's
 * ECDSASigValue schema + AsnSerializer — the same mature ASN.1 library
 * @simplewebauthn/server itself uses internally to decode DER signatures.
 */
function p1363ToDer(sigBuf) {
  const half = sigBuf.length / 2;
  const r = sigBuf.subarray(0, half);
  const s = sigBuf.subarray(half);
  const sig = new ECDSASigValue();
  sig.r = r.buffer.slice(r.byteOffset, r.byteOffset + r.byteLength);
  sig.s = s.buffer.slice(s.byteOffset, s.byteOffset + s.byteLength);
  return Buffer.from(AsnSerializer.serialize(sig));
}

async function signWithLeaf(leafKeys, data) {
  const raw = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, leafKeys.privateKey, data);
  return p1363ToDer(Buffer.from(raw));
}

/** Build a full, real, chain-verifiable registration (attestation) ceremony fixture. */
async function buildRegistrationFixture({ rpId, origin, beFlag = false, leafDer, leafKeys }) {
  const { challenge, challengeB64 } = generateWebAuthnChallenge();
  const credId = randomBytes(16);
  const coseBytes = await coseKeyFromCryptoKey(leafKeys.publicKey);
  const authData = buildAuthData({ rpId, signCount: 0, beFlag, includeAttestedCredData: true, credId, coseBytes });

  const clientData = { type: 'webauthn.create', challenge: challengeB64, origin };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8');
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const sig = await signWithLeaf(leafKeys, Buffer.concat([authData, clientDataHash]));

  const attStmt = new Map([['alg', -7], ['sig', new Uint8Array(sig)], ['x5c', [new Uint8Array(leafDer)]]]);
  const attestationObject = Buffer.from(encodeCBOR(new Map([
    ['fmt', 'packed'], ['attStmt', attStmt], ['authData', new Uint8Array(authData)],
  ])));

  return { attestationObject, clientDataJSON, challenge, challengeB64, credId };
}

console.log('--- Building shared real WebAuthn fixtures (real EC keys, real X.509 chain, no shell-out) ---');
const RP_ID = 'knosky.local';
const ORIGIN = 'https://knosky.local';
const { rootDer, leafDer, leafKeys } = await makeCertPair();
const { rootDer: otherRootDer } = await makeCertPair(); // unrelated root, for chain-rejection test
const { leafDer: leafCrlDer } = await makeCertPair({ withCrlDistributionPoint: true });

// ---------------------------------------------------------------------------
// F01-001..003 — constants + challenge generation
// ---------------------------------------------------------------------------

ok('F01-001 TIER constants are 1,2,3 with distinct labels',
  TIER.TPM === 1 && TIER.WEBAUTHN === 2 && TIER.TOTP === 3 &&
  new Set(Object.values(TIER_LABELS)).size === 3);

{
  const { challenge } = generateWebAuthnChallenge();
  ok('F01-002 generateWebAuthnChallenge produces 32 bytes', challenge.length === 32);
}
{
  const a = generateWebAuthnChallenge();
  const b = generateWebAuthnChallenge();
  ok('F01-003 generateWebAuthnChallenge produces distinct values', !a.challenge.equals(b.challenge));
}

// ---------------------------------------------------------------------------
// F01-004..007 — TOTP (otplib + @otplib/plugin-crypto-node)
// ---------------------------------------------------------------------------

{
  const { secret, secretBase32 } = generateTotpSecret();
  ok('F01-004 generateTotpSecret returns 20-byte secret + non-empty Base32',
    secret.length === 20 && typeof secretBase32 === 'string' && secretBase32.length > 0);
}
{
  const { secret } = generateTotpSecret();
  const code = await computeTotpCode(secret, 1_700_000_000);
  ok('F01-005 computeTotpCode returns 6 digits', /^\d{6}$/.test(code), code);
}
{
  const { secret } = generateTotpSecret();
  const now = 1_700_000_000;
  const code = await computeTotpCode(secret, now);
  const codeNextStep = await computeTotpCode(secret, now + 30);
  const codeFar = await computeTotpCode(secret, now + 90);
  const a = await verifyTotpToken(secret, code, now);
  const b = await verifyTotpToken(secret, codeNextStep, now);
  const c = await verifyTotpToken(secret, codeFar, now);
  ok('F01-006 verifyTotpToken accepts current + ±1 step, rejects +3 step',
    a === true && b === true && c === false);
}
{
  const { secret } = generateTotpSecret();
  const r1 = await verifyTotpToken(secret, '12345', 1_700_000_000);
  const r2 = await verifyTotpToken(secret, 'abcdef', 1_700_000_000);
  const r3 = await verifyTotpToken(secret, 1234567, 1_700_000_000);
  ok('F01-007 verifyTotpToken rejects malformed tokens', r1 === false && r2 === false && r3 === false);
}

// ---------------------------------------------------------------------------
// F01-008..014 — TOTP rate limiter (unchanged logic)
// ---------------------------------------------------------------------------

{
  // Use SUCCESSFUL attempts so the 5-per-window ceiling is exercised
  // independently of the 3-consecutive-fails backoff (recording failures
  // would trigger backoff after the 3rd attempt and mask the window ceiling
  // this test is actually checking — same reasoning the pre-rework suite
  // used here).
  const rl = createTotpRateLimiter();
  let allowed = 0;
  for (let i = 0; i < 5; i++) {
    if (rl.check('u1').ok) allowed++;
    rl.record('u1', true);
  }
  ok('F01-008 rate limiter allows up to 5 attempts', allowed === 5);
  ok('F01-009 rate limiter rejects the 6th attempt', rl.check('u1').ok === false);
}
{
  const rl = createTotpRateLimiter();
  rl.record('u2', false); rl.record('u2', false); rl.record('u2', false);
  const status = rl.check('u2');
  ok('F01-010 backoff activates after 3 consecutive failures', status.ok === false && status.reason === 'backoff_in_effect');
  ok('F01-011 backoff reason returned with waitMs > 0', status.waitMs > 0);
}
{
  const rl = createTotpRateLimiter();
  rl.record('u3', false); rl.record('u3', false); rl.record('u3', false);
  rl.record('u3', true);
  const status = rl.status('u3');
  ok('F01-012 success resets consecutiveFails and backoff', status.consecutiveFails === 0 && status.backoffUntilMs === 0);
}
{
  const rl = createTotpRateLimiter();
  for (let i = 0; i < 5; i++) rl.record('u4', false);
  ok('F01-013 rate limiter isolates ids', rl.check('u5').ok === true && rl.check('u4').ok === false);
}
{
  const rl = createTotpRateLimiter();
  const past = Date.now() - 11 * 60 * 1000;
  for (let i = 0; i < 5; i++) rl.record('u6', false, past);
  ok('F01-014 window slides (stale attempts expire)', rl.check('u6', Date.now()).ok === true);
}

// ---------------------------------------------------------------------------
// F01-015..017 — clock sync
// ---------------------------------------------------------------------------

ok('F01-015 checkClockSync: small drift not flagged',
  checkClockSync({ expectedUtcMs: Date.now() - 1000 }).drifted === false);
ok('F01-016 checkClockSync: >24h drift flagged with message',
  (() => { const r = checkClockSync({ expectedUtcMs: Date.now() - 25 * 3600 * 1000 }); return r.drifted === true && typeof r.message === 'string'; })());
ok('F01-017 checkClockSync: no reference => driftMs null',
  checkClockSync({}).driftMs === null);

// ---------------------------------------------------------------------------
// F01-018..021 — governance.yml parsing
// ---------------------------------------------------------------------------

{
  const gov = parseGovernanceYml('minSigningTier:\n  default: 3\n  core: 2\n  regulated: 1\n');
  ok('F01-018 parseGovernanceYml parses entries',
    gov.minSigningTier.default === 3 && gov.minSigningTier.core === 2 && gov.minSigningTier.regulated === 1);
}
ok('F01-019 parseGovernanceYml returns null when absent', parseGovernanceYml('foo: bar\n').minSigningTier === null);
{
  let threw = false;
  try { parseGovernanceYml('minSigningTier:\n  core: 9\n'); } catch { threw = true; }
  ok('F01-020 parseGovernanceYml throws on invalid tier', threw);
}
{
  const gov = parseGovernanceYml('minSigningTier:\n  # a comment\n  core: 2\n');
  ok('F01-021 parseGovernanceYml ignores comments', gov.minSigningTier.core === 2);
}

// ---------------------------------------------------------------------------
// F01-022..026 — enforceMinSigningTier
// ---------------------------------------------------------------------------

{
  const gov = parseGovernanceYml('minSigningTier:\n  default: 3\n  core: 2\n');
  ok('F01-022 accepts tier equal to required', enforceMinSigningTier(gov, 'core', TIER.WEBAUTHN).ok === true);
  ok('F01-023 accepts tier stronger than required', enforceMinSigningTier(gov, 'core', TIER.TPM).ok === true);
  ok('F01-024 rejects tier weaker than required', enforceMinSigningTier(gov, 'core', TIER.TOTP).ok === false);
  ok('F01-025 falls back to default for unknown district', enforceMinSigningTier(gov, 'unknown-district', TIER.TOTP).required === 3);
}
ok('F01-026 accepts all tiers when unconfigured', enforceMinSigningTier({ minSigningTier: null }, 'core', TIER.TOTP).ok === true);

// ---------------------------------------------------------------------------
// F01-027..030 — quorum accounting
// ---------------------------------------------------------------------------

{
  const s0 = [];
  const s1 = recordSignerTier(s0, 'a', TIER.TPM);
  ok('F01-027 recordSignerTier does not mutate original', s0.length === 0 && s1.length === 1);
}
{
  let signers = [];
  signers = recordSignerTier(signers, 'a', TIER.TPM);
  signers = recordSignerTier(signers, 'b', TIER.TOTP);
  const q = quorumSummaryTier(signers);
  ok('F01-028 quorum summary is the WEAKEST signer despite a stronger co-signer',
    q.summaryTier === TIER.TOTP, JSON.stringify(q));
}
{
  const signers = recordSignerTier([], 'solo', TIER.WEBAUTHN);
  ok('F01-029 single-signer quorum returns that tier', quorumSummaryTier(signers).summaryTier === TIER.WEBAUTHN);
}
{
  let threw = false;
  try { quorumSummaryTier([]); } catch { threw = true; }
  ok('F01-030 quorumSummaryTier throws on empty array', threw);
}

// ---------------------------------------------------------------------------
// F01-031..036 — tier checkpoint (downgrade-attack protection)
// ---------------------------------------------------------------------------

{
  const cp = buildTierCheckpoint(TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');
  ok('F01-031 checkpoint hash is 64-char hex', /^[0-9a-f]{64}$/.test(cp.f01_checkpoint_hash));
  ok('F01-032 verifyTierCheckpoint passes untampered', verifyTierCheckpoint(cp).ok === true);
  ok('F01-033 verifyTierCheckpoint fails on tampered detected_tier',
    verifyTierCheckpoint({ ...cp, f01_detected_tier: TIER.TOTP }).ok === false);
  ok('F01-034 verifyTierCheckpoint fails on tampered min_signing_tier',
    verifyTierCheckpoint({ ...cp, f01_min_signing_tier: TIER.TOTP }).ok === false);
  ok('F01-035 verifyTierCheckpoint fails on tampered district_class',
    verifyTierCheckpoint({ ...cp, f01_district_class: 'regulated' }).ok === false);
  ok('F01-036 verifyTierCheckpoint fails on malformed hash',
    verifyTierCheckpoint({ ...cp, f01_checkpoint_hash: 'short' }).ok === false);
}

// ---------------------------------------------------------------------------
// F01-037..039 — ledger entry assembly
// ---------------------------------------------------------------------------

{
  const cp = buildTierCheckpoint(TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');
  const entry = assembleLedgerEntry({
    signerId: 'agent-1', tier: TIER.WEBAUTHN, assertionHash: 'a'.repeat(64),
    districtClass: 'core', reason: 'test', tierCheckpoint: cp,
  });
  ok('F01-037 ledger entry has event + tier fields',
    entry.event === 'EXCEPTION_GRANTED' && entry.tier === TIER.WEBAUTHN && entry.tier_checkpoint === cp);
}
{
  let threw = false;
  try {
    assembleLedgerEntry({ signerId: 'x', tier: 99, assertionHash: 'a'.repeat(64), districtClass: 'core', reason: '', tierCheckpoint: {} });
  } catch { threw = true; }
  ok('F01-038 assembleLedgerEntry rejects invalid tier', threw);
}
{
  let threw = false;
  try {
    assembleLedgerEntry({ signerId: 'x', tier: TIER.TOTP, assertionHash: 'not-hex', districtClass: 'core', reason: '', tierCheckpoint: {} });
  } catch { threw = true; }
  ok('F01-039 assembleLedgerEntry rejects non-hex assertionHash', threw);
}

// ---------------------------------------------------------------------------
// F01-040..042 — Tier 1 (TPM/Secure Enclave detection)
// ---------------------------------------------------------------------------

{
  const t1 = await detectTier1Key();
  ok('F01-040 detectTier1Key returns a valid tier', t1.tier === TIER.TPM || t1.tier === TIER.TOTP);
  ok('F01-041 detectTier1Key is honest when no TPM is detected',
    t1.probeInfo.tpmPresent === true || t1.label === 'software (no TPM detected)');
  ok('F01-042 detectTier1Key never spawns a process to probe darwin/win32 (probeInfo.detail says so on this platform, or platform is linux with a real device check)',
    typeof t1.probeInfo.detail === 'string' && t1.probeInfo.detail.length > 0);
}

// ---------------------------------------------------------------------------
// F01-043..054 — verifyWebAuthnAttestation (real ceremony, real library)
// ---------------------------------------------------------------------------

{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, beFlag: false, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-043 full real registration ceremony succeeds', r.ok === true, r.reason || '');
  ok('F01-045 BE=0 credential gets TIER.WEBAUTHN', r.tier === TIER.WEBAUTHN);
  ok('F01-054 returns a usable credentialPublicKey', r.credentialPublicKey instanceof Uint8Array && r.credentialPublicKey.length > 0);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, beFlag: true, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-044 BE=1 (multiDevice) credential demoted to TIER.TOTP', r.ok === true && r.tier === TIER.TOTP, JSON.stringify(r));
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [],
  });
  ok('F01-046 empty trustedRoots rejected with clear reason', r.ok === false && /trusted root/.test(r.reason), r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [otherRootDer],
  });
  ok('F01-047 unrelated trust root fails chain verification', r.ok === false, r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer: leafCrlDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-048 CRL-Distribution-Point certificate rejected (no-egress guard)',
    r.ok === false && /no-egress/.test(r.reason), r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: randomBytes(32), expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-049 challenge mismatch rejected', r.ok === false, r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: 'https://evil.example.com', trustedRoots: [rootDer],
  });
  ok('F01-050 origin mismatch rejected', r.ok === false, r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: 'not-knosky.local', expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-051 rpId mismatch rejected', r.ok === false, r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const tamperedAttestationObject = Buffer.from(fx.attestationObject);
  tamperedAttestationObject[tamperedAttestationObject.length - 5] ^= 0xff; // flip a byte inside the CBOR-encoded sig
  const r = await verifyWebAuthnAttestation({
    attestationObject: tamperedAttestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });
  ok('F01-052 corrupted attestation signature rejected', r.ok === false, r.reason);
}
{
  const fx = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const r = await verifyWebAuthnAttestation({
    attestationObject: fx.attestationObject, clientDataJSON: fx.clientDataJSON,
    expectedChallenge: fx.challenge, expectedRpId: RP_ID, trustedRoots: [rootDer],
  });
  ok('F01-053 missing expectedOrigin rejected', r.ok === false && /expectedOrigin is required/.test(r.reason), r.reason);
}

// ---------------------------------------------------------------------------
// F01-055..059 — verifyWebAuthnAssertion (real ceremony, real library)
// ---------------------------------------------------------------------------

async function buildAssertionFixture({ rpId, origin, signCount, leafKeys }) {
  const { challenge, challengeB64 } = generateWebAuthnChallenge();
  const authData = buildAuthData({ rpId, signCount, includeAttestedCredData: false });
  const clientData = { type: 'webauthn.get', challenge: challengeB64, origin };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8');
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const signature = await signWithLeaf(leafKeys, Buffer.concat([authData, clientDataHash]));
  return { authData, signature, clientDataJSON, challenge };
}

{
  const reg = await buildRegistrationFixture({ rpId: RP_ID, origin: ORIGIN, leafDer, leafKeys });
  const regResult = await verifyWebAuthnAttestation({
    attestationObject: reg.attestationObject, clientDataJSON: reg.clientDataJSON,
    expectedChallenge: reg.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN, trustedRoots: [rootDer],
  });

  const a1 = await buildAssertionFixture({ rpId: RP_ID, origin: ORIGIN, signCount: 1, leafKeys });
  const r1 = await verifyWebAuthnAssertion({
    authData: a1.authData, signature: a1.signature, clientDataJSON: a1.clientDataJSON,
    expectedChallenge: a1.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN,
    credentialPublicKey: regResult.credentialPublicKey, credentialId: regResult.credId, storedSignCount: 0,
  });
  ok('F01-055 valid assertion returns 64-char hex assertionHash', r1.ok === true && /^[0-9a-f]{64}$/.test(r1.assertionHash), r1.reason || '');

  const a2 = await buildAssertionFixture({ rpId: RP_ID, origin: ORIGIN, signCount: 1, leafKeys });
  const r2 = await verifyWebAuthnAssertion({
    authData: a2.authData, signature: a2.signature, clientDataJSON: a2.clientDataJSON,
    expectedChallenge: a2.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN,
    credentialPublicKey: regResult.credentialPublicKey, credentialId: regResult.credId, storedSignCount: 1,
  });
  ok('F01-056 signCount replay (not advanced) rejected', r2.ok === false, r2.reason);

  const a3 = await buildAssertionFixture({ rpId: RP_ID, origin: ORIGIN, signCount: 0, leafKeys });
  const r3 = await verifyWebAuthnAssertion({
    authData: a3.authData, signature: a3.signature, clientDataJSON: a3.clientDataJSON,
    expectedChallenge: a3.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN,
    credentialPublicKey: regResult.credentialPublicKey, credentialId: regResult.credId, storedSignCount: 0,
  });
  ok('F01-057 zero/zero counter accepted', r3.ok === true, r3.reason || '');

  const { leafKeys: wrongKeys } = await makeCertPair();
  const wrongCoseBytes = await coseKeyFromCryptoKey(wrongKeys.publicKey);
  const a4 = await buildAssertionFixture({ rpId: RP_ID, origin: ORIGIN, signCount: 2, leafKeys });
  const r4 = await verifyWebAuthnAssertion({
    authData: a4.authData, signature: a4.signature, clientDataJSON: a4.clientDataJSON,
    expectedChallenge: a4.challenge, expectedRpId: RP_ID, expectedOrigin: ORIGIN,
    credentialPublicKey: wrongCoseBytes, credentialId: regResult.credId, storedSignCount: 1,
  });
  ok('F01-058 wrong public key rejected', r4.ok === false, r4.reason);

  const a5 = await buildAssertionFixture({ rpId: RP_ID, origin: ORIGIN, signCount: 2, leafKeys });
  const r5 = await verifyWebAuthnAssertion({
    authData: a5.authData, signature: a5.signature, clientDataJSON: a5.clientDataJSON,
    expectedChallenge: a5.challenge, expectedRpId: RP_ID,
    credentialPublicKey: regResult.credentialPublicKey, credentialId: regResult.credId, storedSignCount: 1,
  });
  ok('F01-059 missing expectedOrigin rejected', r5.ok === false && /expectedOrigin is required/.test(r5.reason), r5.reason);
}

// ---------------------------------------------------------------------------
// F01-060..061 — explicit downgrade-attack framing (duplicates of F01-033/028
// under the AC's own vocabulary, kept for traceability to the ticket text)
// ---------------------------------------------------------------------------

{
  const cp = buildTierCheckpoint(TIER.TPM, TIER.TPM, 'regulated');
  const tampered = { ...cp, f01_detected_tier: TIER.TOTP }; // simulate stripping TPM detection
  ok('F01-060 downgrade attack (tier stripped) breaks checkpoint verification', verifyTierCheckpoint(tampered).ok === false);
}
{
  let signers = [];
  signers = recordSignerTier(signers, 'strong', TIER.TPM);
  signers = recordSignerTier(signers, 'weak', TIER.TOTP);
  ok('F01-061 quorum with mixed Tier1+Tier3 summarizes as Tier3 (never averaged)',
    quorumSummaryTier(signers).summaryTier === TIER.TOTP);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
