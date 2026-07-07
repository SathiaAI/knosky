// SAT-562: Integration tests — buildTierCheckpoint/verifyTierCheckpoint wired
// into signManifest/verifyManifest via signTierCheckpoint/verifySignedTierCheckpoint.
//
// Coverage:
//   F562-001  signTierCheckpoint returns a manifest with key_id + 64-char hex sig.
//   F562-002  verifySignedTierCheckpoint accepts a freshly signed checkpoint.
//   F562-003  verifySignedTierCheckpoint rejects a tampered detected_tier field.
//   F562-004  verifySignedTierCheckpoint rejects a tampered min_signing_tier field.
//   F562-005  verifySignedTierCheckpoint rejects a tampered district_class field.
//   F562-006  verifySignedTierCheckpoint rejects a tampered f01_checkpoint_hash.
//   F562-007  verifySignedTierCheckpoint rejects a tampered HMAC sig (bad_signature).
//   F562-008  verifySignedTierCheckpoint rejects a manifest signed by a revoked key.
//   F562-009  verifySignedTierCheckpoint still accepts a manifest signed by a
//             rotated (not revoked) key.
//   F562-010  signTierCheckpoint throws when no active key in the store.
//   F562-011  After key rotation, old signed checkpoint remains verifiable.
//   F562-012  Round-trip: all three TIER values produce verifiable signed checkpoints.
//
// Run: node test/signing-tiers-keystore-integration.test.mjs

import {
  TIER,
  buildTierCheckpoint,
  signTierCheckpoint,
  verifySignedTierCheckpoint,
} from '../core/signing-tiers.mjs';

import {
  createKeyStore,
  rotateKey,
  revokeKey,
} from '../core/key-store.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// F562-001 — signTierCheckpoint returns a well-formed signed manifest
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');

  ok('F562-001 signed checkpoint has key_id',
    typeof signed.key_id === 'string' && signed.key_id.length > 0);
  ok('F562-001 signed checkpoint has 64-char hex sig',
    /^[0-9a-f]{64}$/.test(signed.sig));
  ok('F562-001 signed checkpoint carries tier fields',
    signed.f01_detected_tier === TIER.WEBAUTHN &&
    signed.f01_min_signing_tier === TIER.WEBAUTHN &&
    signed.f01_district_class === 'core' &&
    /^[0-9a-f]{64}$/.test(signed.f01_checkpoint_hash));
}

// ---------------------------------------------------------------------------
// F562-002 — verifySignedTierCheckpoint accepts a freshly signed checkpoint
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signTierCheckpoint(ks, TIER.TPM, TIER.TPM, 'regulated');
  const result = verifySignedTierCheckpoint(ks, signed);
  ok('F562-002 verifySignedTierCheckpoint accepts fresh signed checkpoint',
    result.ok === true, JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// F562-003..006 — field-tampering breaks verification
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');

  const r3 = verifySignedTierCheckpoint(ks, { ...signed, f01_detected_tier: TIER.TOTP });
  ok('F562-003 tampered detected_tier rejected', r3.ok === false, JSON.stringify(r3));

  const r4 = verifySignedTierCheckpoint(ks, { ...signed, f01_min_signing_tier: TIER.TOTP });
  ok('F562-004 tampered min_signing_tier rejected', r4.ok === false, JSON.stringify(r4));

  const r5 = verifySignedTierCheckpoint(ks, { ...signed, f01_district_class: 'regulated' });
  ok('F562-005 tampered district_class rejected', r5.ok === false, JSON.stringify(r5));

  // Directly forge the checkpoint hash to match the tampered values —
  // verifyManifest must still catch the HMAC mismatch.
  const forgedCp = buildTierCheckpoint(TIER.TOTP, TIER.WEBAUTHN, 'core');
  const r6 = verifySignedTierCheckpoint(ks, {
    ...signed,
    f01_detected_tier: TIER.TOTP,
    f01_checkpoint_hash: forgedCp.f01_checkpoint_hash,
  });
  ok('F562-006 forged checkpoint_hash with tampered fields rejected by HMAC',
    r6.ok === false, JSON.stringify(r6));
}

// ---------------------------------------------------------------------------
// F562-007 — tampered HMAC sig is rejected (bad_signature)
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');
  const badSig = signed.sig.replace(/[0-9a-f]/, c => (parseInt(c, 16) ^ 1).toString(16));
  const result = verifySignedTierCheckpoint(ks, { ...signed, sig: badSig });
  ok('F562-007 corrupted HMAC sig rejected',
    result.ok === false && result.reason === 'bad_signature', JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// F562-008 — revoked key causes rejection
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signingKeyId = ks.activeKeyId;
  const signed = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');

  revokeKey(ks, signingKeyId);

  const result = verifySignedTierCheckpoint(ks, signed);
  ok('F562-008 signed checkpoint rejected after key revocation',
    result.ok === false && result.reason === 'key_revoked', JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// F562-009 — rotated (not revoked) key still verifies
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');

  rotateKey(ks); // demotes signing key to 'rotated', does NOT revoke it

  const result = verifySignedTierCheckpoint(ks, signed);
  ok('F562-009 signed checkpoint still verifiable after key rotation',
    result.ok === true, JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// F562-010 — signTierCheckpoint throws when no active key
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  revokeKey(ks, ks.activeKeyId); // leaves activeKeyId null

  let threw = false;
  try { signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core'); } catch { threw = true; }
  ok('F562-010 signTierCheckpoint throws with no active key', threw);
}

// ---------------------------------------------------------------------------
// F562-011 — old signed checkpoint remains verifiable after key rotation
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signedByOld = signTierCheckpoint(ks, TIER.TPM, TIER.TPM, 'regulated');

  rotateKey(ks);
  const signedByNew = signTierCheckpoint(ks, TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');

  const rOld = verifySignedTierCheckpoint(ks, signedByOld);
  const rNew = verifySignedTierCheckpoint(ks, signedByNew);

  ok('F562-011 pre-rotation checkpoint still verifies after rotation',
    rOld.ok === true, JSON.stringify(rOld));
  ok('F562-011 post-rotation checkpoint verifies', rNew.ok === true, JSON.stringify(rNew));
}

// ---------------------------------------------------------------------------
// F562-012 — round-trip for all three TIER values
// ---------------------------------------------------------------------------
{
  for (const [label, tier] of [['TPM', TIER.TPM], ['WEBAUTHN', TIER.WEBAUTHN], ['TOTP', TIER.TOTP]]) {
    const ks = createKeyStore();
    const signed = signTierCheckpoint(ks, tier, tier, 'default');
    const result = verifySignedTierCheckpoint(ks, signed);
    ok(`F562-012 round-trip for TIER.${label}`, result.ok === true, JSON.stringify(result));
  }
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
