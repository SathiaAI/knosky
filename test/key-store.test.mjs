// KnoSky key-store rotation/revocation lifecycle tests (SAT-446, SAT-472).
// Run: node test/key-store.test.mjs
import {
  createKeyStore,
  rotateKey,
  revokeKey,
  makeRevocationApproval,
  signManifest,
  verifyManifest,
  getKey,
} from '../core/key-store.mjs';
import { makeIntentManifest } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// Minimal manifest used as signing input throughout.
const baseManifest = makeIntentManifest({
  paths: [{ path: 'src/auth.mjs', sha256: 'abc123' }],
  secret_scan: { status: 'clean' },
});

// ---------------------------------------------------------------------------
// (a) createKeyStore — initial state
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();

  ok('(a) activeKeyId is a non-empty string', typeof ks.activeKeyId === 'string' && ks.activeKeyId.length > 0);
  ok('(a) keys map has one entry', ks.keys.size === 1);

  const entry = ks.keys.get(ks.activeKeyId);
  ok('(a) active key entry exists', !!entry);
  ok('(a) active key status is "active"', entry && entry.status === 'active');
  ok('(a) active key has a created_at ISO string', typeof entry?.created_at === 'string' && entry.created_at.length > 0);
  ok('(a) active key has raw Buffer material', Buffer.isBuffer(entry?.raw));
}

// ---------------------------------------------------------------------------
// (b) signManifest + verifyManifest — round-trip
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signManifest(ks, baseManifest);

  ok('(b) signed manifest has key_id', typeof signed.key_id === 'string' && signed.key_id.length > 0);
  ok('(b) signed manifest has sig (64-char hex)', /^[0-9a-f]{64}$/.test(signed.sig));
  ok('(b) sig is appended without mutating original', !('sig' in baseManifest));

  const result = verifyManifest(ks, signed);
  ok('(b) verifyManifest returns ok:true for fresh sig', result.ok === true, JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// (c) verifyManifest — tampered payload rejected
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signManifest(ks, baseManifest);

  const tampered = { ...signed, paths: [{ path: 'src/evil.mjs', sha256: 'deaddead' }] };
  const result = verifyManifest(ks, tampered);
  ok('(c) tampered payload fails verification', result.ok === false);
  ok('(c) reason is bad_signature', result.reason === 'bad_signature', JSON.stringify(result));
}

// ---------------------------------------------------------------------------
// (d) verifyManifest — missing / unknown key_id
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signManifest(ks, baseManifest);

  // Remove key_id entirely
  const { key_id: _removed, ...noKeyId } = signed;
  const r1 = verifyManifest(ks, noKeyId);
  ok('(d) missing key_id → reason missing_key_id', r1.reason === 'missing_key_id', JSON.stringify(r1));

  // Point to a key_id that does not exist
  const r2 = verifyManifest(ks, { ...signed, key_id: '0'.repeat(32) });
  ok('(d) unknown key_id → reason unknown_key', r2.reason === 'unknown_key', JSON.stringify(r2));
}

// ---------------------------------------------------------------------------
// (e) rotateKey — old key stays verifiable, new key is active
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const oldKeyId = ks.activeKeyId;
  const signedByOld = signManifest(ks, baseManifest);

  const newKeyId = rotateKey(ks);

  ok('(e) rotateKey returns a new key_id', newKeyId !== oldKeyId);
  ok('(e) activeKeyId updated to new key', ks.activeKeyId === newKeyId);
  ok('(e) keys map now has 2 entries', ks.keys.size === 2);

  const oldEntry = ks.keys.get(oldKeyId);
  ok('(e) old key status is "rotated"', oldEntry && oldEntry.status === 'rotated', JSON.stringify(oldEntry));

  const newEntry = ks.keys.get(newKeyId);
  ok('(e) new key status is "active"', newEntry && newEntry.status === 'active');

  // Verify that a manifest signed by the old (now rotated) key still passes.
  const verOld = verifyManifest(ks, signedByOld);
  ok('(e) manifest signed by rotated key still verifies', verOld.ok === true, JSON.stringify(verOld));

  // Sign with the new key and verify.
  const signedByNew = signManifest(ks, baseManifest);
  const verNew = verifyManifest(ks, signedByNew);
  ok('(e) manifest signed by new active key verifies', verNew.ok === true, JSON.stringify(verNew));

  // Cross-verify: old-signed manifest does not match with new key_id
  const crossTampered = { ...signedByOld, key_id: newKeyId };
  const verCross = verifyManifest(ks, crossTampered);
  ok('(e) cross-tampered key_id fails verification', verCross.ok === false, JSON.stringify(verCross));
}

// ---------------------------------------------------------------------------
// (f) revokeKey — manifests signed by revoked keys are rejected
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const revokedId = ks.activeKeyId;
  const signedBeforeRevoke = signManifest(ks, baseManifest);

  revokeKey(ks, revokedId);

  ok('(f) revoked key status is "revoked"', ks.keys.get(revokedId)?.status === 'revoked');
  ok('(f) activeKeyId cleared to null after revoking active key', ks.activeKeyId === null);

  // Verification must reject manifests from the revoked key.
  const vr = verifyManifest(ks, signedBeforeRevoke);
  ok('(f) manifest signed by revoked key is rejected', vr.ok === false);
  ok('(f) reason is key_revoked', vr.reason === 'key_revoked', JSON.stringify(vr));
}

// ---------------------------------------------------------------------------
// (g) revokeKey is idempotent; revoking an unknown key throws
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const keyId = ks.activeKeyId;
  revokeKey(ks, keyId);

  let revokedAgain = false;
  try { revokeKey(ks, keyId); revokedAgain = true; } catch { revokedAgain = false; }
  ok('(g) revoking already-revoked key does not throw', revokedAgain === true);

  let threw = false;
  try { revokeKey(ks, 'does-not-exist'); } catch { threw = true; }
  ok('(g) revoking unknown key_id throws', threw);
}

// ---------------------------------------------------------------------------
// (h) signManifest throws when no active key exists
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  revokeKey(ks, ks.activeKeyId);  // revoke so activeKeyId becomes null

  let threw = false;
  try { signManifest(ks, baseManifest); } catch { threw = true; }
  ok('(h) signManifest with no active key throws', threw);

  // After rotation, signing works again.
  rotateKey(ks);
  let signed = null;
  try { signed = signManifest(ks, baseManifest); } catch { /* leave null */ }
  ok('(h) signManifest works after rotating past a revoked key', signed !== null && typeof signed.sig === 'string');
}

// ---------------------------------------------------------------------------
// (i) rotateKey can be chained; each generation still verifiable
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const gen1Id = ks.activeKeyId;
  const signedGen1 = signManifest(ks, baseManifest);

  const gen2Id = rotateKey(ks);
  const signedGen2 = signManifest(ks, baseManifest);

  const gen3Id = rotateKey(ks);
  const signedGen3 = signManifest(ks, baseManifest);

  ok('(i) three distinct key ids', new Set([gen1Id, gen2Id, gen3Id]).size === 3);

  const vg1 = verifyManifest(ks, signedGen1);
  const vg2 = verifyManifest(ks, signedGen2);
  const vg3 = verifyManifest(ks, signedGen3);
  ok('(i) gen1 (rotated→rotated) manifest still verifies', vg1.ok === true, JSON.stringify(vg1));
  ok('(i) gen2 (rotated) manifest still verifies', vg2.ok === true, JSON.stringify(vg2));
  ok('(i) gen3 (active) manifest verifies', vg3.ok === true, JSON.stringify(vg3));
}

// ---------------------------------------------------------------------------
// (j) getKey — returns metadata without raw material
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const id = ks.activeKeyId;
  const meta = getKey(ks, id);

  ok('(j) getKey returns object', meta !== null && typeof meta === 'object');
  ok('(j) getKey returns key_id', meta?.key_id === id);
  ok('(j) getKey returns status', meta?.status === 'active');
  ok('(j) getKey returns created_at', typeof meta?.created_at === 'string');
  ok('(j) getKey does NOT expose raw key material', !('raw' in (meta || {})));

  ok('(j) getKey returns null for unknown id', getKey(ks, 'no-such-key') === null);
}

// ---------------------------------------------------------------------------
// (k) Signed manifest fields: key_id and sig not part of the signing payload
//     (so attaching a sig to a modified copy with matching key_id still fails)
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signManifest(ks, baseManifest);

  // Swap just the sig field to a different random hex string.
  const badSig = signed.sig.replace(/[0-9a-f]/, c => (parseInt(c, 16) ^ 1).toString(16));
  const badSigManifest = { ...signed, sig: badSig };
  const vr = verifyManifest(ks, badSigManifest);
  ok('(k) corrupted sig is rejected', vr.ok === false && vr.reason === 'bad_signature', JSON.stringify(vr));
}

// ---------------------------------------------------------------------------
// (l) key_id itself is excluded from the signed payload (mutating only key_id
//     while keeping the same sig → unknown_key, not bad_signature, because
//     the key_id we forge is not in the store)
// ---------------------------------------------------------------------------
{
  const ks = createKeyStore();
  const signed = signManifest(ks, baseManifest);

  // Swap only the key_id to one not in the store.
  const mutated = { ...signed, key_id: 'aa'.repeat(16) };
  const vr = verifyManifest(ks, mutated);
  ok('(l) mutated key_id (not in store) → unknown_key', vr.reason === 'unknown_key', JSON.stringify(vr));
}

// ---------------------------------------------------------------------------
// (m) SAT-472: quorum gate — a single compromised key CANNOT unilaterally
//     revoke all other keys.
// ---------------------------------------------------------------------------
{
  // Build a 3-key store: k1 (rotated), k2 (rotated), k3 (active).
  const ks = createKeyStore();
  const k1 = ks.activeKeyId;          // will be demoted to 'rotated'
  const k2 = rotateKey(ks);           // demotes k1 → 'rotated'
  const k3 = rotateKey(ks);           // demotes k2 → 'rotated', k3 active

  // k1 is compromised — attacker has it and tries to revoke k2 unilaterally.
  // Peers of k2: k1 (rotated), k3 (active) → M=2, required quorum=2.
  let threwUnilateral = false;
  try {
    const badApproval = makeRevocationApproval(ks, k1, k2); // only 1 approval
    revokeKey(ks, k2, [badApproval]);
  } catch { threwUnilateral = true; }
  ok('(m) compromised k1 alone CANNOT revoke k2 (quorum not met)', threwUnilateral);
  ok('(m) k2 is still non-revoked after failed unilateral attempt',
    ks.keys.get(k2)?.status !== 'revoked');

  // k1 also tries to revoke k3 (the active key) unilaterally.
  let threwUnilateral2 = false;
  try {
    const badApproval = makeRevocationApproval(ks, k1, k3);
    revokeKey(ks, k3, [badApproval]);
  } catch { threwUnilateral2 = true; }
  ok('(m) compromised k1 alone CANNOT revoke active k3 (quorum not met)', threwUnilateral2);
  ok('(m) k3 is still active after failed unilateral attempt',
    ks.keys.get(k3)?.status === 'active');

  // Legitimate revocation of k2: both k1 AND k3 approve (quorum=2 met).
  let revokedLegit = false;
  try {
    const a1 = makeRevocationApproval(ks, k1, k2);
    const a3 = makeRevocationApproval(ks, k3, k2);
    revokeKey(ks, k2, [a1, a3]);
    revokedLegit = true;
  } catch { revokedLegit = false; }
  ok('(m) k2 IS revoked when quorum (k1+k3) is satisfied', revokedLegit);
  ok('(m) k2 status is "revoked" after legitimate revocation',
    ks.keys.get(k2)?.status === 'revoked');

  // After k2 is revoked, revoking k3 now only needs k1 (M=1, quorum=1).
  let revokedK3 = false;
  try {
    const a1 = makeRevocationApproval(ks, k1, k3);
    revokeKey(ks, k3, [a1]);
    revokedK3 = true;
  } catch { revokedK3 = false; }
  ok('(m) k3 can be revoked when only 1 non-revoked peer remains (quorum met)',
    revokedK3);

  // makeRevocationApproval: target cannot approve its own revocation.
  let selfApproveThrew = false;
  try { makeRevocationApproval(ks, k1, k1); } catch { selfApproveThrew = true; }
  ok('(m) makeRevocationApproval throws when signing key === target key', selfApproveThrew);

  // makeRevocationApproval: revoked key cannot co-sign.
  let revokedSignerThrew = false;
  try { makeRevocationApproval(ks, k3, k1); } catch { revokedSignerThrew = true; }
  ok('(m) makeRevocationApproval throws when signing key is already revoked',
    revokedSignerThrew);

  // Forged approval (random sig bytes) must not satisfy quorum.
  const ks2 = createKeyStore();
  const p1 = ks2.activeKeyId;
  const p2 = rotateKey(ks2);
  const p3 = rotateKey(ks2);  // M=2 for p2, quorum=2
  const realApproval = makeRevocationApproval(ks2, p1, p2);
  const forgedApproval = { key_id: p3, sig: 'a'.repeat(64) }; // wrong sig
  let threwForged = false;
  try { revokeKey(ks2, p2, [realApproval, forgedApproval]); } catch { threwForged = true; }
  ok('(m) forged approval does not count toward quorum', threwForged);

  // Duplicate approval tokens for the same signer do not double-count.
  const ks3 = createKeyStore();
  const q1 = ks3.activeKeyId;
  const q2 = rotateKey(ks3);
  const q3 = rotateKey(ks3);  // M=2 for q2, quorum=2
  const dupApproval = makeRevocationApproval(ks3, q1, q2);
  let threwDup = false;
  try { revokeKey(ks3, q2, [dupApproval, dupApproval]); } catch { threwDup = true; }
  ok('(m) duplicate approval tokens from same signer do not double-count', threwDup);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
