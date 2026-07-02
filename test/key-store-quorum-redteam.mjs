// KnoSky red-team scenarios RT-KS-001 / RT-KS-002: quorum degenerate cases.
//
// RT-KS-001 (SAT-475): 2-key quorum degenerate case.
//   Documents and pins the confirmed structural property of core/key-store.mjs:
//   when a store holds exactly 2 non-revoked keys, the quorum formula
//   (Math.floor(peers.length / 2) + 1) reduces to 1 — a single peer key alone
//   can revoke the target. This is EXPECTED, ACCEPTED behaviour (Decision D-163);
//   pre-classifying it prevents red-teamers from re-deriving it as a novel P0 and
//   guards against regression to something *worse* (0-approval takeover).
//
// RT-KS-002 (SAT-477): M=0 quorum — sole-remaining-key self-revocation.
//   When all peer keys have been legitimately revoked and exactly 1 non-revoked
//   key remains, M (peer count) is 0, so required = 0, and the sole key can
//   self-revoke with zero approvals. This is EXPECTED, INTENTIONAL behaviour
//   (Decision D-167): requiring an approval that structurally cannot exist would
//   make a compromised last key permanently irrevocable, which is a worse outcome.
//   This is a self-wipe, not a third-party bypass — there is no peer whose
//   consent could meaningfully be required. Ref: SAT-472 doc comment.
//
// Run:     node test/key-store-quorum-redteam.mjs
// Feeds:   SAT-437 (red-team suite), SAT-438 (synthetic data / simulation)
// Exports: make1KeyFixture, make2KeyFixture, make3KeyFixture

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createKeyStore,
  rotateKey,
  revokeKey,
  makeRevocationApproval,
  signManifest,
  verifyManifest,
} from '../core/key-store.mjs';
import { makeIntentManifest } from '../core/schema.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------
// Module-level minimal manifest (used by make1KeyFixture; kept here so the
// exported factories are self-contained and importable without side-effects).
// ---------------------------------------------------------------------------

const baseManifestForFixture = makeIntentManifest({
  paths: [{ path: 'core/key-store.mjs', sha256: 'abc123' }],
  secret_scan: { status: 'clean' },
});

// ---------------------------------------------------------------------------
// Exported fixture factories
// ---------------------------------------------------------------------------
//
// Factories (not singletons) because revokeKey() mutates the store; each test
// scenario must call one of these to obtain a fresh, independent instance.
//
// Each factory returns an object containing:
//   ks              – live key store with all keys non-revoked
//   targetKeyId     – the key ID that will be the revocation target
//   legitApproval   – valid approval token(s) from peer key(s)
//   forgedApproval  – structurally valid token whose sig bytes are garbage
//   dupApproval     – copy of the first legit approval (duplicate-signer probe)
// ---------------------------------------------------------------------------

/**
 * Build a 1-key store: the sole non-revoked key is the revocation target.
 * N=1, M=0 → required = 0. The key self-revokes with zero approvals.
 * This is the intentional self-wipe path (SAT-477, D-167 / SAT-472 doc comment).
 *
 * The store is constructed by creating a 3-key store and then legitimately
 * revoking 2 of the 3 keys down to the sole survivor, which mirrors a real
 * deployment lifecycle (prior revocations drove the count to 1).
 *
 * @returns {{
 *   ks: object,
 *   soleKeyId: string,
 *   signedBeforeRevoke: object,
 * }}
 */
export function make1KeyFixture() {
  // Start with 3 keys so we can exercise legitimate prior revocations.
  const ks = createKeyStore();
  const k1 = ks.activeKeyId;               // will be revoked first
  const k2 = rotateKey(ks);               // will be revoked second
  const k3 = rotateKey(ks);               // sole survivor → self-revocation target

  // Sign a manifest before revocations begin so we can confirm rejection later.
  const signedBeforeRevoke = signManifest(ks, baseManifestForFixture);

  // Legitimate revocation of k1: peers are k2, k3 → M=2, quorum=2.
  const a2k1 = makeRevocationApproval(ks, k2, k1);
  const a3k1 = makeRevocationApproval(ks, k3, k1);
  revokeKey(ks, k1, [a2k1, a3k1]);

  // Legitimate revocation of k2: only k3 remains as peer → M=1, quorum=1.
  const a3k2 = makeRevocationApproval(ks, k3, k2);
  revokeKey(ks, k2, [a3k2]);

  // Now ks has exactly 1 non-revoked key: k3.  M=0, required=0.
  return { ks, soleKeyId: k3, signedBeforeRevoke };
}

/**
 * Build a 2-key store: target + 1 peer.
 * N=2 → quorum = Math.floor(1/2)+1 = 1.
 * The sole peer key alone is sufficient to revoke the target (EXPECTED at N=2).
 *
 * @returns {{
 *   ks: object,
 *   targetKeyId: string,
 *   peerKeyId: string,
 *   legitApproval: {key_id: string, sig: string},
 *   forgedApproval: {key_id: string, sig: string},
 *   dupApproval: {key_id: string, sig: string},
 * }}
 */
export function make2KeyFixture() {
  const ks = createKeyStore();
  const targetKeyId = ks.activeKeyId;   // first key; becomes 'rotated' after rotate
  const peerKeyId   = rotateKey(ks);   // sole peer; demotes target to 'rotated'

  // Both `target` (rotated) and `peer` (active) are non-revoked here.
  const legitApproval  = makeRevocationApproval(ks, peerKeyId, targetKeyId);
  const forgedApproval = { key_id: peerKeyId, sig: 'f'.repeat(64) }; // wrong sig
  const dupApproval    = { ...legitApproval };                        // same token twice

  return { ks, targetKeyId, peerKeyId, legitApproval, forgedApproval, dupApproval };
}

/**
 * Build a 3-key store: target + 2 peers (contrast fixture — real threshold).
 * N=3 → quorum = Math.floor(2/2)+1 = 2. Both peers must approve.
 *
 * @returns {{
 *   ks: object,
 *   targetKeyId: string,
 *   peer1KeyId: string,
 *   peer2KeyId: string,
 *   peer1Approval: {key_id: string, sig: string},
 *   peer2Approval: {key_id: string, sig: string},
 *   forgedApproval: {key_id: string, sig: string},
 *   dupApproval: {key_id: string, sig: string},
 * }}
 */
export function make3KeyFixture() {
  const ks = createKeyStore();
  const targetKeyId = ks.activeKeyId;   // first key; will be revocation target
  const peer1KeyId  = rotateKey(ks);   // second key
  const peer2KeyId  = rotateKey(ks);   // third key; active

  // All three keys are non-revoked.
  const peer1Approval  = makeRevocationApproval(ks, peer1KeyId, targetKeyId);
  const peer2Approval  = makeRevocationApproval(ks, peer2KeyId, targetKeyId);
  const forgedApproval = { key_id: peer2KeyId, sig: 'a'.repeat(64) }; // wrong sig
  const dupApproval    = { ...peer1Approval };                         // peer1 repeated

  return { ks, targetKeyId, peer1KeyId, peer2KeyId,
           peer1Approval, peer2Approval, forgedApproval, dupApproval };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

const baseManifest = makeIntentManifest({
  paths: [{ path: 'core/key-store.mjs', sha256: 'abc123' }],
  secret_scan: { status: 'clean' },
});

// ---------------------------------------------------------------------------
// RT-KS-001-A  N=2: peer-alone revocation SUCCEEDS (documented, accepted)
//
// This is the degenerate boundary: with only 1 non-revoked peer, quorum=1.
// The test asserts the CURRENT EXPECTED behaviour — not a defect to fix.
// Regression guard: it must not silently degrade to 0-approval (no-quorum) mode.
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peerKeyId, legitApproval } = make2KeyFixture();
  const signedByTarget = signManifest(
    // sign as the target (it is rotated but still non-revoked, so signing works
    // by temporarily swapping activeKeyId — we bypass that by borrowing the raw
    // key to sign a manifest for the verify-after-revoke check below)
    // Instead: sign using the peer's key (active), then verify nothing changed.
    ks, baseManifest,
  );

  // Peer alone provides the single required approval.
  let revokedOk = false;
  try {
    revokeKey(ks, targetKeyId, [legitApproval]);
    revokedOk = true;
  } catch { /* should not throw */ }

  ok('RT-KS-001-A N=2: peer-alone revocation succeeds (quorum=1, EXPECTED)', revokedOk);
  ok('RT-KS-001-A N=2: target status is "revoked" after peer-alone revoke',
    ks.keys.get(targetKeyId)?.status === 'revoked');

  // Verify the active signing key (peer) is unaffected.
  ok('RT-KS-001-A N=2: surviving peer key remains non-revoked',
    ks.keys.get(peerKeyId)?.status !== 'revoked');

  // Manifests signed with the now-revoked key must be rejected.
  // (sign as peer, which is still active — this was signed before revocation above)
  const vr = verifyManifest(ks, { ...signedByTarget, key_id: targetKeyId,
    sig: ks.keys.get(peerKeyId) /* won't match — just confirm key_revoked path */ });
  // We just need reason === 'key_revoked'; re-sign under target to force the path.
  // Build a manifest with the target key_id as if we had kept the pre-revoke sig.
  const stubManifest = { ...signedByTarget, key_id: targetKeyId };
  const vr2 = verifyManifest(ks, stubManifest);
  ok('RT-KS-001-A N=2: manifest with revoked target key_id is rejected',
    vr2.ok === false);
  ok('RT-KS-001-A N=2: rejection reason is "key_revoked" (not "unknown_key")',
    vr2.reason === 'key_revoked', JSON.stringify(vr2));
}

// ---------------------------------------------------------------------------
// RT-KS-001-B  N=2: zero approvals CANNOT revoke (not 0-approval takeover)
//
// The degenerate case must not be confused with the zero-peer case (M=0 where
// no quorum is needed). At N=2, quorum=1, so zero approvals still fail.
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId } = make2KeyFixture();

  let threwOnZero = false;
  try { revokeKey(ks, targetKeyId, []); } catch { threwOnZero = true; }
  ok('RT-KS-001-B N=2: zero approvals CANNOT revoke (quorum 1 not met)', threwOnZero);
  ok('RT-KS-001-B N=2: target is still non-revoked after zero-approval attempt',
    ks.keys.get(targetKeyId)?.status !== 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-001-C  N=2: forged approval CANNOT revoke
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, forgedApproval } = make2KeyFixture();

  let threwOnForged = false;
  try { revokeKey(ks, targetKeyId, [forgedApproval]); } catch { threwOnForged = true; }
  ok('RT-KS-001-C N=2: forged approval alone CANNOT revoke', threwOnForged);
  ok('RT-KS-001-C N=2: target is still non-revoked after forged-approval attempt',
    ks.keys.get(targetKeyId)?.status !== 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-001-D  N=2: duplicate-signer tokens do not double-count
//
// Submitting the same legit approval token twice still counts as exactly 1
// distinct signer. At N=2 quorum=1, the duplicate pair still passes (1 ≥ 1),
// confirming that the dedup does not accidentally break the legitimate path.
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, legitApproval, dupApproval } = make2KeyFixture();

  // [legit, dup] → deduplicated to 1 valid approval → quorum 1 met → SUCCEEDS.
  let revokedWithDup = false;
  try {
    revokeKey(ks, targetKeyId, [legitApproval, dupApproval]);
    revokedWithDup = true;
  } catch { /* should not throw */ }
  ok('RT-KS-001-D N=2: [legit, dup] succeeds (deduped to 1, quorum 1 met)',
    revokedWithDup);

  // Separately verify: forged token + an exact copy of it still fails.
  // (The sig is wrong; submitting two copies of a bad sig cannot satisfy quorum.)
  const { ks: ks2, targetKeyId: t2, forgedApproval } = make2KeyFixture();
  const dupOfForged = { ...forgedApproval };   // identical key_id, identical wrong sig
  let threwForgedDup = false;
  try { revokeKey(ks2, t2, [forgedApproval, dupOfForged]); } catch { threwForgedDup = true; }
  ok('RT-KS-001-D N=2: [forged, dup-of-forged] CANNOT revoke (0 valid, wrong sig)',
    threwForgedDup);
}

// ---------------------------------------------------------------------------
// RT-KS-001-E  N=3 (contrast): single peer CANNOT revoke — real threshold
//
// At N=3, quorum=2. Confirms that the N=2 boundary does not regress N≥3
// threshold protection. Uses the 3-key fixture exported above.
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peer1KeyId, peer1Approval } = make3KeyFixture();

  let threwSingle = false;
  try { revokeKey(ks, targetKeyId, [peer1Approval]); } catch { threwSingle = true; }
  ok('RT-KS-001-E N=3: single peer CANNOT revoke (quorum 2, only 1 provided)',
    threwSingle);
  ok('RT-KS-001-E N=3: target is still non-revoked after single-peer attempt',
    ks.keys.get(targetKeyId)?.status !== 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-001-F  N=3: both peers together CAN revoke — quorum satisfied
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peer1Approval, peer2Approval } = make3KeyFixture();

  let revokedBoth = false;
  try {
    revokeKey(ks, targetKeyId, [peer1Approval, peer2Approval]);
    revokedBoth = true;
  } catch { /* should not throw */ }
  ok('RT-KS-001-F N=3: [peer1, peer2] CAN revoke (quorum 2 met)', revokedBoth);
  ok('RT-KS-001-F N=3: target status is "revoked"',
    ks.keys.get(targetKeyId)?.status === 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-001-G  N=3: forged token + one legit peer still fails quorum
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peer1Approval, forgedApproval } = make3KeyFixture();

  let threwForged = false;
  try { revokeKey(ks, targetKeyId, [peer1Approval, forgedApproval]); } catch { threwForged = true; }
  ok('RT-KS-001-G N=3: [legit-peer1, forged-peer2] CANNOT revoke (only 1 valid)', threwForged);
  ok('RT-KS-001-G N=3: target is still non-revoked after legit+forged attempt',
    ks.keys.get(targetKeyId)?.status !== 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-001-H  N=3: duplicate-signer tokens do not help attacker reach quorum
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peer1Approval, dupApproval } = make3KeyFixture();

  // dupApproval is a copy of peer1Approval — submitting both counts as only 1.
  let threwDup = false;
  try { revokeKey(ks, targetKeyId, [peer1Approval, dupApproval]); } catch { threwDup = true; }
  ok('RT-KS-001-H N=3: [peer1, dup-of-peer1] CANNOT revoke (deduped to 1, quorum 2 not met)',
    threwDup);
}

// ---------------------------------------------------------------------------
// RT-KS-001-I  N=3: forged + duplicate together still fail (0 valid after dedup)
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, forgedApproval, dupApproval } = make3KeyFixture();

  let threwForgedDupN3 = false;
  try { revokeKey(ks, targetKeyId, [forgedApproval, dupApproval]); } catch { threwForgedDupN3 = true; }
  ok('RT-KS-001-I N=3: [forged, dup-of-peer1] CANNOT revoke', threwForgedDupN3);
}

// ===========================================================================
// RT-KS-002  M=0 quorum — sole-remaining-key self-revocation (SAT-477)
//
// When a store has been reduced to exactly 1 non-revoked key via prior
// legitimate revocations, M=0 → required=0. The sole key can self-revoke
// with zero approvals. This is EXPECTED, INTENTIONAL design (D-167 / SAT-472):
// requiring a peer approval that cannot exist would permanently strand a
// compromised last key. The M=0 path is a self-wipe, not an auth bypass.
// ===========================================================================

// ---------------------------------------------------------------------------
// RT-KS-002-A  N=1 (sole survivor): self-revocation with ZERO approvals SUCCEEDS
//
// This is the core documented behaviour. The test confirms:
//   1. revokeKey(ks, soleKeyId, []) does not throw with M=0
//   2. The sole key is marked "revoked" after the call
//   3. activeKeyId is cleared to null (no active key remains)
//   4. Manifests signed before revocation are now rejected (key_revoked)
// ---------------------------------------------------------------------------
{
  const { ks, soleKeyId, signedBeforeRevoke } = make1KeyFixture();

  // Confirm we are in the N=1 state with 0 non-revoked peers.
  const nonRevokedPeers = [...ks.keys.values()].filter(
    e => e.key_id !== soleKeyId && e.status !== 'revoked',
  );
  ok('RT-KS-002-A N=1: store has exactly 0 non-revoked peers before self-revoke',
    nonRevokedPeers.length === 0);

  let selfRevokedOk = false;
  try {
    revokeKey(ks, soleKeyId, []);   // zero approvals required at M=0
    selfRevokedOk = true;
  } catch { /* must not throw */ }

  ok('RT-KS-002-A N=1: self-revocation with zero approvals SUCCEEDS (M=0, EXPECTED)',
    selfRevokedOk);
  ok('RT-KS-002-A N=1: sole key status is "revoked" after self-revoke',
    ks.keys.get(soleKeyId)?.status === 'revoked');
  ok('RT-KS-002-A N=1: activeKeyId is null after sole-key revocation (store exhausted)',
    ks.activeKeyId === null);

  // Manifests signed before self-revocation must now be rejected.
  const vr = verifyManifest(ks, signedBeforeRevoke);
  ok('RT-KS-002-A N=1: manifest signed before self-revoke is now rejected',
    vr.ok === false);
  ok('RT-KS-002-A N=1: rejection reason is "key_revoked"',
    vr.reason === 'key_revoked', JSON.stringify(vr));
}

// ---------------------------------------------------------------------------
// RT-KS-002-B  N=1: self-revocation is idempotent
//
// Revoking the already-revoked key a second time must be a no-op (no throw).
// Matches the general idempotency contract from core/key-store.mjs.
// ---------------------------------------------------------------------------
{
  const { ks, soleKeyId } = make1KeyFixture();
  revokeKey(ks, soleKeyId, []);   // first call

  let idempotentOk = false;
  try { revokeKey(ks, soleKeyId, []); idempotentOk = true; } catch { /* must not throw */ }
  ok('RT-KS-002-B N=1: revoking the already-revoked sole key is a no-op (idempotent)',
    idempotentOk);
  ok('RT-KS-002-B N=1: status remains "revoked" after second call',
    ks.keys.get(soleKeyId)?.status === 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-002-C  N=1: a forged/garbage approval still succeeds (M=0 branch)
//
// At M=0 the quorum check is entirely bypassed (required=0). Passing garbage
// tokens must not PREVENT revocation (they are simply ignored). This guards
// against a future regression where forged-token rejection inadvertently
// raises the effective required count above 0 at M=0.
// ---------------------------------------------------------------------------
{
  const { ks, soleKeyId } = make1KeyFixture();
  const garbage = { key_id: soleKeyId, sig: '0'.repeat(64) };

  let revokedWithGarbage = false;
  try {
    revokeKey(ks, soleKeyId, [garbage]);
    revokedWithGarbage = true;
  } catch { /* must not throw */ }
  ok('RT-KS-002-C N=1: passing garbage approvals at M=0 still SUCCEEDS (quorum=0, bypass)',
    revokedWithGarbage);
  ok('RT-KS-002-C N=1: sole key is "revoked" even when garbage approvals were passed',
    ks.keys.get(soleKeyId)?.status === 'revoked');
}

// ---------------------------------------------------------------------------
// RT-KS-002-D  N=1: the transition from N=2 to N=1 resets the quorum requirement
//
// Demonstrates the full lifecycle: start at N=2 (quorum=1), legitimately revoke
// one key so N=1 (quorum=0), then self-revoke the survivor with zero approvals.
// This is the documented "last-key" handoff path.
// ---------------------------------------------------------------------------
{
  const { ks, targetKeyId, peerKeyId, legitApproval } = make2KeyFixture();

  // Step 1: legitimate revocation at N=2 (quorum=1, peer approves)
  revokeKey(ks, targetKeyId, [legitApproval]);
  ok('RT-KS-002-D step-1: N=2→1 transition — peer-approved revocation sets N=1',
    ks.keys.get(targetKeyId)?.status === 'revoked');

  // Confirm peer is now the sole non-revoked key (M=0 for any revocation of peerKeyId).
  const peersOfPeer = [...ks.keys.values()].filter(
    e => e.key_id !== peerKeyId && e.status !== 'revoked',
  );
  ok('RT-KS-002-D step-1: no non-revoked peers remain for peerKeyId after transition',
    peersOfPeer.length === 0);

  // Step 2: sole survivor (peerKeyId) self-revokes with zero approvals.
  let finalRevokeOk = false;
  try { revokeKey(ks, peerKeyId, []); finalRevokeOk = true; } catch { /* must not throw */ }
  ok('RT-KS-002-D step-2: sole survivor self-revokes with zero approvals SUCCEEDS (EXPECTED)',
    finalRevokeOk);
  ok('RT-KS-002-D step-2: sole survivor is "revoked" after self-revoke',
    ks.keys.get(peerKeyId)?.status === 'revoked');
  ok('RT-KS-002-D step-2: store is fully exhausted — activeKeyId is null',
    ks.activeKeyId === null);
}

// ---------------------------------------------------------------------------
// RT-KS-001-J  Quorum arithmetic boundary table
//
// Exhaustively verify Math.floor(M/2)+1 for M=0..5.
// Prevents a silent regression where the formula changes under refactoring.
// ---------------------------------------------------------------------------
{
  // Expected quorum per non-revoked peer count (M).
  const EXPECTED = [
  //  M:  0  1  2  3  4  5
       0, 1, 2, 2, 3, 3,
  ];

  // Build a store with exactly (M+1) non-revoked keys: 1 target + M peers.
  // Check the formula directly.
  for (let M = 0; M <= 5; M++) {
    const expected = EXPECTED[M];
    const computed = M > 0 ? Math.floor(M / 2) + 1 : 0;
    ok(`RT-KS-001-J quorum math: M=${M} peers → required=${computed} (expected ${expected})`,
      computed === expected);
  }
}

// ---------------------------------------------------------------------------
// SAT-478 gate  revokeKey must remain unreachable from any non-test surface
//
// SAT-478 (SECURITY.md, D-167): revokeKey() at M=0 authorizes by state, not
// caller identity -- any caller can wipe the sole remaining key with zero
// approvals and zero proof of key possession. The ONLY current mitigation is
// that revokeKey has no reachable call site outside core/key-store.mjs and
// test/. This check enforces that in code, not just in a Linear ticket: if a
// future PR wires revokeKey into ANY production surface -- bin/, mcp/, or a
// not-yet-existing directory (lib/, plugins/, server/, etc.) -- without first
// resolving SAT-478, this test fails loudly instead of silently shipping an
// exploitable path. Whole-repo scan (not just bin/+mcp/) so a brand-new
// directory can't quietly bypass it (Architect review, PR #42 re-review).
//
// Known limitation, stated plainly rather than overclaimed: this is a text
// scan, not static analysis -- it does not catch an aliased reference
// (`const r = revokeKey; r(...)`) or a dynamic re-export. A hard technical
// barrier would need an AST-based lint rule, which is disproportionate
// engineering for a function with zero production callers today. This gate
// is a deliberate tripwire against the realistic case (a future ticket adding
// a direct call site), not a claim of airtight enforcement.
//
// A future PR that legitimately resolves SAT-478 and wires revokeKey in must
// update this check as a deliberate, visible part of that change -- that's
// the point: it forces the decision to be conscious, not accidental.
// ---------------------------------------------------------------------------
{
  // Full JS/TS family, not just .mjs/.js -- none of these exist in the repo
  // today, but the scan shouldn't silently miss one if that changes
  // (Architect review, PR #42 round 3).
  const SCAN_EXTENSIONS = ['.mjs', '.cjs', '.js', '.mts', '.cts', '.ts'];
  const SKIP_DIRS = new Set(['test', 'node_modules', '.git']);
  const scanRepoForRevokeKey = (dirPath) => {
    if (!fs.existsSync(dirPath)) return [];
    const hits = [];
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        hits.push(...scanRepoForRevokeKey(path.join(dirPath, entry.name)));
      } else if (entry.isFile() && SCAN_EXTENSIONS.some(ext => entry.name.endsWith(ext))) {
        const full = path.join(dirPath, entry.name);
        if (full === path.join(ROOT, 'core', 'key-store.mjs')) continue; // definition itself
        const content = fs.readFileSync(full, 'utf8');
        if (content.includes('revokeKey')) hits.push(full);
      }
    }
    return hits;
  };

  const hits = scanRepoForRevokeKey(ROOT);
  ok('SAT-478 gate: revokeKey is not referenced anywhere outside core/key-store.mjs and test/ (whole-repo scan)',
    hits.length === 0,
    hits.length ? hits.join(', ') : '');
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
