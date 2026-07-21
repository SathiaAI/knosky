// KnoSky F0.1 — Trust-root recovery/re-key ceremony tests (SAT-545).
//
// Covers both the ordinary (D-193) and emergency (D-194) re-key paths, plus the
// structural firewall between these new event types and the existing exception-
// signing API.
//
// Coverage:
//   RK-001  makeRekeyApproval: produces a { key_id, sig } token for TRUST_ROOT_REKEY.
//   RK-002  makeRekeyApproval: produces a { key_id, sig } token for EMERGENCY_REKEY.
//   RK-003  makeRekeyApproval: throws when signing key === new key id.
//   RK-004  makeRekeyApproval: throws for an unknown signing key.
//   RK-005  makeRekeyApproval: throws when the signing key is revoked.
//   RK-006  makeRekeyApproval: throws on invalid eventType.
//   RK-007  Ordinary path (rekey): majority-met — N=3 keyholders, quorum=2.
//   RK-008  Ordinary path (rekey): majority-not-met — only 1 approval when 2 required.
//   RK-009  Ordinary path (rekey): N=1, majority=1 — sole keyholder co-signs.
//   RK-010  Ordinary path (rekey): duplicate approvals do not double-count.
//   RK-011  Ordinary path (rekey): forged approval does not count toward quorum.
//   RK-012  Activation delay: returned event has activates_at 48 h in the future (clock injection).
//   RK-013  Activation delay: isRekeyActive returns false before the window expires.
//   RK-014  Activation delay: isRekeyActive returns true after the window expires (clock injection).
//   RK-015  Activation delay: isRekeyActive with malformed activates_at returns false.
//   RK-016  Emergency path: N=3, unanimity met (all 3 approve).
//   RK-017  Emergency path: N=3, unanimity not met — only 2 approve (1 missing).
//   RK-018  Emergency path: N=1, unanimity met (sole keyholder approves).
//   RK-019  Emergency path: empty justification — rejected.
//   RK-020  Emergency path: whitespace-only justification — rejected.
//   RK-021  Emergency path: null justification — rejected.
//   RK-022  Emergency path: missing justification — rejected.
//   RK-023  Event-type separation: TRUST_ROOT_REKEY approval does not satisfy EMERGENCY_REKEY quorum.
//   RK-024  Event-type separation: EMERGENCY_REKEY approval does not satisfy TRUST_ROOT_REKEY quorum.
//   RK-025  Event-type firewall: assembleLedgerEntry (exception API) can only emit EXCEPTION_GRANTED,
//           never TRUST_ROOT_REKEY or EMERGENCY_REKEY.
//   RK-026  Checkpoint wiring: TRUST_ROOT_REKEY event is written to the checkpoint file.
//   RK-027  Checkpoint wiring: EMERGENCY_REKEY event is written to the checkpoint file.
//   RK-028  Ordinary event shape: required fields present and correctly typed.
//   RK-029  Emergency event shape: required fields present and correctly typed.
//   RK-030  rekey: throws on missing/invalid newKeyId.
//   RK-031  emergencyRekey: throws on missing/invalid newKeyId.
//   RK-032  Ordinary path (rekey): N=2, quorum=2 — both keyholders must approve.
//   RK-033  Emergency path: N=2, unanimity=2 — both keyholders must approve.
//
// Run: node test/trust-root-rekey.test.mjs

import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  createKeyStore,
  rotateKey,
  revokeKey,
  makeRevocationApproval,
} from '../core/key-store.mjs';
import {
  makeRekeyApproval,
  rekey,
  emergencyRekey,
  isRekeyActive,
  REKEY_DELAY_MIN_MS,
  REKEY_DELAY_MAX_MS,
} from '../core/trust-root-rekey.mjs';
import { assembleLedgerEntry, TIER } from '../core/signing-tiers.mjs';
import { buildTierCheckpoint } from '../core/signing-tiers.mjs';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

const tmpDir = mkdtempSync(join(tmpdir(), 'knosky-rekey-test-'));
let cpSeq = 0;
function cpPath() {
  return join(tmpDir, `rekey-cp-${++cpSeq}.jsonl`);
}

// Stable synthetic new-key id (test fixture only — not a live secret; gitleaks-safe shape)
const NEW_KEY_ID = ['test', 'fixture', 'key', 'id', '001'].join('-');

// ---------------------------------------------------------------------------
// Fixture builder
// Builds a key store with exactly `n` non-revoked keys.
// Returns the key store and the ids of all non-revoked keys in creation order.
// ---------------------------------------------------------------------------
function makeNKeyStore(n) {
  if (n < 1) throw new Error('n must be >= 1');
  const ks = createKeyStore();
  const ids = [ks.activeKeyId];
  for (let i = 1; i < n; i++) {
    ids.push(rotateKey(ks)); // demotes previous key to 'rotated' (still non-revoked)
  }
  // All keys are non-revoked at this point (some rotated, the last active).
  return { ks, ids };
}

// Produce valid TRUST_ROOT_REKEY approval tokens for a subset of keys in `ks`.
function rekeyApprovals(ks, keyIds, newKeyId = NEW_KEY_ID) {
  return keyIds.map(id => makeRekeyApproval(ks, id, newKeyId, 'TRUST_ROOT_REKEY'));
}

// Produce valid EMERGENCY_REKEY approval tokens for a subset of keys in `ks`.
function emergencyApprovals(ks, keyIds, newKeyId = NEW_KEY_ID) {
  return keyIds.map(id => makeRekeyApproval(ks, id, newKeyId, 'EMERGENCY_REKEY'));
}

// ---------------------------------------------------------------------------
// RK-001..006 — makeRekeyApproval
// ---------------------------------------------------------------------------

{
  const { ks, ids } = makeNKeyStore(2);
  const token = makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'TRUST_ROOT_REKEY');
  ok('RK-001 makeRekeyApproval produces key_id + 64-char hex sig (TRUST_ROOT_REKEY)',
    token.key_id === ids[0] && /^[0-9a-f]{64}$/.test(token.sig), JSON.stringify(token));

  const token2 = makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'EMERGENCY_REKEY');
  ok('RK-002 makeRekeyApproval produces key_id + 64-char hex sig (EMERGENCY_REKEY)',
    token2.key_id === ids[0] && /^[0-9a-f]{64}$/.test(token2.sig));

  // Tokens for the two event types must be different (HMAC input differs)
  ok('RK-002 TRUST_ROOT_REKEY and EMERGENCY_REKEY tokens have different sigs',
    token.sig !== token2.sig);
}

{
  const { ks, ids } = makeNKeyStore(2);
  let threw = false;
  try { makeRekeyApproval(ks, ids[0], ids[0], 'TRUST_ROOT_REKEY'); } catch { threw = true; }
  ok('RK-003 makeRekeyApproval throws when signing key === new key id', threw);
}

{
  const { ks } = makeNKeyStore(1);
  let threw = false;
  try { makeRekeyApproval(ks, 'does-not-exist', NEW_KEY_ID, 'TRUST_ROOT_REKEY'); } catch { threw = true; }
  ok('RK-004 makeRekeyApproval throws for unknown signing key', threw);
}

{
  const { ks, ids } = makeNKeyStore(3);
  // Revoke the last key (ids[2] is active); get down to a store where ids[0] is revoked.
  // Revoke ids[0]: peers are ids[1], ids[2] → quorum = 2
  const a1 = makeRevocationApproval(ks, ids[1], ids[0]);
  const a2 = makeRevocationApproval(ks, ids[2], ids[0]);
  revokeKey(ks, ids[0], [a1, a2]);

  let threw = false;
  try { makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'TRUST_ROOT_REKEY'); } catch { threw = true; }
  ok('RK-005 makeRekeyApproval throws when signing key is revoked', threw);
}

{
  const { ks, ids } = makeNKeyStore(2);
  let threw = false;
  try { makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'UNKNOWN_TYPE'); } catch { threw = true; }
  ok('RK-006 makeRekeyApproval throws on invalid eventType', threw);
}

// ---------------------------------------------------------------------------
// RK-007..011 — Ordinary path (rekey): quorum enforcement
// ---------------------------------------------------------------------------

{
  // N=3: quorum = Math.floor(3/2)+1 = 2
  const { ks, ids } = makeNKeyStore(3);
  const approvals = rekeyApprovals(ks, [ids[0], ids[1]]);  // 2 approvals → meets quorum
  let result = null;
  try { result = rekey(ks, NEW_KEY_ID, approvals); } catch { /* should not throw */ }
  ok('RK-007 ordinary rekey N=3 quorum=2: majority met (2 of 3)', result !== null, result?.event);
  ok('RK-007 event type is TRUST_ROOT_REKEY', result?.event === 'TRUST_ROOT_REKEY');
}

{
  // N=3: quorum=2, only 1 approval supplied
  const { ks, ids } = makeNKeyStore(3);
  const approvals = rekeyApprovals(ks, [ids[0]]);  // only 1 → quorum not met
  let threw = false;
  try { rekey(ks, NEW_KEY_ID, approvals); } catch { threw = true; }
  ok('RK-008 ordinary rekey N=3: quorum not met (1 of 2 required) throws', threw);
}

{
  // N=1: quorum = Math.floor(1/2)+1 = 1 — sole keyholder must approve
  const { ks, ids } = makeNKeyStore(1);
  const approvals = rekeyApprovals(ks, [ids[0]]);
  let result = null;
  try { result = rekey(ks, NEW_KEY_ID, approvals); } catch { /* should not throw */ }
  ok('RK-009 ordinary rekey N=1 (sole keyholder): majority=1 met', result !== null);
  ok('RK-009 event type is TRUST_ROOT_REKEY', result?.event === 'TRUST_ROOT_REKEY');
}

{
  // Duplicate approvals from same signer should deduplicate to 1
  // N=3: quorum=2. Submit same token twice → only 1 valid → quorum not met.
  const { ks, ids } = makeNKeyStore(3);
  const a0 = makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'TRUST_ROOT_REKEY');
  let threw = false;
  try { rekey(ks, NEW_KEY_ID, [a0, a0]); } catch { threw = true; }
  ok('RK-010 duplicate approvals do not double-count (deduped to 1, quorum 2 not met)', threw);
}

{
  // Forged approval (wrong sig) should not count
  const { ks, ids } = makeNKeyStore(3);
  const legit = makeRekeyApproval(ks, ids[0], NEW_KEY_ID, 'TRUST_ROOT_REKEY');
  const forged = { key_id: ids[1], sig: 'f'.repeat(64) };  // wrong sig
  let threw = false;
  try { rekey(ks, NEW_KEY_ID, [legit, forged]); } catch { threw = true; }
  ok('RK-011 forged approval does not count toward quorum (1 valid, 2 needed)', threw);
}

// ---------------------------------------------------------------------------
// RK-012..015 — Activation delay (without wall-clock sleep)
// ---------------------------------------------------------------------------

{
  const NOW = 1_700_000_000_000;  // fixed synthetic timestamp
  const { ks, ids } = makeNKeyStore(2);  // N=2: quorum=2
  const approvals = rekeyApprovals(ks, [ids[0], ids[1]]);
  const evt = rekey(ks, NEW_KEY_ID, approvals, { now: NOW });

  ok('RK-012 activates_at is 48h after signed_at',
    Date.parse(evt.activates_at) === NOW + REKEY_DELAY_MIN_MS,
    `signed_at=${evt.signed_at} activates_at=${evt.activates_at}`);

  ok('RK-012 activates_after_ms equals REKEY_DELAY_MIN_MS',
    evt.activates_after_ms === REKEY_DELAY_MIN_MS);

  // Before the window: isRekeyActive must return false
  ok('RK-013 isRekeyActive returns false before the 48h window',
    isRekeyActive(evt, NOW + REKEY_DELAY_MIN_MS - 1) === false);

  ok('RK-013 isRekeyActive returns false immediately after signing (t=NOW)',
    isRekeyActive(evt, NOW) === false);

  // After the window: isRekeyActive must return true
  ok('RK-014 isRekeyActive returns true at exactly 48h (lower bound)',
    isRekeyActive(evt, NOW + REKEY_DELAY_MIN_MS) === true);

  ok('RK-014 isRekeyActive returns true at 72h (upper bound)',
    isRekeyActive(evt, NOW + REKEY_DELAY_MAX_MS) === true);

  ok('RK-014 isRekeyActive returns true well past the window',
    isRekeyActive(evt, NOW + REKEY_DELAY_MAX_MS * 2) === true);
}

{
  // Malformed activates_at
  ok('RK-015 isRekeyActive returns false for malformed activates_at',
    isRekeyActive({ activates_at: 'not-a-date' }, Date.now()) === false);

  ok('RK-015 isRekeyActive returns false for missing activates_at',
    isRekeyActive({}, Date.now()) === false);

  ok('RK-015 isRekeyActive returns false for null input',
    isRekeyActive(null, Date.now()) === false);
}

// ---------------------------------------------------------------------------
// RK-016..022 — Emergency path: unanimity enforcement + justification
// ---------------------------------------------------------------------------

{
  // N=3: unanimity = all 3 must sign
  const { ks, ids } = makeNKeyStore(3);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1], ids[2]]);
  let result = null;
  try { result = emergencyRekey(ks, NEW_KEY_ID, approvals, 'Keyholder Alice lost HSM — unanimous override authorized by all remaining keyholders.'); } catch { /* should not throw */ }
  ok('RK-016 emergency rekey N=3: unanimity met (all 3 approve)', result !== null);
  ok('RK-016 event type is EMERGENCY_REKEY', result?.event === 'EMERGENCY_REKEY');
  ok('RK-016 justification is preserved in event', result?.justification === 'Keyholder Alice lost HSM — unanimous override authorized by all remaining keyholders.');
}

{
  // N=3: unanimity=3, only 2 approve → fails
  const { ks, ids } = makeNKeyStore(3);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1]]);  // missing ids[2]
  let threw = false;
  try { emergencyRekey(ks, NEW_KEY_ID, approvals, 'Missing one signer.'); } catch { threw = true; }
  ok('RK-017 emergency rekey N=3: unanimity not met (2 of 3) throws', threw);
}

{
  // N=1: unanimity = just the sole keyholder
  const { ks, ids } = makeNKeyStore(1);
  const approvals = emergencyApprovals(ks, [ids[0]]);
  let result = null;
  try { result = emergencyRekey(ks, NEW_KEY_ID, approvals, 'Sole keyholder emergency rekey with justification.'); } catch { /* should not throw */ }
  ok('RK-018 emergency rekey N=1: unanimity=1 met (sole keyholder)', result !== null);
  ok('RK-018 event type is EMERGENCY_REKEY', result?.event === 'EMERGENCY_REKEY');
}

{
  const { ks, ids } = makeNKeyStore(2);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1]]);

  // Empty justification
  let threw1 = false;
  try { emergencyRekey(ks, NEW_KEY_ID, approvals, ''); } catch { threw1 = true; }
  ok('RK-019 empty justification is rejected', threw1);

  // Whitespace-only
  let threw2 = false;
  try { emergencyRekey(ks, NEW_KEY_ID, approvals, '   \t\n'); } catch { threw2 = true; }
  ok('RK-020 whitespace-only justification is rejected', threw2);

  // null
  let threw3 = false;
  try { emergencyRekey(ks, NEW_KEY_ID, approvals, null); } catch { threw3 = true; }
  ok('RK-021 null justification is rejected', threw3);

  // missing (undefined)
  let threw4 = false;
  try { emergencyRekey(ks, NEW_KEY_ID, approvals); } catch { threw4 = true; }
  ok('RK-022 missing justification is rejected', threw4);
}

// ---------------------------------------------------------------------------
// RK-023..024 — Event-type separation: cross-path approval tokens fail
// ---------------------------------------------------------------------------

{
  // Approval tokens are bound to their event type: a TRUST_ROOT_REKEY token
  // CANNOT satisfy an EMERGENCY_REKEY ceremony (different HMAC binding).
  const { ks, ids } = makeNKeyStore(3);

  // Produce TRUST_ROOT_REKEY tokens for all 3 keyholders
  const wrongTypeApprovals = rekeyApprovals(ks, [ids[0], ids[1], ids[2]]);

  // Try to use them for an emergency rekey — should fail (wrong binding)
  let threw = false;
  try { emergencyRekey(ks, NEW_KEY_ID, wrongTypeApprovals, 'Using wrong token type.'); } catch { threw = true; }
  ok('RK-023 TRUST_ROOT_REKEY tokens do NOT satisfy EMERGENCY_REKEY quorum', threw);
}

{
  const { ks, ids } = makeNKeyStore(3);

  // Produce EMERGENCY_REKEY tokens for 2 of 3 keyholders
  const wrongTypeApprovals = emergencyApprovals(ks, [ids[0], ids[1]]);

  // Try to use them for an ordinary rekey — N=3 quorum=2, but wrong binding
  let threw = false;
  try { rekey(ks, NEW_KEY_ID, wrongTypeApprovals); } catch { threw = true; }
  ok('RK-024 EMERGENCY_REKEY tokens do NOT satisfy TRUST_ROOT_REKEY quorum', threw);
}

// ---------------------------------------------------------------------------
// RK-025 — Event-type firewall: assembleLedgerEntry can only emit EXCEPTION_GRANTED
// ---------------------------------------------------------------------------

{
  // assembleLedgerEntry is the only official way to write a ledger entry via the
  // signing-tiers exception API. It hardcodes `event: 'EXCEPTION_GRANTED'`.
  // There is no parameter to change the event type — the firewall is structural.
  const cp = buildTierCheckpoint(TIER.WEBAUTHN, TIER.WEBAUTHN, 'core');
  const entry = assembleLedgerEntry({
    signerId: 'agent-1', tier: TIER.WEBAUTHN, assertionHash: 'a'.repeat(64),
    districtClass: 'core', reason: 'test exception', tierCheckpoint: cp,
  });

  ok('RK-025 assembleLedgerEntry always emits event=EXCEPTION_GRANTED (structural firewall)',
    entry.event === 'EXCEPTION_GRANTED');
  ok('RK-025 TRUST_ROOT_REKEY is not an exported event from assembleLedgerEntry',
    entry.event !== 'TRUST_ROOT_REKEY');
  ok('RK-025 EMERGENCY_REKEY is not an exported event from assembleLedgerEntry',
    entry.event !== 'EMERGENCY_REKEY');

  // The signing-tiers module exports no function that can produce either rekey event type.
  // Confirm by checking the module namespace.
  const stModule = await import('../core/signing-tiers.mjs');
  const stExports = Object.keys(stModule);
  // No exported function name should contain "rekey" or "Rekey" (case-insensitive).
  const rekeyLike = stExports.filter(n => /rekey/i.test(n));
  ok('RK-025 signing-tiers.mjs exports no rekey-related function',
    rekeyLike.length === 0, rekeyLike.join(', '));
}

// ---------------------------------------------------------------------------
// RK-026..027 — Checkpoint wiring
// ---------------------------------------------------------------------------

{
  const cp = cpPath();
  const { ks, ids } = makeNKeyStore(2);  // N=2: quorum=2
  const approvals = rekeyApprovals(ks, [ids[0], ids[1]]);
  rekey(ks, NEW_KEY_ID, approvals, { checkpointPath: cp });

  const lines = readFileSync(cp, 'utf8').trim().split('\n').filter(Boolean);
  ok('RK-026 TRUST_ROOT_REKEY event is written to checkpoint', lines.length >= 1);
  const parsed = JSON.parse(lines[lines.length - 1]);
  ok('RK-026 checkpoint entry has event=TRUST_ROOT_REKEY', parsed.event === 'TRUST_ROOT_REKEY');
  ok('RK-026 checkpoint entry has new_key_id', parsed.new_key_id === NEW_KEY_ID);
}

{
  const cp = cpPath();
  const { ks, ids } = makeNKeyStore(3);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1], ids[2]]);
  emergencyRekey(ks, NEW_KEY_ID, approvals, 'Emergency override test justification.', { checkpointPath: cp });

  const lines = readFileSync(cp, 'utf8').trim().split('\n').filter(Boolean);
  ok('RK-027 EMERGENCY_REKEY event is written to checkpoint', lines.length >= 1);
  const parsed = JSON.parse(lines[lines.length - 1]);
  ok('RK-027 checkpoint entry has event=EMERGENCY_REKEY', parsed.event === 'EMERGENCY_REKEY');
  ok('RK-027 checkpoint entry preserves justification', typeof parsed.justification === 'string' && parsed.justification.length > 0);
}

// ---------------------------------------------------------------------------
// RK-028..029 — Event shape validation
// ---------------------------------------------------------------------------

{
  const { ks, ids } = makeNKeyStore(3);
  const approvals = rekeyApprovals(ks, [ids[0], ids[1]]);
  const NOW = 1_700_000_000_000;
  const evt = rekey(ks, NEW_KEY_ID, approvals, { now: NOW });

  ok('RK-028 ordinary event has event=TRUST_ROOT_REKEY', evt.event === 'TRUST_ROOT_REKEY');
  ok('RK-028 ordinary event has new_key_id', evt.new_key_id === NEW_KEY_ID);
  ok('RK-028 ordinary event has valid_approvals >= required_approvals',
    evt.valid_approvals >= evt.required_approvals);
  ok('RK-028 ordinary event has signed_at (ISO string)', /^\d{4}-\d{2}-\d{2}T/.test(evt.signed_at));
  ok('RK-028 ordinary event has activates_at (ISO string)', /^\d{4}-\d{2}-\d{2}T/.test(evt.activates_at));
  ok('RK-028 activates_at > signed_at', Date.parse(evt.activates_at) > Date.parse(evt.signed_at));
  ok('RK-028 activates_after_ms is a positive integer', Number.isInteger(evt.activates_after_ms) && evt.activates_after_ms > 0);
  // No justification field on ordinary events
  ok('RK-028 ordinary event has no justification field', !('justification' in evt));
}

{
  const { ks, ids } = makeNKeyStore(3);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1], ids[2]]);
  const JUSTIFICATION = 'All keyholders present and accounted for — emergency override.';
  const evt = emergencyRekey(ks, NEW_KEY_ID, approvals, JUSTIFICATION);

  ok('RK-029 emergency event has event=EMERGENCY_REKEY', evt.event === 'EMERGENCY_REKEY');
  ok('RK-029 emergency event has new_key_id', evt.new_key_id === NEW_KEY_ID);
  ok('RK-029 emergency event has valid_approvals', evt.valid_approvals === 3);
  ok('RK-029 emergency event has required_approvals', evt.required_approvals === 3);
  ok('RK-029 emergency event has missing_signers=0', evt.missing_signers === 0);
  ok('RK-029 emergency event has justification', evt.justification === JUSTIFICATION);
  ok('RK-029 emergency event has signed_at (ISO string)', /^\d{4}-\d{2}-\d{2}T/.test(evt.signed_at));
  // No activates_at on emergency events (no mandatory delay on the unanimous path)
  ok('RK-029 emergency event has no activates_at field', !('activates_at' in evt));
}

// ---------------------------------------------------------------------------
// RK-030..031 — Input validation: missing/invalid newKeyId
// ---------------------------------------------------------------------------

{
  const { ks, ids } = makeNKeyStore(2);
  const approvals = rekeyApprovals(ks, [ids[0], ids[1]]);

  let threw1 = false;
  try { rekey(ks, '', approvals); } catch { threw1 = true; }
  ok('RK-030 rekey rejects empty newKeyId', threw1);

  let threw2 = false;
  try { rekey(ks, null, approvals); } catch { threw2 = true; }
  ok('RK-030 rekey rejects null newKeyId', threw2);
}

{
  const { ks, ids } = makeNKeyStore(2);
  const approvals = emergencyApprovals(ks, [ids[0], ids[1]]);

  let threw1 = false;
  try { emergencyRekey(ks, '', approvals, 'valid justification'); } catch { threw1 = true; }
  ok('RK-031 emergencyRekey rejects empty newKeyId', threw1);

  let threw2 = false;
  try { emergencyRekey(ks, null, approvals, 'valid justification'); } catch { threw2 = true; }
  ok('RK-031 emergencyRekey rejects null newKeyId', threw2);
}

// ---------------------------------------------------------------------------
// RK-032..033 — N=2 edge cases
// ---------------------------------------------------------------------------

{
  // N=2: ordinary quorum = Math.floor(2/2)+1 = 2 — BOTH keyholders must sign
  const { ks, ids } = makeNKeyStore(2);
  const oneApproval = rekeyApprovals(ks, [ids[0]]);  // only 1 of 2 required
  let threw = false;
  try { rekey(ks, NEW_KEY_ID, oneApproval); } catch { threw = true; }
  ok('RK-032 ordinary rekey N=2: quorum=2, only 1 approval → fails', threw);

  const bothApprovals = rekeyApprovals(ks, [ids[0], ids[1]]);
  let result = null;
  try { result = rekey(ks, NEW_KEY_ID, bothApprovals); } catch { /* should not throw */ }
  ok('RK-032 ordinary rekey N=2: quorum=2 met with both keyholders', result !== null);
}

{
  // N=2: emergency unanimity = both must sign
  const { ks, ids } = makeNKeyStore(2);
  const oneApproval = emergencyApprovals(ks, [ids[0]]);
  let threw = false;
  try { emergencyRekey(ks, NEW_KEY_ID, oneApproval, 'One signer, but need two.'); } catch { threw = true; }
  ok('RK-033 emergency rekey N=2: unanimity=2, only 1 approval → fails', threw);

  const bothApprovals = emergencyApprovals(ks, [ids[0], ids[1]]);
  const { ks: ks2, ids: ids2 } = makeNKeyStore(2);
  const bothApprovals2 = emergencyApprovals(ks2, [ids2[0], ids2[1]]);
  let result = null;
  try { result = emergencyRekey(ks2, NEW_KEY_ID, bothApprovals2, 'Both keyholders sign — emergency override.'); } catch { /* should not throw */ }
  ok('RK-033 emergency rekey N=2: unanimity=2 met with both keyholders', result !== null);
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
