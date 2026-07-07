// KnoSky ledger high-water-mark guard tests (SAT-443 / SAT-476 / V13).
// Run: node test/ledger.test.mjs
import { mkdtempSync, rmSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readHwm, writeHwm, checkAndAdvance } from '../core/ledger.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Set up a fresh temp directory for each logical group so tests are isolated.
// ---------------------------------------------------------------------------

const tmpDir = mkdtempSync(join(tmpdir(), 'knosky-ledger-test-'));

function hwmPath(name) {
  return join(tmpDir, name, 'ledger.hwm.json');
}

// ---------------------------------------------------------------------------
// (a) readHwm returns 0 when the file does not exist
// ---------------------------------------------------------------------------
{
  const path = hwmPath('a-new');
  const hwm = readHwm(path);
  ok('(a) readHwm returns 0 for absent file', hwm === 0, String(hwm));
}

// ---------------------------------------------------------------------------
// (b) writeHwm + readHwm round-trip
// ---------------------------------------------------------------------------
{
  const path = hwmPath('b-roundtrip');
  writeHwm(path, 42);
  const hwm = readHwm(path);
  ok('(b) writeHwm + readHwm round-trip: value 42', hwm === 42, String(hwm));

  writeHwm(path, 100);
  const hwm2 = readHwm(path);
  ok('(b) writeHwm + readHwm round-trip: value 100', hwm2 === 100, String(hwm2));
}

// ---------------------------------------------------------------------------
// (c) writeHwm rejects non-integer / negative values
// ---------------------------------------------------------------------------
{
  const path = hwmPath('c-bad-write');
  let threw = false;
  try { writeHwm(path, -1); } catch { threw = true; }
  ok('(c) writeHwm rejects negative seq', threw);

  let threw2 = false;
  try { writeHwm(path, 3.5); } catch { threw2 = true; }
  ok('(c) writeHwm rejects non-integer seq', threw2);
}

// ---------------------------------------------------------------------------
// (d) checkAndAdvance: first call (no file) always accepts and creates HWM
// ---------------------------------------------------------------------------
{
  const path = hwmPath('d-first');
  const result = checkAndAdvance(7, path);
  ok('(d) first call ok=true', result.ok === true, JSON.stringify(result));
  ok('(d) first call seq=7', result.seq === 7);
  ok('(d) first call HWM file written: readHwm returns 7', readHwm(path) === 7);
}

// ---------------------------------------------------------------------------
// (e) checkAndAdvance: advancing sequence is accepted and HWM advances
// ---------------------------------------------------------------------------
{
  const path = hwmPath('e-advance');
  checkAndAdvance(5, path);          // HWM = 5
  const result = checkAndAdvance(9, path); // advance to 9
  ok('(e) advance seq ok=true', result.ok === true, JSON.stringify(result));
  ok('(e) advance seq updates HWM to 9', readHwm(path) === 9);
}

// ---------------------------------------------------------------------------
// (f) checkAndAdvance: equal sequence is accepted (idempotent replay)
// ---------------------------------------------------------------------------
{
  const path = hwmPath('f-equal');
  checkAndAdvance(10, path);         // HWM = 10
  const result = checkAndAdvance(10, path); // replay same seq
  ok('(f) equal seq ok=true (idempotent)', result.ok === true, JSON.stringify(result));
  ok('(f) equal seq HWM stays 10', readHwm(path) === 10);
}

// ---------------------------------------------------------------------------
// (g) checkAndAdvance: LOWER sequence is REFUSED — anti-truncation guard
// ---------------------------------------------------------------------------
{
  const path = hwmPath('g-refused');
  checkAndAdvance(20, path);          // HWM = 20
  const result = checkAndAdvance(19, path); // rollback attempt
  ok('(g) lower seq ok=false', result.ok === false, JSON.stringify(result));
  ok('(g) lower seq error mentions anti-truncation', typeof result.error === 'string' && result.error.includes('anti-truncation'), result.error);
  ok('(g) lower seq error mentions both seq and hwm', result.error.includes('19') && result.error.includes('20'));
  // HWM must NOT be overwritten by the refused state
  ok('(g) HWM file unchanged after refusal', readHwm(path) === 20);
}

// ---------------------------------------------------------------------------
// (h) checkAndAdvance: sequence 0 is accepted when HWM is 0 (first seq ever)
// ---------------------------------------------------------------------------
{
  const path = hwmPath('h-zero');
  const result = checkAndAdvance(0, path);
  ok('(h) seq=0 at HWM=0 ok=true', result.ok === true, JSON.stringify(result));
  ok('(h) HWM written as 0', readHwm(path) === 0);
}

// ---------------------------------------------------------------------------
// (i) checkAndAdvance: invalid seq (negative, float) is refused without touching file
// ---------------------------------------------------------------------------
{
  const path = hwmPath('i-invalid');
  writeHwm(path, 5);

  const r1 = checkAndAdvance(-1, path);
  ok('(i) negative seq ok=false', r1.ok === false, JSON.stringify(r1));
  ok('(i) negative seq HWM unchanged', readHwm(path) === 5);

  const r2 = checkAndAdvance(2.5, path);
  ok('(i) float seq ok=false', r2.ok === false, JSON.stringify(r2));
  ok('(i) float seq HWM unchanged', readHwm(path) === 5);
}

// ---------------------------------------------------------------------------
// (j) checkAndAdvance: multiple rollback attempts — HWM stays at peak
// ---------------------------------------------------------------------------
{
  const path = hwmPath('j-peak');
  checkAndAdvance(1, path);
  checkAndAdvance(50, path);   // peak
  checkAndAdvance(49, path);   // refused
  checkAndAdvance(1,  path);   // refused
  checkAndAdvance(0,  path);   // refused
  ok('(j) HWM stays at peak 50 after rollback attempts', readHwm(path) === 50);
}

// ---------------------------------------------------------------------------
// (k) RED-TEAM (SAT-476): HWM-file deletion bypass
//
// Structural finding: readHwm() returns 0 on ENOENT by design ("first run —
// any sequence is valid").  An attacker with local write access who DELETES
// (rather than rewrites) the HWM file resets the guard to zero — the next
// ledger state, however old or truncated, is accepted as a first-run state.
// This is an inherent property of any fully-local watermark scheme; there is
// no code fix (see SECURITY.md trust-boundary note and D-168 Decisions Log).
//
// Synthetic fixture pair used by this scenario:
//   • populated ledger at sequence 999 (high-water mark persisted)
//   • replay of an old/truncated ledger at sequence 1 immediately after deletion
//
// The scenario confirms the *documented* behavior — guard resets to accept-any,
// no crash, no silent data corruption, no acceptance of an out-of-range value —
// rather than silently missing an unexpected failure mode.
// ---------------------------------------------------------------------------
{
  const path = hwmPath('k-hwm-deletion-bypass');

  // Synthetic fixture: populate ledger to a known high sequence.
  const HIGH_SEQ = 999;   // fixture watermark — represents a mature ledger
  const OLD_SEQ  = 1;     // fixture replay — old/truncated state an attacker presents

  // Step 1: establish the high watermark (normal operation).
  const r1 = checkAndAdvance(HIGH_SEQ, path);
  ok('(k) fixture: populated ledger accepted at HIGH_SEQ=999', r1.ok === true, JSON.stringify(r1));
  ok('(k) fixture: HWM file written at 999', readHwm(path) === HIGH_SEQ);

  // Step 2: confirm the anti-truncation guard blocks an incoming old state
  //         BEFORE deletion — baseline proof the guard is working.
  const rGuardActive = checkAndAdvance(OLD_SEQ, path);
  ok('(k) baseline: OLD_SEQ=1 is refused while HWM file exists', rGuardActive.ok === false,
    JSON.stringify(rGuardActive));
  ok('(k) baseline: refusal error mentions anti-truncation', typeof rGuardActive.error === 'string' &&
    rGuardActive.error.includes('anti-truncation'), rGuardActive.error);

  // Step 3: attacker action — delete (not corrupt, not rewrite) the HWM file.
  unlinkSync(path);
  const hwmAfterDeletion = readHwm(path);   // should return 0 (ENOENT → first-run)
  ok('(k) after deletion: readHwm returns 0 (guard reset to zero)', hwmAfterDeletion === 0,
    String(hwmAfterDeletion));

  // Step 4: post-deletion replay — the "old" ledger state is now accepted
  //         because the guard treats it as a first-run entry.  This is the
  //         documented bypass: fully accepted, no crash, no out-of-range error.
  const rBypass = checkAndAdvance(OLD_SEQ, path);
  ok('(k) bypass confirmed: OLD_SEQ=1 accepted after HWM deletion (documented behavior)',
    rBypass.ok === true, JSON.stringify(rBypass));
  ok('(k) bypass: HWM file re-created at OLD_SEQ=1 (not at 999)',
    readHwm(path) === OLD_SEQ);

  // Step 5: guard is functional again from the new (reset) baseline —
  //         no crash, no corrupt state, no acceptance of an out-of-range value.
  const rPostBypass = checkAndAdvance(OLD_SEQ - 1, path);   // attempt to go below OLD_SEQ
  ok('(k) post-bypass: guard still refuses further rollback below reset baseline',
    rPostBypass.ok === false, JSON.stringify(rPostBypass));

  const rAdvance = checkAndAdvance(OLD_SEQ + 1, path);       // normal advance
  ok('(k) post-bypass: normal advance above reset baseline is accepted',
    rAdvance.ok === true, JSON.stringify(rAdvance));
}

// ===========================================================================
// SAT-583  Test to verify checkpoint error reporting via checkAndAdvance
//          (specifically checkAndAdvance's return fields).
//
// This test ensures checkAndAdvance now has:
//   - new checkpoint_ok: true | false | null
//   - new checkpoint_error: string | null
//
// Tests the following scenarios:
//   (a) checkpoint failure (unwritable checkpointPath) → primary write still ok=true + checkpoint_ok=false + non-empty checkpoint_error
//   (b) success path → checkpoint_ok=true
//   (c) omitted path → checkpoint_ok=null
// ===========================================================================
{
  const hwmFile = hwmPath('sat-583');

  // Test case (a): Unwritable checkpoint path should still succeed with primary HWM write
  // but report checkpoint failure
  const unwritablePath = '/root/unwritable-file.jsonl'; // This should fail due to permissions
  const r1 = checkAndAdvance(1, hwmFile, unwritablePath);
  ok('SAT-583-a: checkpoint failure scenario - primary write ok=true', r1.ok === true, JSON.stringify(r1));
  ok('SAT-583-a: checkpoint failure scenario - checkpoint_ok=false', r1.checkpoint_ok === false, JSON.stringify(r1));
  ok('SAT-583-a: checkpoint failure scenario - checkpoint_error is not null', r1.checkpoint_error !== null, JSON.stringify(r1));
  ok('SAT-583-a: checkpoint failure scenario - checkpoint_error is string', typeof r1.checkpoint_error === 'string', JSON.stringify(r1));

  // Test case (b): Success path should show checkpoint_ok=true
  const cpFile = hwmPath('sat-583-success.jsonl');
  const r2 = checkAndAdvance(2, hwmFile, cpFile);
  ok('SAT-583-b: success path - primary write ok=true', r2.ok === true, JSON.stringify(r2));
  ok('SAT-583-b: success path - checkpoint_ok=true', r2.checkpoint_ok === true, JSON.stringify(r2));
  ok('SAT-583-b: success path - checkpoint_error is null', r2.checkpoint_error === null, JSON.stringify(r2));

  // Test case (c): Omitted path should return checkpoint_ok=null
  const hwmFile2 = hwmPath('sat-583b.hwm.json');
  const r3 = checkAndAdvance(3, hwmFile2);
  ok('SAT-583-c: omitted path - primary write ok=true', r3.ok === true, JSON.stringify(r3));
  ok('SAT-583-c: omitted path - checkpoint_ok=null', r3.checkpoint_ok === null, JSON.stringify(r3));
  ok('SAT-583-c: omitted path - checkpoint_error is null', r3.checkpoint_error === null, JSON.stringify(r3));
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
