// KnoSky ledger high-water-mark guard tests (SAT-443 / V13).
// Run: node test/ledger.test.mjs
import { mkdtempSync, rmSync } from 'node:fs';
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
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
