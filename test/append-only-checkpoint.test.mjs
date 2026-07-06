// KnoSky F0.2 — Append-only checkpoint tests (SAT-546).
//
// PR #62 round-5 (2026-07-05): the export daemon was split out of this repo
// entirely into a separate package/repo, SathiaAI/knosky-export-daemon.
// knosky never imports, requires, or ships that package -- see F02-020/F02-021
// below and SECURITY.md, "Opt-in org export". Its own functional tests
// (parseExportConfig / readCheckpointLines / exportBatch) now live in that
// separate repo's test suite, not here.
//
// Coverage:
//   F02-001  appendCheckpointEntry writes a valid JSONL line.
//   F02-002  Multiple calls append — never overwrite.
//   F02-003  Open flag is O_APPEND / 'a' — no truncation sentinel.
//   F02-004  openCheckpoint creates the file and parent dirs; idempotent.
//   F02-005  setAppendOnlyAttribute returns a structured result; never throws.
//   F02-006  EVALUATOR_NO_NETWORK_SENTINEL is the expected constant string.
//   F02-007  no evaluator-path module imports an "export-daemon" module by
//            name (evaluator isolation — the evaluator never gains network
//            capability, whether or not the separate export-daemon package
//            is installed).
//   F02-017  No-egress: append-only-checkpoint.mjs source has no network-call
//            patterns (checkpoint module never touches the network itself).
//   F02-020  No file or directory named "daemon" or matching "export-daemon"
//            exists ANYWHERE in this repo — the export daemon was split into
//            a fully separate package/repo (SathiaAI/knosky-export-daemon);
//            this repo cannot ship it even by accident.
//   F02-021  package.json declares no dependency on "knosky-export-daemon" —
//            knosky itself has zero coupling to the export package.
//
// Run: node test/append-only-checkpoint.test.mjs

import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

import {
  appendCheckpointEntry,
  openCheckpoint,
  setAppendOnlyAttribute,
  EVALUATOR_NO_NETWORK_SENTINEL,
} from '../core/append-only-checkpoint.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Temp directory for all on-disk tests.
// ---------------------------------------------------------------------------
const tmpDir = mkdtempSync(join(tmpdir(), 'knosky-f02-test-'));

function testPath(...parts) {
  return join(tmpDir, ...parts);
}

// ===========================================================================
// F02-001  appendCheckpointEntry writes a valid JSONL line
// ===========================================================================
console.log('\n--- F02-001  appendCheckpointEntry writes a valid JSONL line ---');

{
  const p = testPath('f02-001.jsonl');
  const entry = { seq: 1, event: 'ledger_state', ts: '2026-07-04T00:00:00Z', payload_hash: 'abc123' };
  appendCheckpointEntry(p, entry);

  const content = readFileSync(p, 'utf8');
  const lines = content.split('\n').filter(l => l.trim());
  ok('F02-001: exactly one line written', lines.length === 1, String(lines.length));

  let parsed;
  let parseOk = false;
  try { parsed = JSON.parse(lines[0]); parseOk = true; } catch { /* fail below */ }
  ok('F02-001: line is valid JSON', parseOk);
  ok('F02-001: seq field preserved', parsed?.seq === 1);
  ok('F02-001: event field preserved', parsed?.event === 'ledger_state');
  ok('F02-001: ts field preserved', parsed?.ts === '2026-07-04T00:00:00Z');
  ok('F02-001: payload_hash field preserved', parsed?.payload_hash === 'abc123');
}

// ===========================================================================
// F02-002  Multiple calls append — never overwrite
// ===========================================================================
console.log('\n--- F02-002  Multiple appendCheckpointEntry calls append, not overwrite ---');

{
  const p = testPath('f02-002.jsonl');
  const entries = [
    { seq: 1, event: 'e1' },
    { seq: 2, event: 'e2' },
    { seq: 3, event: 'e3' },
  ];
  for (const e of entries) appendCheckpointEntry(p, e);

  const lines = readFileSync(p, 'utf8').trim().split('\n');
  ok('F02-002: 3 lines written', lines.length === 3, String(lines.length));

  const parsed = lines.map(l => JSON.parse(l));
  ok('F02-002: line 0 is seq=1', parsed[0].seq === 1);
  ok('F02-002: line 1 is seq=2', parsed[1].seq === 2);
  ok('F02-002: line 2 is seq=3', parsed[2].seq === 3);

  // Write again — must be line 4, not a reset.
  appendCheckpointEntry(p, { seq: 4, event: 'e4' });
  const allLines = readFileSync(p, 'utf8').trim().split('\n');
  ok('F02-002: 4th append produces 4 lines total', allLines.length === 4, String(allLines.length));
  ok('F02-002: 4th line is seq=4', JSON.parse(allLines[3]).seq === 4);
}

// ===========================================================================
// F02-003  appendCheckpointEntry uses 'a' flag (O_APPEND — no truncation)
// ===========================================================================
console.log('\n--- F02-003  O_APPEND open flag — no truncation ---');

{
  // Pre-populate the file with known content.
  const p = testPath('f02-003.jsonl');
  writeFileSync(p, '{"seq":0,"event":"pre-existing"}\n', 'utf8');

  // Call appendCheckpointEntry — must not erase the pre-existing line.
  appendCheckpointEntry(p, { seq: 1, event: 'post-existing' });

  const lines = readFileSync(p, 'utf8').trim().split('\n');
  ok('F02-003: pre-existing line is still present', lines.length === 2, String(lines.length));
  ok('F02-003: first line is the pre-existing entry', JSON.parse(lines[0]).event === 'pre-existing');
  ok('F02-003: second line is the new entry', JSON.parse(lines[1]).event === 'post-existing');
}

// ===========================================================================
// F02-004  openCheckpoint creates file + parent dirs; idempotent
// ===========================================================================
console.log('\n--- F02-004  openCheckpoint creates file and parent dirs ---');

{
  const p = testPath('sub', 'dir', 'f02-004.jsonl');
  ok('F02-004: file does not exist before openCheckpoint', !existsSync(p));

  const r1 = openCheckpoint(p);
  ok('F02-004: openCheckpoint returns object', typeof r1 === 'object' && r1 !== null);
  ok('F02-004: created=true on first call', r1.created === true, String(r1.created));
  ok('F02-004: file exists after openCheckpoint', existsSync(p));
  ok('F02-004: attributeResult is an object', typeof r1.attributeResult === 'object');
  ok('F02-004: attributeResult has ok field', 'ok' in r1.attributeResult);

  // Idempotent second call.
  const r2 = openCheckpoint(p);
  ok('F02-004: created=false on second call (already exists)', r2.created === false, String(r2.created));
  ok('F02-004: file still exists after second call', existsSync(p));

  // File is writable via appendCheckpointEntry after openCheckpoint.
  appendCheckpointEntry(p, { seq: 1, event: 'post-open' });
  const content = readFileSync(p, 'utf8').trim();
  ok('F02-004: can append after openCheckpoint', content.length > 0);
}

// ===========================================================================
// F02-005  setAppendOnlyAttribute never throws; returns structured result
// ===========================================================================
console.log('\n--- F02-005  setAppendOnlyAttribute never throws ---');

{
  // Create a temp file to run the attribute setter against.
  const p = testPath('f02-005-attr.jsonl');
  writeFileSync(p, '', 'utf8');

  let threw = false;
  let result;
  try { result = setAppendOnlyAttribute(p); } catch { threw = true; }

  ok('F02-005: setAppendOnlyAttribute does not throw', !threw);
  ok('F02-005: result is an object', typeof result === 'object' && result !== null);
  ok('F02-005: result has ok field (boolean)', typeof result.ok === 'boolean');
  ok('F02-005: result has skipped field (boolean)', typeof result.skipped === 'boolean');
  ok('F02-005: result has error field (string or null)',
    result.error === null || typeof result.error === 'string');
  // mechanism is either a string (platform-supported) or null (unsupported/skipped).
  ok('F02-005: result has mechanism field (string or null)',
    result.mechanism === null || typeof result.mechanism === 'string');

  // On an unsupported platform, skipped should be true.
  const PLATFORM = process.platform;
  if (PLATFORM !== 'linux' && PLATFORM !== 'darwin') {
    ok('F02-005: skipped=true on unsupported platform', result.skipped === true,
      'platform=' + PLATFORM);
  }

  // On a non-existent path the call must still return (not throw), ok=false.
  let threw2 = false;
  let r2;
  try { r2 = setAppendOnlyAttribute(testPath('nonexistent-f02-005.jsonl')); } catch { threw2 = true; }
  ok('F02-005: does not throw for nonexistent file', !threw2);
  ok('F02-005: returns ok=false or skipped=true for nonexistent file',
    r2 && (r2.ok === false || r2.skipped === true));
}

// ===========================================================================
// F02-006  EVALUATOR_NO_NETWORK_SENTINEL is the expected constant
// ===========================================================================
console.log('\n--- F02-006  EVALUATOR_NO_NETWORK_SENTINEL constant ---');

{
  ok('F02-006: sentinel is exported string',
    typeof EVALUATOR_NO_NETWORK_SENTINEL === 'string' &&
    EVALUATOR_NO_NETWORK_SENTINEL.length > 0);
  ok('F02-006: sentinel value is f02_evaluator_local_only',
    EVALUATOR_NO_NETWORK_SENTINEL === 'f02_evaluator_local_only');
}

// ===========================================================================
// F02-007  export-daemon.mjs is NOT imported by append-only-checkpoint.mjs
//          (evaluator isolation — the evaluator never gains network capability)
// ===========================================================================
console.log('\n--- F02-007  evaluator isolation: checkpoint does not import export-daemon ---');

{
  const checkpointSrc = fs.readFileSync(
    path.join(ROOT, 'core/append-only-checkpoint.mjs'), 'utf8');
  // Check for actual ES module import statements, not doc-comment mentions.
  // Pattern: `import ... from '...export-daemon...'` or `import('...export-daemon...')`.
  const hasImportStatement = /^\s*import\s[\s\S]*?['"].*export-daemon/m.test(checkpointSrc) ||
                             /\bimport\s*\(\s*['"].*export-daemon/.test(checkpointSrc);
  // Also check for require() references (not used in ESM but belt-and-suspenders).
  const hasRequire = /require\s*\(\s*['"].*export-daemon/.test(checkpointSrc);
  ok('F02-007: append-only-checkpoint.mjs does NOT import export-daemon', !hasImportStatement && !hasRequire,
    (hasImportStatement || hasRequire) ? 'found import of export-daemon in evaluator module' : '');
}

// ===========================================================================
// F02-017  No-egress: append-only-checkpoint.mjs has no network-call patterns
// ===========================================================================
console.log('\n--- F02-017  append-only-checkpoint.mjs: no network-call patterns ---');

{
  const NETWORK_PATTERNS = [
    /\bfetch\s*\(/,
    /\bhttps?\s*\./,
    /\bdns\s*\./,
    /XMLHttpRequest/,
    /WebSocket/,
  ];
  const src = fs.readFileSync(path.join(ROOT, 'core/append-only-checkpoint.mjs'), 'utf8');
  const lines = src.split('\n').map((l, i) => [i + 1, l]);
  const hits = lines.filter(([, l]) => NETWORK_PATTERNS.some(p => p.test(l)));
  ok('F02-017: append-only-checkpoint.mjs has no network-call patterns',
    hits.length === 0,
    hits.length ? hits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
}

// ===========================================================================

// ===========================================================================
// F02-020  Structural: no "daemon" dir or "export-daemon" file anywhere in
//          this repo — the export daemon lives in a fully separate package
//          (SathiaAI/knosky-export-daemon), not just a different directory
//          within this one.
// ===========================================================================
console.log('\n--- F02-020  export-daemon is not present anywhere in this repo ---');

{
  const walk = (dir) => {
    let hits = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'daemon') hits.push(full);
        hits = hits.concat(walk(full));
      } else if (/export-daemon/i.test(entry.name)) {
        hits.push(full);
      }
    }
    return hits;
  };
  const hits = walk(ROOT);
  ok('F02-020: no "daemon" directory or "export-daemon" file anywhere in this repo',
    hits.length === 0,
    hits.length ? hits.map((h) => path.relative(ROOT, h)).join('; ') : '');
}

// ===========================================================================
// F02-021  Structural: package.json has no dependency on knosky-export-daemon
//          — knosky itself never depends on the separate export package.
// ===========================================================================
console.log('\n--- F02-021  package.json has zero coupling to knosky-export-daemon ---');

{
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const allDeps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.optionalDependencies || {}),
    ...(pkg.peerDependencies || {}),
  };
  ok('F02-021: package.json does not depend on knosky-export-daemon',
    !Object.keys(allDeps).some((d) => d === 'knosky-export-daemon'));
}

// ===========================================================================
// F02-022  Integration: a real ledger write (checkAndAdvance) also produces
//          a checkpoint line in the JSONL file (SAT-561 / F0.2b).
//
// This test wires checkpointPath through checkAndAdvance and verifies:
//   (a) the primary HWM write is unaffected (checkAndAdvance still returns ok).
//   (b) a checkpoint line is created in the JSONL file.
//   (c) the checkpoint line carries seq + event='ledger_state'.
//   (d) multiple ledger writes produce multiple checkpoint lines (append, not
//       overwrite).
//   (e) a refused write (seq < HWM) produces NO checkpoint line — the
//       checkpoint must not record events the primary guard rejected.
//   (f) omitting checkpointPath (legacy callers) still works — no crash.
// ===========================================================================
console.log('\n--- F02-022  Integration: real ledger write produces checkpoint line ---');

import { checkAndAdvance } from '../core/ledger.mjs';

{
  const hwmFile = testPath('f02-022.hwm.json');
  const cpFile = testPath('f02-022.jsonl');

  // (a) primary write is unaffected
  const r1 = checkAndAdvance(1, hwmFile, cpFile);
  ok('F02-022-a: checkAndAdvance ok=true with checkpointPath', r1.ok === true, JSON.stringify(r1));

  // (b) checkpoint file exists after first write
  ok('F02-022-b: checkpoint file created after first ledger write', existsSync(cpFile));

  // (c) checkpoint line carries expected fields
  {
    const lines = readFileSync(cpFile, 'utf8').trim().split('\n').filter(l => l.trim());
    ok('F02-022-c: exactly one checkpoint line after first write', lines.length === 1, String(lines.length));
    let parsed;
    let parseOk = false;
    try { parsed = JSON.parse(lines[0]); parseOk = true; } catch { /* fail below */ }
    ok('F02-022-c: checkpoint line is valid JSON', parseOk);
    ok('F02-022-c: checkpoint line has seq=1', parsed?.seq === 1, JSON.stringify(parsed));
    ok('F02-022-c: checkpoint line has event=ledger_state', parsed?.event === 'ledger_state', JSON.stringify(parsed));
    ok('F02-022-c: checkpoint line has ts (ISO string)', typeof parsed?.ts === 'string' && parsed.ts.length > 0);
  }

  // (d) multiple ledger writes → multiple checkpoint lines (append, not overwrite)
  const r2 = checkAndAdvance(2, hwmFile, cpFile);
  const r3 = checkAndAdvance(3, hwmFile, cpFile);
  ok('F02-022-d: second write ok=true', r2.ok === true);
  ok('F02-022-d: third write ok=true', r3.ok === true);
  {
    const allLines = readFileSync(cpFile, 'utf8').trim().split('\n').filter(l => l.trim());
    ok('F02-022-d: three writes produce three checkpoint lines', allLines.length === 3, String(allLines.length));
    const seqs = allLines.map(l => JSON.parse(l).seq);
    ok('F02-022-d: checkpoint lines are seq 1, 2, 3 in order',
      seqs[0] === 1 && seqs[1] === 2 && seqs[2] === 3, JSON.stringify(seqs));
  }

  // (e) a refused write (seq < HWM) produces NO new checkpoint line
  const linesBefore = readFileSync(cpFile, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  const rRefused = checkAndAdvance(1, hwmFile, cpFile); // seq=1 < HWM=3 → refused
  ok('F02-022-e: refused write returns ok=false', rRefused.ok === false, JSON.stringify(rRefused));
  const linesAfter = readFileSync(cpFile, 'utf8').trim().split('\n').filter(l => l.trim()).length;
  ok('F02-022-e: refused write does NOT add a checkpoint line',
    linesAfter === linesBefore, `before=${linesBefore} after=${linesAfter}`);

  // (f) omitting checkpointPath (legacy call signature) does not throw
  const hwmFile2 = testPath('f02-022b.hwm.json');
  let threw = false;
  let rLegacy;
  try { rLegacy = checkAndAdvance(5, hwmFile2); } catch { threw = true; }
  ok('F02-022-f: checkAndAdvance without checkpointPath does not throw', !threw);
  ok('F02-022-f: legacy call returns ok=true', rLegacy && rLegacy.ok === true, JSON.stringify(rLegacy));
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
