// KnoSky F0.2 — Append-only checkpoint tests (SAT-546).
//
// Coverage:
//   F02-001  appendCheckpointEntry writes a valid JSONL line.
//   F02-002  Multiple calls append — never overwrite.
//   F02-003  Open flag is O_APPEND / 'a' — no truncation sentinel.
//   F02-004  openCheckpoint creates the file and parent dirs; idempotent.
//   F02-005  setAppendOnlyAttribute returns a structured result; never throws.
//   F02-006  EVALUATOR_NO_NETWORK_SENTINEL is the expected constant string.
//   F02-007  export-daemon.mjs is NOT imported by append-only-checkpoint.mjs
//            (evaluator isolation — no network in evaluator).
//   F02-008  parseExportConfig: off-by-default (null/false/absent → ok=false).
//   F02-009  parseExportConfig: missing/non-HTTPS destination → ok=false.
//   F02-010  parseExportConfig: valid HTTPS destination → ok=true.
//   F02-011  parseExportConfig: non-HTTPS (http://) destination → ok=false.
//   F02-012  readCheckpointLines reads and parses JSONL correctly.
//   F02-013  readCheckpointLines skips blank lines, warns on malformed JSON.
//   F02-014  readCheckpointLines respects startLine cursor and limit.
//   F02-015  exportBatch returns exhausted=true when checkpoint has no new lines.
//   F02-016  exportBatch returns ok=false on filesystem error (missing file).
//   F02-017  No-egress: append-only-checkpoint.mjs source has no network-call patterns.
//   F02-018  No-egress: export-daemon.mjs (now in daemon/, not core/) source uses
//            only node:https (expected); no evaluator core/ file ever imports it.
//            Also asserts export-daemon.mjs does not exist under core/ anymore --
//            PR #62 hardening: the boundary is a directory fact, not just a
//            source-scan convention test.
//   F02-019  daemon/ is NOT listed in package.json "files" -- export-daemon.mjs
//            can never ship in the published npm package (structural, not just
//            "not imported"), on top of re-confirming the checkpoint module
//            itself has no network imports.
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

import {
  parseExportConfig,
  readCheckpointLines,
  exportBatch,
} from '../daemon/export-daemon.mjs';

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
// F02-008  parseExportConfig: off by default
// ===========================================================================
console.log('\n--- F02-008  parseExportConfig: off-by-default ---');

{
  for (const absent of [null, undefined, false]) {
    const r = parseExportConfig(absent);
    ok(`F02-008: parseExportConfig(${JSON.stringify(absent)}) → ok=false`, r.ok === false,
      JSON.stringify(r));
    ok(`F02-008: error is export_not_configured for ${JSON.stringify(absent)}`,
      r.error === 'export_not_configured', r.error);
  }
}

// ===========================================================================
// F02-009  parseExportConfig: missing/malformed destination → ok=false
// ===========================================================================
console.log('\n--- F02-009  parseExportConfig: invalid destination ---');

{
  const cases = [
    [{}, 'export_config_missing_destination'],
    [{ destination: null }, 'export_config_missing_destination'],
    [{ destination: 'not-an-object' }, 'export_config_missing_destination'],
    [{ destination: {} }, 'export_destination_url_missing'],
    [{ destination: { url: '' } }, 'export_destination_url_missing'],
    [{ destination: { url: 'not-a-url' } }, 'export_destination_url_invalid: not-a-url'],
  ];
  for (const [cfg, expectedErr] of cases) {
    const r = parseExportConfig(cfg);
    ok(`F02-009: ok=false for ${JSON.stringify(cfg).slice(0, 60)}`, r.ok === false,
      JSON.stringify(r));
    ok(`F02-009: error starts with ${expectedErr.slice(0, 40)}`,
      typeof r.error === 'string' && r.error.startsWith(expectedErr.split(':')[0]),
      r.error);
  }
}

// ===========================================================================
// F02-010  parseExportConfig: valid HTTPS destination → ok=true
// ===========================================================================
console.log('\n--- F02-010  parseExportConfig: valid HTTPS destination ---');

{
  const cfg = {
    destination: {
      url: 'https://logs.example-org.com/knosky/ingest',
      headers: { Authorization: 'Bearer secret' },
    },
  };
  const r = parseExportConfig(cfg);
  ok('F02-010: ok=true for valid HTTPS destination', r.ok === true, JSON.stringify(r));
  ok('F02-010: config.destination.url preserved', r.config?.destination?.url === cfg.destination.url);
  ok('F02-010: config.destination.headers preserved',
    r.config?.destination?.headers?.Authorization === 'Bearer secret');
  ok('F02-010: config.batchSize is DEFAULT_BATCH_SIZE (100)',
    r.config?.batchSize === 100, String(r.config?.batchSize));
  ok('F02-010: config.retryMax is DEFAULT_RETRY_MAX (3)',
    r.config?.retryMax === 3, String(r.config?.retryMax));

  // Custom batchSize / retryMax respected.
  const cfg2 = { destination: { url: 'https://org.example/ep' }, batchSize: 50, retryMax: 1 };
  const r2 = parseExportConfig(cfg2);
  ok('F02-010: custom batchSize=50 respected', r2.config?.batchSize === 50);
  ok('F02-010: custom retryMax=1 respected', r2.config?.retryMax === 1);
}

// ===========================================================================
// F02-011  parseExportConfig: http:// (non-HTTPS) destination → ok=false
// ===========================================================================
console.log('\n--- F02-011  parseExportConfig: http:// rejected ---');

{
  const r = parseExportConfig({ destination: { url: 'http://org.example/ep' } });
  ok('F02-011: http:// destination is rejected', r.ok === false, JSON.stringify(r));
  ok('F02-011: error mentions must_be_https',
    typeof r.error === 'string' && r.error.includes('must_be_https'), r.error);
}

// ===========================================================================
// F02-012  readCheckpointLines reads and parses JSONL correctly
// ===========================================================================
console.log('\n--- F02-012  readCheckpointLines reads JSONL ---');

{
  const p = testPath('f02-012.jsonl');
  const entries = [
    { seq: 1, event: 'a' },
    { seq: 2, event: 'b' },
    { seq: 3, event: 'c' },
  ];
  for (const e of entries) appendCheckpointEntry(p, e);

  const { entries: read, nextLine } = await readCheckpointLines(p, 0, 10);
  ok('F02-012: reads 3 entries', read.length === 3, String(read.length));
  ok('F02-012: entry 0 is seq=1', read[0].seq === 1);
  ok('F02-012: entry 1 is seq=2', read[1].seq === 2);
  ok('F02-012: entry 2 is seq=3', read[2].seq === 3);
  ok('F02-012: nextLine is 3', nextLine === 3, String(nextLine));
}

// ===========================================================================
// F02-013  readCheckpointLines skips blank lines; warns on malformed JSON
// ===========================================================================
console.log('\n--- F02-013  readCheckpointLines: blank/malformed handling ---');

{
  const p = testPath('f02-013.jsonl');
  // Write a file with blank lines and one malformed line.
  const content = [
    '{"seq":1,"event":"ok1"}',
    '',                                   // blank
    'NOT VALID JSON',                     // malformed — should be skipped with warning
    '{"seq":2,"event":"ok2"}',
    '',                                   // trailing blank
  ].join('\n') + '\n';
  writeFileSync(p, content, 'utf8');

  // Capture warnings emitted during parsing.
  const warnings = [];
  const origWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(' '));

  const { entries: read } = await readCheckpointLines(p, 0, 10);

  console.warn = origWarn;   // restore

  ok('F02-013: 2 valid entries returned (blank + malformed skipped)',
    read.length === 2, String(read.length));
  ok('F02-013: entry 0 is seq=1', read[0]?.seq === 1);
  ok('F02-013: entry 1 is seq=2', read[1]?.seq === 2);
  ok('F02-013: warning emitted for malformed line',
    warnings.some(w => w.includes('malformed') || w.includes('export-daemon')),
    warnings.join('; ').slice(0, 200));
}

// ===========================================================================
// F02-014  readCheckpointLines respects startLine and limit
// ===========================================================================
console.log('\n--- F02-014  readCheckpointLines: startLine and limit ---');

{
  const p = testPath('f02-014.jsonl');
  for (let i = 1; i <= 5; i++) appendCheckpointEntry(p, { seq: i });

  // Read from line 2 (0-indexed), limit 2.
  const { entries: read, nextLine } = await readCheckpointLines(p, 2, 2);
  ok('F02-014: 2 entries returned', read.length === 2, String(read.length));
  ok('F02-014: first entry is seq=3 (skip first 2 lines)', read[0].seq === 3,
    String(read[0].seq));
  ok('F02-014: second entry is seq=4', read[1].seq === 4, String(read[1].seq));
  ok('F02-014: nextLine is 4 (startLine + entries read)', nextLine === 4, String(nextLine));
}

// ===========================================================================
// F02-015  exportBatch returns exhausted=true when no new lines
// ===========================================================================
console.log('\n--- F02-015  exportBatch exhausted=true on empty cursor ---');

{
  const p = testPath('f02-015.jsonl');
  // Write 2 entries.
  appendCheckpointEntry(p, { seq: 1 });
  appendCheckpointEntry(p, { seq: 2 });

  const cfgResult = parseExportConfig({
    destination: { url: 'https://org.example/ep' },
  });
  ok('F02-015: config parsed ok', cfgResult.ok === true);

  // Start cursor at 2 (past the end) — no new entries.
  const result = await exportBatch(cfgResult.config, p, 2);
  ok('F02-015: ok=true', result.ok === true, JSON.stringify(result));
  ok('F02-015: exhausted=true', result.exhausted === true);
  ok('F02-015: exported=0', result.exported === 0);
  ok('F02-015: nextLine=2 (unchanged)', result.nextLine === 2, String(result.nextLine));
}

// ===========================================================================
// F02-016  exportBatch returns ok=false on filesystem read error
// ===========================================================================
console.log('\n--- F02-016  exportBatch ok=false for missing checkpoint file ---');

{
  const p = testPath('does-not-exist-f02-016.jsonl');
  const cfgResult = parseExportConfig({ destination: { url: 'https://org.example/ep' } });

  const result = await exportBatch(cfgResult.config, p, 0);
  ok('F02-016: ok=false when checkpoint file missing', result.ok === false, JSON.stringify(result));
  ok('F02-016: error is a non-empty string', typeof result.error === 'string' && result.error.length > 0,
    result.error);
  ok('F02-016: nextLine unchanged at 0', result.nextLine === 0, String(result.nextLine));
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
// F02-018  No-egress: export-daemon.mjs uses only node:https (expected);
//          evaluator core files never import it
// ===========================================================================
console.log('\n--- F02-018  export-daemon.mjs isolation check ---');

{
  // PR #62 hardening: export-daemon.mjs must live OUTSIDE core/ -- structural,
  // not just a source-scan convention. Check this FIRST so a bad move fails
  // loudly here rather than producing a confusing ENOENT below.
  const oldCoreLocation = path.join(ROOT, 'core/export-daemon.mjs');
  ok('F02-018: export-daemon.mjs does NOT exist under core/ (moved to daemon/)',
    !fs.existsSync(oldCoreLocation));

  const daemonPath = path.join(ROOT, 'daemon/export-daemon.mjs');
  ok('F02-018: daemon/export-daemon.mjs exists', fs.existsSync(daemonPath));
  if (!fs.existsSync(daemonPath)) {
    // Nothing further to check without the file; avoid a hard crash below.
  } else {
    const daemonSrc = fs.readFileSync(daemonPath, 'utf8');

    // export-daemon.mjs MAY use node:https (it is the export module).
    // But it must NOT use fetch() or WebSocket (unexpected egress vectors).
    const UNEXPECTED = [/\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/];
    const daemonLines = daemonSrc.split('\n').map((l, i) => [i + 1, l]);
    const unexpectedHits = daemonLines.filter(([, l]) => UNEXPECTED.some(p => p.test(l)));
    ok('F02-018: export-daemon.mjs has no unexpected network patterns (fetch/WebSocket/XMLHttpRequest)',
      unexpectedHits.length === 0,
      unexpectedHits.length ? unexpectedHits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
  }

  // Evaluator-side modules (core/ = published, evaluator path) must NOT import export-daemon.mjs.
  // Check for actual import statements only (not doc-comment mentions).
  // PR #62 hardening: missing/renamed files now produce an attributable test
  // failure instead of an unhandled readFileSync exception crashing the suite.
  const EVALUATOR_MODULES = [
    'core/append-only-checkpoint.mjs',
    'core/ledger.mjs',
    'core/key-store.mjs',
    'core/config.mjs',
    'core/constants.mjs',
    'core/freshness.mjs',
    'core/schema.mjs',
    'core/local-ipc-identity.mjs',
  ];
  for (const rel of EVALUATOR_MODULES) {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) {
      ok(`F02-018: ${rel} does NOT import export-daemon.mjs`, false, `file not found: ${rel}`);
      continue;
    }
    const text = fs.readFileSync(abs, 'utf8');
    // Only flag actual ES module import statements, not doc-comment prose.
    const hasImport = /^\s*import\s[\s\S]*?['"].*export-daemon/m.test(text) ||
                      /\bimport\s*\(\s*['"].*export-daemon/.test(text) ||
                      /require\s*\(\s*['"].*export-daemon/.test(text);
    ok(`F02-018: ${rel} does NOT import export-daemon.mjs`, !hasImport);
  }

  // PR #62 hardening: daemon/ must not be in package.json "files" -- this
  // makes "export-daemon.mjs never ships in the npm package" a structural
  // fact, not just an unimport claim (the daemon-move alone doesn't prove
  // this without checking the publish manifest).
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const files = Array.isArray(pkg.files) ? pkg.files : [];
  ok('F02-019: package.json "files" does NOT include daemon/ (never published to npm)',
    !files.some((f) => f === 'daemon' || f.startsWith('daemon/')));
}

// ===========================================================================
// F02-019  Structural: export-daemon.mjs lives in daemon/ (not core/) and is
//          NOT imported by append-only-checkpoint.mjs (evaluator boundary
//          enforced both by directory placement and in source)
// ===========================================================================
console.log('\n--- F02-019  Structural separation: evaluator never requires daemon ---');

{
  // This test re-confirms F02-007 at a source / static level.
  const checkpointSrc = fs.readFileSync(
    path.join(ROOT, 'core/append-only-checkpoint.mjs'), 'utf8');

  // No dynamic import of export-daemon either.
  const hasDynamic = /import\s*\(\s*['"].*export-daemon/.test(checkpointSrc);
  ok('F02-019: no import() of export-daemon in checkpoint module', !hasDynamic);

  // No https, no net, no dns in the checkpoint module.
  const hasHttps = /node:https/.test(checkpointSrc);
  const hasNet   = /\bnode:net\b/.test(checkpointSrc);
  ok('F02-019: checkpoint module does not import node:https', !hasHttps);
  ok('F02-019: checkpoint module does not import node:net', !hasNet);
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
