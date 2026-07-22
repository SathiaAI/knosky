// KnoSky ledger-anchored freshness attestation tests (SAT-444).
// Run: node test/freshness.test.mjs

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  extractLedgerSeq,
  computeLedgerSeq,
  checkHighWaterMark,
  validateFreshness,
  validateFreshnessWithHwm,
} from '../core/freshness.mjs';
import { readHwm } from '../core/ledger.mjs';
import { makeRouteDoc, validateRouteDoc, makeIntentManifest, validateIntentManifest } from '../core/schema.mjs';
import { kcRoute } from '../core/route.mjs';
import { kcBundle } from '../core/bundle.mjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const NODE = process.execPath;

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// extractLedgerSeq
// ---------------------------------------------------------------------------
{
  ok('extractLedgerSeq: integer 0', extractLedgerSeq({ ledger_seq: 0 }) === 0);
  ok('extractLedgerSeq: positive integer 42', extractLedgerSeq({ ledger_seq: 42 }) === 42);
  ok('extractLedgerSeq: null field returns null', extractLedgerSeq({ ledger_seq: null }) === null);
  ok('extractLedgerSeq: missing field returns null', extractLedgerSeq({}) === null);
  ok('extractLedgerSeq: float is rejected', extractLedgerSeq({ ledger_seq: 1.5 }) === null);
  ok('extractLedgerSeq: negative is rejected', extractLedgerSeq({ ledger_seq: -1 }) === null);
  ok('extractLedgerSeq: string is rejected', extractLedgerSeq({ ledger_seq: '5' }) === null);
  ok('extractLedgerSeq: null object returns null', extractLedgerSeq(null) === null);
}

// ---------------------------------------------------------------------------
// computeLedgerSeq — non-git directory returns 0
// ---------------------------------------------------------------------------
{
  const d = mkdtempSync(join(tmpdir(), 'klfresh-nongit-'));
  const seq = computeLedgerSeq(d);
  ok('computeLedgerSeq: non-git dir returns 0', seq === 0, String(seq));
  rmSync(d, { recursive: true, force: true });
}

// computeLedgerSeq — git repo with commits returns the exact commit count
{
  const d = mkdtempSync(join(tmpdir(), 'klfresh-git-'));
  execFileSync('git', ['-C', d, 'init', '-q']);
  execFileSync('git', ['-C', d, 'config', 'user.email', 'a@b.com']);
  execFileSync('git', ['-C', d, 'config', 'user.name', 'test']);
  writeFileSync(join(d, 'a.txt'), 'one\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'c1']);
  writeFileSync(join(d, 'b.txt'), 'two\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'c2']);

  const seq = computeLedgerSeq(d);
  ok('computeLedgerSeq: 2-commit repo returns 2', seq === 2, String(seq));
  rmSync(d, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// checkHighWaterMark
// ---------------------------------------------------------------------------
{
  // First load (null lastSeq) is always accepted
  ok('hwm: null lastSeq accepts any newSeq', checkHighWaterMark(null, 10).ok === true);
  ok('hwm: null lastSeq accepts newSeq=0', checkHighWaterMark(null, 0).ok === true);
  ok('hwm: null lastSeq accepts null newSeq', checkHighWaterMark(null, null).ok === true);

  // Advancing ledger is accepted
  ok('hwm: newSeq > lastSeq accepted', checkHighWaterMark(5, 6).ok === true);
  ok('hwm: newSeq >> lastSeq accepted', checkHighWaterMark(0, 100).ok === true);

  // Equal — replay, rejected
  const eqResult = checkHighWaterMark(5, 5);
  ok('hwm: newSeq === lastSeq is rejected (replay)', eqResult.ok === false);
  ok('hwm: equal reason mentions "not advanced"', eqResult.reason && eqResult.reason.includes('not advanced'));

  // Rollback — rejected
  const rollback = checkHighWaterMark(10, 3);
  ok('hwm: newSeq < lastSeq is rejected (rollback)', rollback.ok === false);
  ok('hwm: rollback reason mentions "truncated"', rollback.reason && rollback.reason.includes('truncated'));

  // null newSeq treated as 0: rejected if lastSeq >= 0
  ok('hwm: null newSeq (treated as 0) rejected when lastSeq=5', checkHighWaterMark(5, null).ok === false);

  // Corrupt lastSeq — resets watermark (accepts)
  ok('hwm: corrupt lastSeq (-1) resets (accepts)', checkHighWaterMark(-1, 0).ok === true);
  ok('hwm: NaN lastSeq resets (accepts)', checkHighWaterMark(NaN, 5).ok === true);
}

// ---------------------------------------------------------------------------
// validateFreshness
// ---------------------------------------------------------------------------
{
  // Valid artifact, first load
  const vf1 = validateFreshness({ ledger_seq: 42 }, null);
  ok('validateFreshness: valid seq, first load passes', vf1.ok === true, JSON.stringify(vf1.errors));
  ok('validateFreshness: returns ledger_seq=42', vf1.ledger_seq === 42);

  // Valid artifact, advancing ledger
  const vf2 = validateFreshness({ ledger_seq: 10 }, 9);
  ok('validateFreshness: seq 10 > lastSeq 9 passes', vf2.ok === true, JSON.stringify(vf2.errors));

  // Missing ledger_seq fails
  const vf3 = validateFreshness({}, null);
  ok('validateFreshness: missing ledger_seq fails', vf3.ok === false);
  ok('validateFreshness: error mentions ledger_seq', vf3.errors.some(e => e.includes('ledger_seq')));
  ok('validateFreshness: ledger_seq is null on missing', vf3.ledger_seq === null);

  // Rollback fails
  const vf4 = validateFreshness({ ledger_seq: 3 }, 7);
  ok('validateFreshness: rollback seq 3 < lastSeq 7 fails', vf4.ok === false);
  ok('validateFreshness: rollback has error', vf4.errors.length >= 1);

  // Equal (replay) fails
  const vf5 = validateFreshness({ ledger_seq: 5 }, 5);
  ok('validateFreshness: equal seq fails (replay)', vf5.ok === false);
}

// ---------------------------------------------------------------------------
// schema.mjs: ledger_seq in makeRouteDoc / validateRouteDoc
// ---------------------------------------------------------------------------
{
  // Default: ledger_seq is null
  const doc0 = makeRouteDoc({ destination: 'dst' });
  ok('makeRouteDoc: default ledger_seq is null', doc0.ledger_seq === null);
  const r0 = validateRouteDoc(doc0);
  ok('makeRouteDoc default passes validateRouteDoc', r0.ok === true, JSON.stringify(r0.errors));

  // Integer value passes
  const doc1 = makeRouteDoc({ destination: 'dst', ledger_seq: 7 });
  ok('makeRouteDoc: ledger_seq=7 stored', doc1.ledger_seq === 7);
  const r1 = validateRouteDoc(doc1);
  ok('makeRouteDoc with ledger_seq=7 passes validate', r1.ok === true, JSON.stringify(r1.errors));

  // ledger_seq=0 is valid (brand-new repo)
  const doc2 = makeRouteDoc({ destination: 'dst', ledger_seq: 0 });
  ok('makeRouteDoc: ledger_seq=0 (new repo) is valid', validateRouteDoc(doc2).ok === true);

  // Float fails
  const doc3 = { ...makeRouteDoc({ destination: 'dst' }), ledger_seq: 1.5 };
  const r3 = validateRouteDoc(doc3);
  ok('validateRouteDoc: float ledger_seq fails', r3.ok === false);
  ok('validateRouteDoc: float error mentions ledger_seq', r3.errors.some(e => e.includes('ledger_seq')));

  // Negative fails
  const doc4 = { ...makeRouteDoc({ destination: 'dst' }), ledger_seq: -3 };
  ok('validateRouteDoc: negative ledger_seq fails', validateRouteDoc(doc4).ok === false);

  // String fails
  const doc5 = { ...makeRouteDoc({ destination: 'dst' }), ledger_seq: '10' };
  ok('validateRouteDoc: string ledger_seq fails', validateRouteDoc(doc5).ok === false);
}

// ---------------------------------------------------------------------------
// schema.mjs: ledger_seq in makeIntentManifest / validateIntentManifest
// ---------------------------------------------------------------------------
{
  const m0 = makeIntentManifest({ secret_scan: { status: 'clean' } });
  ok('makeIntentManifest: default ledger_seq is null', m0.ledger_seq === null);
  ok('makeIntentManifest default passes validate', validateIntentManifest(m0).ok === true);

  const m1 = makeIntentManifest({ secret_scan: { status: 'clean' }, ledger_seq: 3 });
  ok('makeIntentManifest: ledger_seq=3 stored', m1.ledger_seq === 3);
  ok('makeIntentManifest with ledger_seq=3 passes validate', validateIntentManifest(m1).ok === true);

  const mBad = { ...makeIntentManifest({ secret_scan: { status: 'clean' } }), ledger_seq: -1 };
  ok('validateIntentManifest: negative ledger_seq fails', validateIntentManifest(mBad).ok === false);
}

// ---------------------------------------------------------------------------
// kcRoute: ledger_seq propagated from ctx.city into route doc
// ---------------------------------------------------------------------------
{
  const node = {
    id: 'fs:core/auth.js',
    kind: 'file',
    title: 'Auth',
    category: 'core',
    links: [],
    provenance: { store: 'fs', ref: 'core/auth.js' },
  };

  // City carries a ledger_seq
  const ctxWithSeq = {
    city: { nodes: [node], categories: [], source_rev: null, ledger_seq: 17 },
    byId: new Map([[node.id, node]]),
  };
  const doc = kcRoute(ctxWithSeq, 'file:core/auth.js');
  ok('kcRoute: ledger_seq propagated from city (17)', doc.ledger_seq === 17, String(doc.ledger_seq));
  ok('kcRoute: result passes validateRouteDoc', validateRouteDoc(doc).ok === true,
     JSON.stringify(validateRouteDoc(doc).errors));

  // City without ledger_seq → null in doc
  const ctxNoSeq = {
    city: { nodes: [node], categories: [], source_rev: null },
    byId: new Map([[node.id, node]]),
  };
  const doc2 = kcRoute(ctxNoSeq, 'file:core/auth.js');
  ok('kcRoute: missing city ledger_seq → null in doc', doc2.ledger_seq === null, String(doc2.ledger_seq));
  ok('kcRoute: null ledger_seq still passes validateRouteDoc', validateRouteDoc(doc2).ok === true);
}

// ---------------------------------------------------------------------------
// kcBundle: ledger_seq propagated from ctx.city into manifest
// ---------------------------------------------------------------------------
{
  const node = {
    id: 'fs:src/x.mjs',
    kind: 'file',
    title: 'X',
    category: 'src',
    links: [],
    provenance: { store: 'fs', ref: 'src/x.mjs' },
  };

  // City carries a ledger_seq
  const ctxSeq = {
    city: { nodes: [node], ledger_seq: 25 },
    byId: new Map([[node.id, node]]),
  };
  const m = kcBundle(ctxSeq, [node.id]);
  ok('kcBundle: ledger_seq propagated from city (25)', m.ledger_seq === 25, String(m.ledger_seq));
  ok('kcBundle: result passes validateIntentManifest', validateIntentManifest(m).ok === true,
     JSON.stringify(validateIntentManifest(m).errors));

  // City without ledger_seq → null in manifest
  const ctxNone = {
    city: { nodes: [node] },
    byId: new Map([[node.id, node]]),
  };
  const m2 = kcBundle(ctxNone, [node.id]);
  ok('kcBundle: missing city ledger_seq → null in manifest', m2.ledger_seq === null, String(m2.ledger_seq));
  ok('kcBundle: null ledger_seq still passes validateIntentManifest', validateIntentManifest(m2).ok === true);
}

// ---------------------------------------------------------------------------
// fs-indexer integration: ledger_seq written to city output
// ---------------------------------------------------------------------------
{
  const d = mkdtempSync(join(tmpdir(), 'klfresh-idx-'));
  const out = join(d, 'city.json');

  // Init a git repo with one commit so computeLedgerSeq returns 1
  execFileSync('git', ['-C', d, 'init', '-q']);
  execFileSync('git', ['-C', d, 'config', 'user.email', 'a@b.com']);
  execFileSync('git', ['-C', d, 'config', 'user.name', 'test']);
  writeFileSync(join(d, 'doc.md'), '# Hello\n\ntest file\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'init']);

  execFileSync(
    NODE,
    [join(ROOT_DIR, 'core/fs-indexer.mjs'), '--root', d, '--out', out, '--share-safe'],
    { encoding: 'utf8' },
  );

  const city = JSON.parse(readFileSync(out, 'utf8'));
  ok('fs-indexer: ledger_seq present in city envelope',
     typeof city.ledger_seq === 'number', String(city.ledger_seq));
  ok('fs-indexer: ledger_seq is a non-negative integer',
     Number.isInteger(city.ledger_seq) && city.ledger_seq >= 0);
  ok('fs-indexer: ledger_seq matches 1 commit', city.ledger_seq === 1, String(city.ledger_seq));

  rmSync(d, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// V13 high-water-mark guard end-to-end: detect a ledger rollback
// ---------------------------------------------------------------------------
{
  // Simulate receiving two successive city snapshots.
  // The second has a lower ledger_seq (history was truncated / key resurrected).
  const city_v1 = { ledger_seq: 50 };
  const city_v2_rollback = { ledger_seq: 45 };

  const r1 = validateFreshness(city_v1, null);
  ok('v13 e2e: first city accepted (lastSeq=null)', r1.ok === true);

  const r2 = validateFreshness(city_v2_rollback, r1.ledger_seq);
  ok('v13 e2e: rolled-back city rejected', r2.ok === false);
  ok('v13 e2e: rejection reason present', r2.errors.length > 0, JSON.stringify(r2.errors));

  // An advancing snapshot is accepted
  const city_v3 = { ledger_seq: 51 };
  const r3 = validateFreshness(city_v3, r1.ledger_seq);
  ok('v13 e2e: advancing city accepted', r3.ok === true);

  // A city with no ledger_seq at all fails even on first load from second acceptance
  const city_v4_noSeq = {};
  const r4 = validateFreshness(city_v4_noSeq, r1.ledger_seq);
  ok('v13 e2e: no-seq city after anchored acceptance is rejected', r4.ok === false);
}

// ---------------------------------------------------------------------------
// validateFreshnessWithHwm — persisted high-water-mark guard (SAT-474)
// Proves that a ledger-truncation/rollback attempt is caught end-to-end via
// the freshness-attestation entry point using the persisted HWM (not just via
// core/ledger.mjs in isolation).
// ---------------------------------------------------------------------------
{
  const d = mkdtempSync(join(tmpdir(), 'klfresh-hwm-'));
  const hwmPath = join(d, 'ledger.hwm.json');

  // (1) First load: no HWM file yet — any seq is accepted.
  const r1 = validateFreshnessWithHwm({ ledger_seq: 10 }, hwmPath);
  ok('persisted-hwm e2e: first load (seq=10) accepted', r1.ok === true, JSON.stringify(r1.errors));
  ok('persisted-hwm e2e: returns ledger_seq=10', r1.ledger_seq === 10);
  ok('persisted-hwm e2e: HWM file written at 10', readHwm(hwmPath) === 10);

  // (2) Advancing ledger is accepted and HWM advances.
  const r2 = validateFreshnessWithHwm({ ledger_seq: 20 }, hwmPath);
  ok('persisted-hwm e2e: advancing seq (10→20) accepted', r2.ok === true, JSON.stringify(r2.errors));
  ok('persisted-hwm e2e: HWM advanced to 20', readHwm(hwmPath) === 20);

  // (3) Rollback attempt: seq=15 < HWM=20 — must be refused.
  const r3 = validateFreshnessWithHwm({ ledger_seq: 15 }, hwmPath);
  ok('persisted-hwm e2e: rollback (seq=15 < hwm=20) rejected', r3.ok === false);
  ok('persisted-hwm e2e: rollback error present', r3.errors.length > 0, JSON.stringify(r3.errors));
  ok('persisted-hwm e2e: rollback error mentions anti-truncation',
     r3.errors.some(e => e.includes('anti-truncation')));
  // HWM must NOT have been lowered by the refused state.
  ok('persisted-hwm e2e: HWM unchanged after rollback attempt', readHwm(hwmPath) === 20);

  // (4) After restart simulation: re-read the HWM from disk and verify defence
  //     is still enforced (this is the key distinction from the in-memory guard).
  //     Attempt another rollback — seq=5, which is well below the persisted HWM=20.
  const r4 = validateFreshnessWithHwm({ ledger_seq: 5 }, hwmPath);
  ok('persisted-hwm e2e: post-restart rollback (seq=5) still rejected', r4.ok === false);
  ok('persisted-hwm e2e: HWM still 20 after second rollback attempt', readHwm(hwmPath) === 20);

  // (5) Idempotent replay at HWM=20 is accepted (checkAndAdvance contract).
  const r5 = validateFreshnessWithHwm({ ledger_seq: 20 }, hwmPath);
  ok('persisted-hwm e2e: replay seq=20 accepted (idempotent)', r5.ok === true, JSON.stringify(r5.errors));

  // (6) Missing ledger_seq fails without touching the HWM file.
  const r6 = validateFreshnessWithHwm({}, hwmPath);
  ok('persisted-hwm e2e: missing ledger_seq fails', r6.ok === false);
  ok('persisted-hwm e2e: missing-seq error present', r6.errors.some(e => e.includes('ledger_seq')));
  ok('persisted-hwm e2e: HWM unchanged after missing-seq attempt', readHwm(hwmPath) === 20);

  rmSync(d, { recursive: true, force: true });
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
