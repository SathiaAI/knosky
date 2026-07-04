// KnoSky F0.3 — Build provenance: in-toto/DSSE attestation tests (SAT-547).
//
// Tests for core/provenance.mjs.
//
// Coverage:
//   F03-001  makeProvenanceStatement produces a well-formed in-toto Statement v1
//            with the correct _type, predicateType, subject, and predicate fields.
//   F03-002  makeProvenanceStatement rejects bad inputs (malformed digests, missing
//            fields) without crashing.
//   F03-003  buildDsseEnvelope produces a valid DSSE envelope: correct payloadType,
//            base64url payload, signatures array, and _ks_sig token.
//   F03-004  verifyDsseEnvelope accepts a freshly built envelope.
//   F03-005  verifyDsseEnvelope rejects a tampered payload (swap attack).
//   F03-006  verifyDsseEnvelope rejects an envelope whose signing key is revoked.
//   F03-007  verifyDsseEnvelope rejects a missing / structurally wrong envelope.
//   F03-008  dssePreAuthEncoding produces the correct PAE per DSSE § 4.2.
//   F03-009  Round-trip: statement JSON survives encode → sign → verify → decode.
//   F03-010  No external network calls: provenance.mjs imports only node: builtins
//            and the two sibling key-store functions — no fetch/https/net/dns.
//
// Run: node test/provenance.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  makeProvenanceStatement,
  buildDsseEnvelope,
  verifyDsseEnvelope,
  dssePreAuthEncoding,
  STATEMENT_TYPE,
  PREDICATE_TYPE,
  BUILD_TYPE,
  DSSE_PAYLOAD_TYPE,
} from '../core/provenance.mjs';

import {
  createKeyStore,
  rotateKey,
  revokeKey,
  makeRevocationApproval,
} from '../core/key-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

const FIXTURE = {
  packageName:     'knosky',
  packageVersion:  '0.6.3',
  // 64-char hex (SHA-256 placeholder)
  artifactDigest:  'a'.repeat(64),
  sourceCommit:    'deadbeef1234567890abcdef1234567890abcdef',
  lockfileDigest:  'b'.repeat(64),
  keyId:           'somekey0123456789abcdef0123456789abcdef01',
  finishedOn:      '2026-07-04T00:00:00.000Z',
};

// ===========================================================================
// F03-001  makeProvenanceStatement — well-formed output
// ===========================================================================
console.log('\n--- F03-001  makeProvenanceStatement ---');

{
  const stmt = makeProvenanceStatement(FIXTURE);

  ok('F03-001: _type is in-toto Statement v1', stmt._type === STATEMENT_TYPE,
    '_type=' + stmt._type);
  ok('F03-001: predicateType is SLSA Provenance v1', stmt.predicateType === PREDICATE_TYPE,
    'predicateType=' + stmt.predicateType);
  ok('F03-001: subject is an array', Array.isArray(stmt.subject));
  ok('F03-001: subject has one entry', stmt.subject.length === 1);

  const subj = stmt.subject[0];
  ok('F03-001: subject.name is <pkg>@<ver>',
    subj.name === 'knosky@0.6.3', 'name=' + subj.name);
  ok('F03-001: subject.digest.sha256 matches artifactDigest',
    subj.digest.sha256 === FIXTURE.artifactDigest.toLowerCase());

  const bd = stmt.predicate?.buildDefinition;
  ok('F03-001: buildDefinition.buildType is knosky BUILD_TYPE',
    bd?.buildType === BUILD_TYPE, 'buildType=' + bd?.buildType);
  ok('F03-001: externalParameters.source_commit matches',
    bd?.externalParameters?.source_commit === FIXTURE.sourceCommit.toLowerCase());
  ok('F03-001: externalParameters.lockfile_sha256 matches',
    bd?.externalParameters?.lockfile_sha256 === FIXTURE.lockfileDigest.toLowerCase());

  const rd = stmt.predicate?.runDetails;
  ok('F03-001: builder.id is present', typeof rd?.builder?.id === 'string');
  ok('F03-001: metadata.invocationId is keyId',
    rd?.metadata?.invocationId === FIXTURE.keyId);
  ok('F03-001: metadata.finishedOn is finishedOn',
    rd?.metadata?.finishedOn === FIXTURE.finishedOn);
}

// ===========================================================================
// F03-002  makeProvenanceStatement — input validation
// ===========================================================================
console.log('\n--- F03-002  makeProvenanceStatement — validation ---');

{
  const base = { ...FIXTURE };

  const badCases = [
    ['missing packageName',    { ...base, packageName: '' }],
    ['non-string packageName', { ...base, packageName: 42 }],
    ['bad artifactDigest (short)',   { ...base, artifactDigest: 'abc' }],
    ['bad artifactDigest (non-hex)', { ...base, artifactDigest: 'z'.repeat(64) }],
    ['bad sourceCommit (empty)',     { ...base, sourceCommit: '' }],
    ['bad lockfileDigest (short)',   { ...base, lockfileDigest: 'abc' }],
    ['missing keyId',      { ...base, keyId: '' }],
    ['missing finishedOn', { ...base, finishedOn: '' }],
  ];

  for (const [label, args] of badCases) {
    let threw = false;
    try { makeProvenanceStatement(args); } catch { threw = true; }
    ok(`F03-002: throws for ${label}`, threw);
  }
}

// ===========================================================================
// F03-008  dssePreAuthEncoding — PAE correctness (DSSE § 4.2)
// ===========================================================================
console.log('\n--- F03-008  dssePreAuthEncoding ---');

{
  // The PAE format is:  "DSSEv1" SP len(pt) SP pt SP len(pay) SP pay
  // Example: payloadType="foo" (3 bytes), payload="bar" (3 bytes)
  //   → "DSSEv1 3 foo 3 bar"
  const pae = dssePreAuthEncoding('foo', 'bar');
  const expected = Buffer.from('DSSEv1 3 foo 3 bar', 'utf8');
  ok('F03-008: PAE matches DSSEv1 spec format', pae.equals(expected),
    'got=' + pae.toString('utf8'));

  // Multi-byte UTF-8 payload type
  const ptUtf8 = DSSE_PAYLOAD_TYPE;   // "application/vnd.in-toto+json"
  const payStr = '{"hello":"world"}';
  const pae2 = dssePreAuthEncoding(ptUtf8, payStr);
  const ptLen  = Buffer.byteLength(ptUtf8, 'utf8');
  const payLen = Buffer.byteLength(payStr, 'utf8');
  const exp2   = Buffer.from(`DSSEv1 ${ptLen} ${ptUtf8} ${payLen} ${payStr}`, 'utf8');
  ok('F03-008: PAE correct for full DSSE_PAYLOAD_TYPE', pae2.equals(exp2));

  // Buffer input equivalent to string input
  const pae3 = dssePreAuthEncoding('foo', Buffer.from('bar', 'utf8'));
  ok('F03-008: Buffer payload equivalent to string payload', pae3.equals(expected));
}

// ===========================================================================
// F03-003  buildDsseEnvelope — structure
// ===========================================================================
console.log('\n--- F03-003  buildDsseEnvelope ---');

{
  const ks   = createKeyStore();
  const stmt = makeProvenanceStatement({ ...FIXTURE, keyId: ks.activeKeyId });
  const env  = buildDsseEnvelope(ks, stmt);

  ok('F03-003: payloadType is DSSE_PAYLOAD_TYPE',
    env.payloadType === DSSE_PAYLOAD_TYPE, 'payloadType=' + env.payloadType);
  ok('F03-003: payload is a non-empty string', typeof env.payload === 'string' && env.payload.length > 0);

  // Payload must be valid base64url → JSON
  let decodedStmt;
  let decodeOk = false;
  try {
    decodedStmt = JSON.parse(Buffer.from(env.payload, 'base64url').toString('utf8'));
    decodeOk = true;
  } catch { /* falls through */ }
  ok('F03-003: payload decodes to valid JSON', decodeOk);
  ok('F03-003: decoded payload _type is Statement v1',
    decodedStmt?._type === STATEMENT_TYPE);

  ok('F03-003: signatures is a non-empty array',
    Array.isArray(env.signatures) && env.signatures.length > 0);
  const sig0 = env.signatures[0];
  ok('F03-003: signatures[0].keyid is a non-empty string',
    typeof sig0?.keyid === 'string' && sig0.keyid.length > 0);
  ok('F03-003: signatures[0].sig is a non-empty base64url string',
    typeof sig0?.sig === 'string' && sig0.sig.length > 0);
  // base64url characters only
  ok('F03-003: signatures[0].sig uses base64url alphabet',
    /^[A-Za-z0-9_-]+=*$/.test(sig0?.sig ?? ''));

  ok('F03-003: _ks_sig is present',
    env._ks_sig && typeof env._ks_sig === 'object');
  ok('F03-003: _ks_sig.key_id matches signatures[0].keyid',
    env._ks_sig?.key_id === sig0?.keyid);
  ok('F03-003: _ks_sig.sig is a 64-char hex string',
    /^[0-9a-f]{64}$/.test(env._ks_sig?.sig ?? ''));
}

// ===========================================================================
// F03-004  verifyDsseEnvelope — fresh envelope accepted
// ===========================================================================
console.log('\n--- F03-004  verifyDsseEnvelope — happy path ---');

{
  const ks   = createKeyStore();
  const stmt = makeProvenanceStatement({ ...FIXTURE, keyId: ks.activeKeyId });
  const env  = buildDsseEnvelope(ks, stmt);

  const result = verifyDsseEnvelope(ks, env);
  ok('F03-004: ok=true for fresh envelope', result.ok === true, JSON.stringify(result));
  ok('F03-004: statement._type is correct', result.statement?._type === STATEMENT_TYPE,
    JSON.stringify(result.statement?._type));
  ok('F03-004: statement subject name matches',
    result.statement?.subject?.[0]?.name === 'knosky@0.6.3');
}

// ===========================================================================
// F03-009  Round-trip: statement data survives encode → sign → verify → decode
// ===========================================================================
console.log('\n--- F03-009  round-trip fidelity ---');

{
  const ks      = createKeyStore();
  const fixture = {
    packageName:    'mypkg',
    packageVersion: '1.2.3',
    artifactDigest: 'c'.repeat(64),
    sourceCommit:   'cafebabe' + '0'.repeat(32),
    lockfileDigest: 'd'.repeat(64),
    keyId:          ks.activeKeyId,
    finishedOn:     '2026-07-04T12:34:56.789Z',
  };
  const stmt   = makeProvenanceStatement(fixture);
  const env    = buildDsseEnvelope(ks, stmt);
  const result = verifyDsseEnvelope(ks, env);

  ok('F03-009: round-trip ok', result.ok === true, JSON.stringify(result));

  const s = result.statement;
  ok('F03-009: subject name survives round-trip',
    s?.subject?.[0]?.name === 'mypkg@1.2.3');
  ok('F03-009: artifactDigest survives round-trip',
    s?.subject?.[0]?.digest?.sha256 === 'c'.repeat(64));
  ok('F03-009: source_commit survives round-trip',
    s?.predicate?.buildDefinition?.externalParameters?.source_commit === ('cafebabe' + '0'.repeat(32)).toLowerCase());
  ok('F03-009: lockfile_sha256 survives round-trip',
    s?.predicate?.buildDefinition?.externalParameters?.lockfile_sha256 === 'd'.repeat(64));
  ok('F03-009: finishedOn survives round-trip',
    s?.predicate?.runDetails?.metadata?.finishedOn === '2026-07-04T12:34:56.789Z');
}

// ===========================================================================
// F03-005  verifyDsseEnvelope — tampered payload rejected
// ===========================================================================
console.log('\n--- F03-005  tampered payload ---');

{
  const ks   = createKeyStore();
  const stmt = makeProvenanceStatement({ ...FIXTURE, keyId: ks.activeKeyId });
  const env  = buildDsseEnvelope(ks, stmt);

  // Swap the payload to a different statement (different commit).
  const evilStmt = makeProvenanceStatement({
    ...FIXTURE,
    keyId:        ks.activeKeyId,
    sourceCommit: 'ffffffffffffffffffffffffffffffffffffffff',
  });
  const tamperedEnv = {
    ...env,
    payload: Buffer.from(JSON.stringify(evilStmt), 'utf8').toString('base64url'),
  };

  const result = verifyDsseEnvelope(ks, tamperedEnv);
  ok('F03-005: ok=false for swapped payload', result.ok === false, JSON.stringify(result));
  ok('F03-005: reason is pae_digest_mismatch', result.reason === 'pae_digest_mismatch',
    'reason=' + result.reason);
}

// Also test a direct base64-flip inside the payload
{
  const ks   = createKeyStore();
  const stmt = makeProvenanceStatement({ ...FIXTURE, keyId: ks.activeKeyId });
  const env  = buildDsseEnvelope(ks, stmt);

  // Flip one character in the middle of the payload.
  const payArr = env.payload.split('');
  const mid    = Math.floor(payArr.length / 2);
  payArr[mid]  = payArr[mid] === 'A' ? 'B' : 'A';
  const flippedEnv = { ...env, payload: payArr.join('') };

  const result = verifyDsseEnvelope(ks, flippedEnv);
  ok('F03-005: ok=false for bit-flipped payload', result.ok === false, JSON.stringify(result));
}

// ===========================================================================
// F03-006  verifyDsseEnvelope — revoked key rejected
// ===========================================================================
console.log('\n--- F03-006  revoked signing key rejected ---');

{
  const ks     = createKeyStore();
  const keyId1 = ks.activeKeyId;
  const stmt   = makeProvenanceStatement({ ...FIXTURE, keyId: keyId1 });
  const env    = buildDsseEnvelope(ks, stmt);

  // Rotate to give us a second key, then revoke the original.
  const keyId2 = rotateKey(ks);
  // Quorum: 1 peer (keyId2) needed; it approves revocation of keyId1.
  const approval = makeRevocationApproval(ks, keyId2, keyId1);
  revokeKey(ks, keyId1, [approval]);

  const result = verifyDsseEnvelope(ks, env);
  ok('F03-006: ok=false after signing key revoked', result.ok === false, JSON.stringify(result));
  ok('F03-006: reason includes ks_sig_invalid', result.reason?.startsWith('ks_sig_invalid'),
    'reason=' + result.reason);
}

// ===========================================================================
// F03-007  verifyDsseEnvelope — structural rejections
// ===========================================================================
console.log('\n--- F03-007  structural rejections ---');

{
  const ks   = createKeyStore();
  const stmt = makeProvenanceStatement({ ...FIXTURE, keyId: ks.activeKeyId });
  const env  = buildDsseEnvelope(ks, stmt);

  const badCases = [
    ['null',                         null],
    ['not an object (string)',        'hello'],
    ['wrong payloadType',             { ...env, payloadType: 'application/json' }],
    ['missing payload',               { ...env, payload: '' }],
    ['missing _ks_sig',               { ...env, _ks_sig: undefined }],
    ['_ks_sig not an object',         { ...env, _ks_sig: 'bad' }],
    ['payload not valid base64/JSON', { ...env, payload: '!!!notbase64!!!' }],
  ];

  for (const [label, input] of badCases) {
    let threw = false;
    let result;
    try { result = verifyDsseEnvelope(ks, input); } catch { threw = true; }
    ok(`F03-007: no throw for ${label}`, !threw,
      threw ? '(threw)' : '');
    ok(`F03-007: ok=false for ${label}`,
      !threw && result?.ok === false, threw ? '(threw)' : 'ok=' + result?.ok);
  }
}

// ===========================================================================
// F03-010  No external network calls in provenance.mjs (no-egress pin)
// ===========================================================================
console.log('\n--- F03-010  no-egress regression pin ---');

{
  const src = fs.readFileSync(path.join(ROOT, 'core/provenance.mjs'), 'utf8');

  // Must not contain any of the network-call patterns checked by no-egress-v21.
  const NETWORK_PATTERNS = [
    /\bfetch\s*\(/,
    /\bhttps?\s*\./,
    /\bnet\s*\./,
    /\bdns\s*\./,
    /XMLHttpRequest/,
    /WebSocket/,
  ];
  const netHits = src.split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => NETWORK_PATTERNS.some(p => p.test(l)));
  ok('F03-010: core/provenance.mjs contains no network-call patterns',
    netHits.length === 0,
    netHits.length ? netHits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');

  // Must not import any third-party package (only node: builtins and sibling ./key-store).
  const importLines = src.split('\n').filter(l => /^\s*import\s/.test(l));
  const badImports = importLines.filter(l => !/['"]node:/.test(l) && !/'\.\/key-store\.mjs'/.test(l));
  ok('F03-010: imports are restricted to node: builtins and ./key-store.mjs',
    badImports.length === 0,
    badImports.length ? badImports.join('; ') : '');

  // Must export the required public symbols.
  const requiredExports = [
    'makeProvenanceStatement',
    'buildDsseEnvelope',
    'verifyDsseEnvelope',
    'dssePreAuthEncoding',
    'STATEMENT_TYPE',
    'PREDICATE_TYPE',
    'BUILD_TYPE',
    'DSSE_PAYLOAD_TYPE',
  ];
  for (const sym of requiredExports) {
    ok(`F03-010: exports symbol ${sym}`, src.includes(`export`) && src.includes(sym));
  }
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
