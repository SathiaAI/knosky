// KnoSky deny-overrides-allow lattice evaluator tests (SAT-507 / KS2-F1-4 / D-187).
// Run: node test/policy-lattice.test.mjs
//
// Coverage goals: 100% branch coverage on core/policy-lattice.mjs.
// No external dependencies.  No network I/O.

import { combine, evaluate, DENY, ALLOW, NOT_APPLICABLE } from '../core/policy-lattice.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (1) Exported constants
// ---------------------------------------------------------------------------
console.log('\n--- 1. Exported constants ---');

ok('(1a) DENY is the string "DENY"',            DENY           === 'DENY');
ok('(1b) ALLOW is the string "ALLOW"',          ALLOW          === 'ALLOW');
ok('(1c) NOT_APPLICABLE is the string "NOT_APPLICABLE"', NOT_APPLICABLE === 'NOT_APPLICABLE');
ok('(1d) The three constants are pairwise distinct',
  DENY !== ALLOW && DENY !== NOT_APPLICABLE && ALLOW !== NOT_APPLICABLE);

// ---------------------------------------------------------------------------
// (2) combine — trivial / edge-case inputs
// ---------------------------------------------------------------------------
console.log('\n--- 2. combine: trivial / edge-case inputs ---');

ok('(2a) empty array → NOT_APPLICABLE',         combine([])                  === NOT_APPLICABLE);
ok('(2b) null → NOT_APPLICABLE',                combine(null)                === NOT_APPLICABLE);
ok('(2c) undefined → NOT_APPLICABLE',           combine(undefined)           === NOT_APPLICABLE);
ok('(2d) non-array scalar → NOT_APPLICABLE',    combine('ALLOW')             === NOT_APPLICABLE);
ok('(2e) all unknown values → NOT_APPLICABLE',  combine(['x', 1, null, {}]) === NOT_APPLICABLE);

// ---------------------------------------------------------------------------
// (3) combine — single-value arrays (identity checks)
// ---------------------------------------------------------------------------
console.log('\n--- 3. combine: single-value arrays ---');

ok('(3a) [DENY]            → DENY',            combine([DENY])            === DENY);
ok('(3b) [ALLOW]           → ALLOW',           combine([ALLOW])           === ALLOW);
ok('(3c) [NOT_APPLICABLE]  → NOT_APPLICABLE',  combine([NOT_APPLICABLE])  === NOT_APPLICABLE);

// ---------------------------------------------------------------------------
// (4) combine — deny-overrides-allow: core fixture matrix
// ---------------------------------------------------------------------------
console.log('\n--- 4. combine: deny-overrides-allow fixtures ---');

// DENY beats ALLOW
ok('(4a) [DENY, ALLOW]         → DENY', combine([DENY, ALLOW])         === DENY);
ok('(4b) [ALLOW, DENY]         → DENY', combine([ALLOW, DENY])         === DENY);

// DENY beats NOT_APPLICABLE
ok('(4c) [DENY, NOT_APPLICABLE]   → DENY', combine([DENY, NOT_APPLICABLE])   === DENY);
ok('(4d) [NOT_APPLICABLE, DENY]   → DENY', combine([NOT_APPLICABLE, DENY])   === DENY);

// DENY beats both
ok('(4e) [ALLOW, NOT_APPLICABLE, DENY] → DENY',
  combine([ALLOW, NOT_APPLICABLE, DENY]) === DENY);
ok('(4f) [DENY, ALLOW, NOT_APPLICABLE] → DENY',
  combine([DENY, ALLOW, NOT_APPLICABLE]) === DENY);
ok('(4g) [NOT_APPLICABLE, ALLOW, DENY] → DENY',
  combine([NOT_APPLICABLE, ALLOW, DENY]) === DENY);

// ALLOW beats NOT_APPLICABLE
ok('(4h) [ALLOW, NOT_APPLICABLE]   → ALLOW', combine([ALLOW, NOT_APPLICABLE])   === ALLOW);
ok('(4i) [NOT_APPLICABLE, ALLOW]   → ALLOW', combine([NOT_APPLICABLE, ALLOW])   === ALLOW);

// All ALLOW
ok('(4j) [ALLOW, ALLOW]            → ALLOW', combine([ALLOW, ALLOW])            === ALLOW);

// All NOT_APPLICABLE
ok('(4k) [NOT_APPLICABLE, NOT_APPLICABLE] → NOT_APPLICABLE',
  combine([NOT_APPLICABLE, NOT_APPLICABLE]) === NOT_APPLICABLE);

// Multiple DENYs
ok('(4l) [DENY, DENY]             → DENY', combine([DENY, DENY])             === DENY);
ok('(4m) [DENY, DENY, ALLOW]      → DENY', combine([DENY, DENY, ALLOW])      === DENY);

// ---------------------------------------------------------------------------
// (5) combine — unknown/mixed inputs are neutral (no crash, skipped)
// ---------------------------------------------------------------------------
console.log('\n--- 5. combine: unknown values are neutral ---');

ok('(5a) [ALLOW, "BLAH"]          → ALLOW', combine([ALLOW, 'BLAH'])         === ALLOW);
ok('(5b) [DENY, "BLAH"]           → DENY',  combine([DENY,  'BLAH'])         === DENY);
ok('(5c) ["BLAH", "BLAH"]         → NOT_APPLICABLE',
  combine(['BLAH', 'BLAH'])                           === NOT_APPLICABLE);
ok('(5d) [null, ALLOW]            → ALLOW', combine([null, ALLOW])            === ALLOW);
ok('(5e) [undefined, DENY]        → DENY',  combine([undefined, DENY])        === DENY);
ok('(5f) [0, false, ALLOW]        → ALLOW', combine([0, false, ALLOW])        === ALLOW);

// ---------------------------------------------------------------------------
// (6) combine — verify short-circuit: DENY stops iteration
//     We can't directly observe short-circuiting, but we can prove that a DENY
//     at the head of a large array still returns DENY instantly without error.
// ---------------------------------------------------------------------------
console.log('\n--- 6. combine: DENY short-circuits ---');

{
  const big = [DENY, ...Array(9999).fill(ALLOW)];
  const result = combine(big);
  ok('(6a) DENY at head of 10 000-entry array → DENY', result === DENY);

  // ALLOW + 9999 NOT_APPLICABLE → ALLOW (no short-circuit needed, but verifies full scan)
  const big2 = [ALLOW, ...Array(9999).fill(NOT_APPLICABLE)];
  ok('(6b) ALLOW + 9999 NOT_APPLICABLE → ALLOW', combine(big2) === ALLOW);
}

// ---------------------------------------------------------------------------
// (7) evaluate — trivial / edge-case inputs
// ---------------------------------------------------------------------------
console.log('\n--- 7. evaluate: trivial / edge-case inputs ---');

{
  const r = evaluate([], 'anything');
  ok('(7a) empty rules array → decision NOT_APPLICABLE', r.decision === NOT_APPLICABLE);
  ok('(7b) empty rules array → reasons []',               r.reasons.length === 0);
}

{
  const r = evaluate(null, 'anything');
  ok('(7c) null rules → decision NOT_APPLICABLE',  r.decision === NOT_APPLICABLE);
  ok('(7d) null rules → reasons []',               r.reasons.length === 0);
}

{
  const r = evaluate(undefined, 'anything');
  ok('(7e) undefined rules → decision NOT_APPLICABLE', r.decision === NOT_APPLICABLE);
}

{
  const r = evaluate('not-an-array', 'anything');
  ok('(7f) non-array rules → decision NOT_APPLICABLE', r.decision === NOT_APPLICABLE);
}

// ---------------------------------------------------------------------------
// (8) evaluate — single-rule decisions
// ---------------------------------------------------------------------------
console.log('\n--- 8. evaluate: single-rule decisions ---');

ok('(8a) single DENY rule → DENY',
  evaluate([() => DENY], {}).decision === DENY);
ok('(8b) single ALLOW rule → ALLOW',
  evaluate([() => ALLOW], {}).decision === ALLOW);
ok('(8c) single NOT_APPLICABLE rule → NOT_APPLICABLE',
  evaluate([() => NOT_APPLICABLE], {}).decision === NOT_APPLICABLE);

// ---------------------------------------------------------------------------
// (9) evaluate — deny-overrides-allow through pure rule composition
// ---------------------------------------------------------------------------
console.log('\n--- 9. evaluate: deny-overrides-allow through rule composition ---');

const denyAll  = () => DENY;
const allowAll = () => ALLOW;
const naAll    = () => NOT_APPLICABLE;

ok('(9a) [denyAll, allowAll]         → DENY',
  evaluate([denyAll, allowAll], null).decision === DENY);
ok('(9b) [allowAll, denyAll]         → DENY',
  evaluate([allowAll, denyAll], null).decision === DENY);
ok('(9c) [allowAll, naAll]           → ALLOW',
  evaluate([allowAll, naAll], null).decision === ALLOW);
ok('(9d) [naAll, allowAll]           → ALLOW',
  evaluate([naAll, allowAll], null).decision === ALLOW);
ok('(9e) [naAll, naAll]              → NOT_APPLICABLE',
  evaluate([naAll, naAll], null).decision === NOT_APPLICABLE);
ok('(9f) [allowAll, allowAll, denyAll] → DENY',
  evaluate([allowAll, allowAll, denyAll], null).decision === DENY);
ok('(9g) [denyAll, naAll, allowAll]  → DENY',
  evaluate([denyAll, naAll, allowAll], null).decision === DENY);

// ---------------------------------------------------------------------------
// (10) evaluate — subject is passed to every rule
// ---------------------------------------------------------------------------
console.log('\n--- 10. evaluate: subject forwarding ---');

{
  const seen = [];
  const recorder = (subj) => { seen.push(subj); return NOT_APPLICABLE; };
  const subj = { user: 'alice', resource: 'billing' };
  evaluate([recorder, recorder], subj);
  ok('(10a) each rule receives the subject',       seen.length === 2);
  ok('(10b) subject is passed by reference/value', seen[0] === subj && seen[1] === subj);
}

// ---------------------------------------------------------------------------
// (11) evaluate — fail-closed: non-function rule → DENY + reason
// ---------------------------------------------------------------------------
console.log('\n--- 11. evaluate: fail-closed for non-function rules ---');

{
  const r = evaluate([null], 'x');
  ok('(11a) null rule → decision DENY',             r.decision === DENY);
  ok('(11b) null rule → reasons non-empty',         r.reasons.length > 0);
  ok('(11c) null rule → reason mentions rule[0]',   r.reasons[0].includes('rule[0]'));
  ok('(11d) null rule → reason mentions DENY',      r.reasons[0].includes('DENY'));
}
{
  const r = evaluate([42], 'x');
  ok('(11e) numeric rule → DENY',                   r.decision === DENY);
  ok('(11f) numeric rule → reason mentions DENY',   r.reasons[0].includes('DENY'));
}
{
  const r = evaluate(['ALLOW'], 'x');
  ok('(11g) string rule → DENY (not a function)',   r.decision === DENY);
}

// Mix: first rule fine, second is not a function
{
  const r = evaluate([allowAll, 99], 'x');
  ok('(11h) [ALLOW, <non-fn>] → DENY (non-fn overrides)', r.decision === DENY);
  ok('(11i) reason records the bad rule index',            r.reasons.some(s => s.includes('rule[1]')));
}

// ---------------------------------------------------------------------------
// (12) evaluate — fail-closed: throwing rule → DENY + reason
// ---------------------------------------------------------------------------
console.log('\n--- 12. evaluate: fail-closed for throwing rules ---');

{
  const boom = () => { throw new Error('exploded'); };
  const r = evaluate([boom], 'x');
  ok('(12a) throwing rule → DENY',                   r.decision === DENY);
  ok('(12b) throwing rule → reason non-empty',       r.reasons.length > 0);
  ok('(12c) throwing rule → reason mentions rule[0]', r.reasons[0].includes('rule[0]'));
  ok('(12d) throwing rule → reason includes error message',
    r.reasons[0].includes('exploded'));
}

// Throw with no .message
{
  const boomStr = () => { throw 'raw string error'; };
  const r = evaluate([boomStr], 'x');
  ok('(12e) throw non-Error → DENY',                r.decision === DENY);
  ok('(12f) throw non-Error → reason includes thrown value',
    r.reasons[0].includes('raw string error'));
}

// ALLOW + thrower → DENY beats ALLOW (fail-closed)
{
  const r = evaluate([allowAll, () => { throw new Error('kaboom'); }], 'x');
  ok('(12g) [ALLOW, thrower] → DENY (fail-closed)',  r.decision === DENY);
}

// ---------------------------------------------------------------------------
// (13) evaluate — unknown return values → NOT_APPLICABLE + reason
// ---------------------------------------------------------------------------
console.log('\n--- 13. evaluate: unknown return values from rules ---');

{
  const unknownRule = () => 'MAYBE';
  const r = evaluate([unknownRule], 'x');
  ok('(13a) unknown return → NOT_APPLICABLE',        r.decision === NOT_APPLICABLE);
  ok('(13b) unknown return → reason non-empty',      r.reasons.length > 0);
  ok('(13c) unknown return → reason mentions rule[0]', r.reasons[0].includes('rule[0]'));
  ok('(13d) unknown return → reason mentions NOT_APPLICABLE',
    r.reasons[0].includes('NOT_APPLICABLE'));
  ok('(13e) unknown return → reason includes returned value',
    r.reasons[0].includes('"MAYBE"'));
}

{
  const nullReturn = () => null;
  const r = evaluate([nullReturn], 'x');
  ok('(13f) null return → NOT_APPLICABLE',            r.decision === NOT_APPLICABLE);
}

{
  const numReturn = () => 0;
  const r = evaluate([numReturn], 'x');
  ok('(13g) numeric 0 return → NOT_APPLICABLE',       r.decision === NOT_APPLICABLE);
}

// DENY + unknown → still DENY (DENY dominates)
{
  const r = evaluate([denyAll, () => 'MAYBE'], 'x');
  ok('(13h) [DENY, unknown] → DENY',                 r.decision === DENY);
}

// ALLOW + unknown → ALLOW (unknown is neutral)
{
  const r = evaluate([allowAll, () => 'MAYBE'], 'x');
  ok('(13i) [ALLOW, unknown] → ALLOW',               r.decision === ALLOW);
}

// ---------------------------------------------------------------------------
// (14) evaluate — realistic policy fixture: role-based allow + IP-range deny
// ---------------------------------------------------------------------------
console.log('\n--- 14. evaluate: realistic policy fixture ---');

{
  // Allow authenticated users
  const requireAuth     = (ctx) => ctx.authenticated ? ALLOW : DENY;
  // Deny requests from a blocked IP range prefix
  const blockBadIp      = (ctx) => ctx.ip && ctx.ip.startsWith('10.0.99.') ? DENY : NOT_APPLICABLE;
  // Allow only 'admin' or 'editor' roles
  const requireRole     = (ctx) => (['admin', 'editor'].includes(ctx.role)) ? ALLOW : NOT_APPLICABLE;

  const policy = [requireAuth, blockBadIp, requireRole];

  // Authenticated admin from a normal IP → ALLOW
  const r1 = evaluate(policy, { authenticated: true, ip: '10.0.1.5', role: 'admin' });
  ok('(14a) auth + good IP + admin role → ALLOW',  r1.decision === ALLOW);

  // Authenticated admin but from blocked IP → DENY
  const r2 = evaluate(policy, { authenticated: true, ip: '10.0.99.7', role: 'admin' });
  ok('(14b) auth + blocked IP + admin role → DENY (IP rule wins)', r2.decision === DENY);

  // Unauthenticated → DENY (auth rule fires), regardless of role
  const r3 = evaluate(policy, { authenticated: false, ip: '10.0.1.5', role: 'admin' });
  ok('(14c) unauth + good IP + admin → DENY (auth rule)',         r3.decision === DENY);

  // Authenticated, good IP, but no useful role → ALLOW from requireAuth
  // (requireRole returns NOT_APPLICABLE for viewer, requireAuth already gave ALLOW)
  const r4 = evaluate(policy, { authenticated: true, ip: '10.0.1.5', role: 'viewer' });
  ok('(14d) auth + good IP + viewer role → ALLOW (auth rule covers)',  r4.decision === ALLOW);

  // Unauthenticated, blocked IP → DENY (both requireAuth and blockBadIp fire DENY)
  const r5 = evaluate(policy, { authenticated: false, ip: '10.0.99.2', role: 'viewer' });
  ok('(14e) unauth + blocked IP → DENY',                         r5.decision === DENY);
}

// ---------------------------------------------------------------------------
// (15) No-egress: the module must use no network-call patterns.
// ---------------------------------------------------------------------------
console.log('\n--- 15. no-egress: core/policy-lattice.mjs has no network calls ---');

{
  const NET_PATTERNS = [
    /\bfetch\s*\(/,
    /\bhttps?\s*\./,
    /\bnet\s*\./,
    /\bdns\s*\./,
    /XMLHttpRequest/,
    /WebSocket/,
  ];

  // Inspect exported function source text without any filesystem I/O or
  // external dependencies — synchronous so the result is recorded before exit.
  const bodies = [combine, evaluate].map(fn => fn.toString());
  const hits = bodies.flatMap((src, i) =>
    NET_PATTERNS.filter(p => p.test(src)).map(p => `export[${i}] matched ${p}`)
  );

  ok('(15) exported function bodies contain no network-call patterns',
    hits.length === 0,
    hits.length ? hits.join('; ') : '');
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
