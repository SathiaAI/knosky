// HITL escalation gate tests (D-166 / SAT-467 / SAT-466).
// Any P0/critical or ambiguous review result must surface to Paul, never silent.
// SAT-466: zero-P0/critical + all reviewers succeeded → canAutoPublish (APPROVE path).
// Run: node test/escalate.test.mjs
import { shouldEscalateToPaul } from '../core/escalate.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) Clean run — no criticals, no failures → no escalation, canAutoPublish
// ---------------------------------------------------------------------------
{
  const r = shouldEscalateToPaul({ criticals: [], failed: [], total: 2 });
  ok('(a) clean run: escalate === false', r.escalate === false);
  ok('(a) clean run: reasons is empty', r.reasons.length === 0);
  ok('(a) clean run: paulMessage is empty string', r.paulMessage === '');
  ok('(a) clean run: canAutoPublish === true (SAT-466 D-166 path)', r.canAutoPublish === true);
}

// ---------------------------------------------------------------------------
// (b) P0 / CRITICAL finding → must escalate, must NOT canAutoPublish
// ---------------------------------------------------------------------------
{
  const crit = { sev: 'CRITICAL', file: 'core/key-store.mjs', hint: 'single key takeover', role: 'QA' };
  const r = shouldEscalateToPaul({ criticals: [crit], failed: [], total: 2 });
  ok('(b) one CRITICAL: escalate === true', r.escalate === true);
  ok('(b) one CRITICAL: reasons mentions CRITICAL', r.reasons.some(s => s.includes('CRITICAL')));
  ok('(b) one CRITICAL: paulMessage non-empty', r.paulMessage.length > 0);
  ok('(b) one CRITICAL: paulMessage mentions Paul', r.paulMessage.includes('Paul'));
  ok('(b) one CRITICAL: canAutoPublish === false', r.canAutoPublish === false);
}

// ---------------------------------------------------------------------------
// (c) Multiple CRITICALs → escalate with correct count
// ---------------------------------------------------------------------------
{
  const crits = [
    { sev: 'CRITICAL', file: 'a.mjs', hint: 'issue 1', role: 'QA' },
    { sev: 'CRITICAL', file: 'b.mjs', hint: 'issue 2', role: 'Adversarial' },
  ];
  const r = shouldEscalateToPaul({ criticals: crits, failed: [], total: 2 });
  ok('(c) two CRITICALs: escalate === true', r.escalate === true);
  ok('(c) two CRITICALs: reasons mention count 2', r.reasons.some(s => s.includes('2')));
}

// ---------------------------------------------------------------------------
// (d) All reviewers failed (allFailed) → ambiguous → must escalate, not canAutoPublish
// ---------------------------------------------------------------------------
{
  const f = [
    { role: 'QA', err: 'HTTP 503', ok: false },
    { role: 'Adversarial', err: 'timeout', ok: false },
  ];
  const r = shouldEscalateToPaul({ criticals: [], failed: f, total: 2 });
  ok('(d) allFailed: escalate === true', r.escalate === true);
  ok('(d) allFailed: reasons mention "ambiguous"', r.reasons.some(s => s.includes('ambiguous')));
  ok('(d) allFailed: paulMessage non-empty', r.paulMessage.length > 0);
  ok('(d) allFailed: canAutoPublish === false', r.canAutoPublish === false);
}

// ---------------------------------------------------------------------------
// (e) Degraded (partial failure) — some reviewers failed → ambiguous → escalate
// D-166 key rule: incomplete result must not pass silently
// ---------------------------------------------------------------------------
{
  const f = [{ role: 'Adversarial', err: 'model unavailable', ok: false }];
  const r = shouldEscalateToPaul({ criticals: [], failed: f, total: 2 });
  ok('(e) degraded (1 of 2 failed): escalate === true', r.escalate === true);
  ok('(e) degraded: reasons mention "ambiguous"', r.reasons.some(s => s.includes('ambiguous')));
  ok('(e) degraded: reasons mention failed count', r.reasons.some(s => s.includes('1')));
  ok('(e) degraded: paulMessage non-empty', r.paulMessage.length > 0);
  ok('(e) degraded: paulMessage mentions Paul', r.paulMessage.includes('Paul'));
}

// ---------------------------------------------------------------------------
// (f) CRITICALs plus failed reviewers — both reasons present
// ---------------------------------------------------------------------------
{
  const crit = { sev: 'CRITICAL', file: 'x.mjs', hint: 'egress found', role: 'QA' };
  const f = [{ role: 'Architect', err: 'timeout', ok: false }];
  const r = shouldEscalateToPaul({ criticals: [crit], failed: f, total: 3 });
  ok('(f) criticals+failed: escalate === true', r.escalate === true);
  ok('(f) criticals+failed: mentions CRITICAL', r.reasons.some(s => s.includes('CRITICAL')));
  ok('(f) criticals+failed: mentions failed/ambiguous', r.reasons.some(s => s.includes('ambiguous')));
}

// ---------------------------------------------------------------------------
// (g) No-reviewer run (total=0) — zero counts, no escalation by default,
//     but canAutoPublish must also be false (no evidence of a clean review).
// ---------------------------------------------------------------------------
{
  const r = shouldEscalateToPaul({ criticals: [], failed: [], total: 0 });
  ok('(g) no-reviewer run: escalate === false', r.escalate === false);
  ok('(g) no-reviewer run: canAutoPublish === false (no evidence)', r.canAutoPublish === false);
}

// ---------------------------------------------------------------------------
// (h) warnings only (no criticals, no failures) — must NOT escalate
// ---------------------------------------------------------------------------
{
  const r = shouldEscalateToPaul({ criticals: [], failed: [], total: 2 });
  ok('(h) warnings-only (passed as empty criticals): escalate === false', r.escalate === false);
  ok('(h) warnings-only: paulMessage empty', r.paulMessage === '');
}

// ---------------------------------------------------------------------------
// (i) Return shape is always stable
// ---------------------------------------------------------------------------
{
  const r = shouldEscalateToPaul();   // no args
  ok('(i) no-args: escalate is boolean', typeof r.escalate === 'boolean');
  ok('(i) no-args: reasons is array', Array.isArray(r.reasons));
  ok('(i) no-args: paulMessage is string', typeof r.paulMessage === 'string');
  ok('(i) no-args: canAutoPublish is boolean', typeof r.canAutoPublish === 'boolean');
}

// ---------------------------------------------------------------------------
// (j) SAT-466: canAutoPublish true requires total > 0, zero criticals, zero failures
// ---------------------------------------------------------------------------
{
  // Single reviewer, clean — the minimal valid auto-publish case
  const r1 = shouldEscalateToPaul({ criticals: [], failed: [], total: 1 });
  ok('(j) single reviewer clean: canAutoPublish === true', r1.canAutoPublish === true);
  ok('(j) single reviewer clean: escalate === false', r1.escalate === false);

  // Degraded: one of two failed → NOT canAutoPublish
  const r2 = shouldEscalateToPaul({ criticals: [], failed: [{ role: 'QA', err: 'timeout', ok: false }], total: 2 });
  ok('(j) degraded (1 fail): canAutoPublish === false', r2.canAutoPublish === false);

  // Warnings only (criticals=[]) with all reviewers passing → canAutoPublish
  const r3 = shouldEscalateToPaul({ criticals: [], failed: [], total: 3 });
  ok('(j) warnings-only path: canAutoPublish === true', r3.canAutoPublish === true);
}

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
