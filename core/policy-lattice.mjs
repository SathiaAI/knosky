// KS2-F1-4 deny-overrides-allow lattice evaluator (SAT-507 / D-187).
// Hand-rolled: zero external dependencies, no egress.
//
// Lattice model — three decision values form a total order under
// deny-overrides-allow combination semantics:
//
//   NOT_APPLICABLE  <  ALLOW  <  DENY
//
// DENY dominates: any DENY anywhere in a decision set makes the combined
// result DENY, regardless of how many ALLOW or NOT_APPLICABLE values accompany
// it.  ALLOW dominates NOT_APPLICABLE: at least one ALLOW with no DENY → ALLOW.
// All NOT_APPLICABLE (or empty set) → NOT_APPLICABLE.
//
// Fail-closed: a rule that throws, or a non-function rule entry, is treated
// as DENY.  Unknown return values are treated as NOT_APPLICABLE (neutral).

// ---------------------------------------------------------------------------
// Decision constants
// ---------------------------------------------------------------------------

/** Lattice decision: access is explicitly denied.  Dominates ALLOW. */
export const DENY           = 'DENY';

/** Lattice decision: access is explicitly allowed. */
export const ALLOW          = 'ALLOW';

/** Lattice decision: this rule has no opinion on the subject. */
export const NOT_APPLICABLE = 'NOT_APPLICABLE';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Numeric weights implement the lattice order.
// DENY (2) beats ALLOW (1) beats NOT_APPLICABLE (0).
const WEIGHT = { [DENY]: 2, [ALLOW]: 1, [NOT_APPLICABLE]: 0 };

/**
 * Return true when d is a recognised lattice constant.
 * @param {unknown} d
 * @returns {boolean}
 */
function isKnown(d) {
  return d === DENY || d === ALLOW || d === NOT_APPLICABLE;
}

// ---------------------------------------------------------------------------
// combine — join an array of decisions into one
// ---------------------------------------------------------------------------

/**
 * Combine an array of lattice decisions using deny-overrides-allow semantics.
 *
 * - Any DENY → DENY (short-circuits: remaining decisions are skipped).
 * - No DENY, at least one ALLOW → ALLOW.
 * - All NOT_APPLICABLE, or empty array → NOT_APPLICABLE.
 * - Non-array, null, undefined → NOT_APPLICABLE.
 * - Unrecognised (unknown) values are skipped — they are neutral.
 *
 * @param {unknown[]} decisions
 * @returns {'DENY'|'ALLOW'|'NOT_APPLICABLE'}
 */
export function combine(decisions) {
  if (!Array.isArray(decisions) || decisions.length === 0) {
    return NOT_APPLICABLE;
  }

  let best = NOT_APPLICABLE;

  for (const d of decisions) {
    if (!isKnown(d)) continue;               // unknown values are neutral
    if (WEIGHT[d] > WEIGHT[best]) {
      best = d;
    }
    if (best === DENY) break;                 // DENY is the maximum — short-circuit
  }

  return best;
}

// ---------------------------------------------------------------------------
// evaluate — run rule functions against a subject, then combine
// ---------------------------------------------------------------------------

/**
 * Evaluate a policy (array of rule functions) against a subject.
 *
 * Each rule is called as `rule(subject)` and must return one of the three
 * lattice constants.  Rules are evaluated left-to-right.
 *
 * Fail-closed behaviour:
 *   - A rule that throws           → treated as DENY.
 *   - A non-function rule entry    → treated as DENY (structural error).
 *   - A rule returning an unknown value → treated as NOT_APPLICABLE (neutral).
 *
 * The individual decisions are combined with {@link combine}.
 *
 * @param {Array<(subject: unknown) => string>} rules
 * @param {unknown} subject  Passed verbatim to every rule.
 * @returns {{ decision: string, reasons: string[] }}
 *   decision — combined lattice value (DENY | ALLOW | NOT_APPLICABLE).
 *   reasons  — explanatory strings for errors or unknown-value situations.
 */
export function evaluate(rules, subject) {
  if (!Array.isArray(rules) || rules.length === 0) {
    return { decision: NOT_APPLICABLE, reasons: [] };
  }

  const decisions = [];
  const reasons   = [];

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];

    if (typeof rule !== 'function') {
      decisions.push(DENY);
      reasons.push(`rule[${i}] is not a function — treated as DENY`);
      continue;
    }

    let d;
    try {
      d = rule(subject);
    } catch (err) {
      // Fail-closed: a rule that throws becomes DENY.
      decisions.push(DENY);
      reasons.push(`rule[${i}] threw: ${err && err.message ? err.message : String(err)}`);
      continue;
    }

    if (!isKnown(d)) {
      // Unknown return value → neutral (NOT_APPLICABLE).
      decisions.push(NOT_APPLICABLE);
      reasons.push(`rule[${i}] returned unknown value ${JSON.stringify(d)} — treated as NOT_APPLICABLE`);
      continue;
    }

    decisions.push(d);
  }

  return { decision: combine(decisions), reasons };
}
