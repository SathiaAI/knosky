// KnoSky HITL escalation gate (D-166 / SAT-467) — any P0/critical or ambiguous
// review result must surface to Paul, never proceed silently.
// D-166 (SAT-466): zero-P0/critical + all reviewers succeeded → auto-proceed-to-publish.
// Pure function: no I/O, no external dependencies, safe to import anywhere.

/**
 * Decide whether a review result must be escalated to Paul, or may auto-publish.
 *
 * Rules (D-166 hitl gate, SAT-467 / SAT-466):
 *   - One or more CRITICAL findings   → P0, escalate immediately.
 *   - All reviewers failed             → ambiguous (no result at all), escalate.
 *   - Any reviewer failed (degraded)   → ambiguous (result is incomplete), escalate.
 *   - Zero criticals + zero failures + at least one reviewer ran
 *                                      → canAutoPublish (D-166 pre-authorized path).
 *
 * @param {object}   opts
 * @param {object[]} [opts.criticals]  CRITICAL findings ({ sev, file, hint, role }).
 * @param {object[]} [opts.failed]     Failed reviewer records ({ role, err, ok: false }).
 * @param {number}   [opts.total]      Total reviewer count dispatched this run.
 * @returns {{ escalate: boolean, reasons: string[], paulMessage: string, canAutoPublish: boolean }}
 *   escalate       — true iff the result must block and surface to Paul.
 *   reasons        — human-readable list explaining why escalation was triggered
 *                    (empty array when escalate === false).
 *   paulMessage    — the block line to embed in the PR review body;
 *                    non-empty iff escalate === true.
 *   canAutoPublish — true iff the review may auto-approve the PR (D-166 pre-authorized):
 *                    zero criticals, zero reviewer failures, and ≥1 reviewer ran.
 */
export function shouldEscalateToPaul({ criticals = [], failed = [], total = 0 } = {}) {
  const reasons = [];

  // P0 / critical findings — must never pass silently
  if (criticals.length > 0) {
    reasons.push(`${criticals.length} CRITICAL finding(s)`);
  }

  const allFailed = total > 0 && failed.length === total;

  if (allFailed) {
    // No reviewer returned a result — outcome is unknowable (ambiguous)
    reasons.push('all reviewers failed (no result — ambiguous)');
  } else if (failed.length > 0) {
    // At least one reviewer failed — remaining results are incomplete (ambiguous)
    reasons.push(`${failed.length} of ${total} reviewer(s) failed (degraded — ambiguous)`);
  }

  const escalate = reasons.length > 0;

  // D-166 (SAT-466): pre-authorized auto-publish path — zero criticals, all reviewers
  // succeeded, and at least one reviewer actually ran.  Do NOT auto-publish when total
  // is 0 (no-reviewer synthetic run) — that would be a silent pass with no evidence.
  const canAutoPublish = !escalate && total > 0 && failed.length === 0;

  return {
    escalate,
    reasons,
    paulMessage: escalate
      ? 'Merge blocked until CRITICAL items are resolved or dismissed by Paul.'
      : '',
    canAutoPublish,
  };
}
