// KnoSky naive-vs-guided agent comparison protocol (SAT-458).
// Defines the artifact schema and validators for a single comparison run:
//   tokens (in + out), tool-calls, time-to-relevant-file, correctness
// for both a naive agent and an identical task run with KnoSky guidance.
// Pure Node stdlib, ESM — no new deps.

import { PROTOCOL_VERSION } from './schema.mjs';

// ---------------------------------------------------------------------------
// Artifact type constant
// ---------------------------------------------------------------------------

/** @type {string} */
export const COMPARISON_ARTIFACT_TYPE = 'comparison-run';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Return true when `p` is a relative-safe file path:
 *   — non-empty string
 *   — does not start with `/` (Unix absolute) or Windows drive letter
 *   — contains no `..` path segment
 * @param {string} p
 * @returns {boolean}
 */
function isRelativeSafePath(p) {
  if (!p || typeof p !== 'string') return false;
  if (p.startsWith('/')) return false;
  if (/^[A-Za-z]:[\\\/]/.test(p)) return false;
  if (p.split(/[/\\]/).some(s => s === '..')) return false;
  return true;
}

/**
 * Validate one metric side object (either `naive` or `guided`).
 * Returns an array of violation strings; empty means valid.
 *
 * @param {unknown} side
 * @param {string}  label   — "naive" or "guided"
 * @returns {string[]}
 */
function validateSide(side, label) {
  const errors = [];

  if (!side || typeof side !== 'object') {
    errors.push(`${label} must be an object`);
    return errors; // can't go further
  }

  // tokens_in: non-negative integer
  if (!Number.isInteger(side.tokens_in) || side.tokens_in < 0) {
    errors.push(`${label}.tokens_in must be a non-negative integer, got: ${JSON.stringify(side.tokens_in)}`);
  }

  // tokens_out: non-negative integer
  if (!Number.isInteger(side.tokens_out) || side.tokens_out < 0) {
    errors.push(`${label}.tokens_out must be a non-negative integer, got: ${JSON.stringify(side.tokens_out)}`);
  }

  // tool_calls: non-negative integer
  if (!Number.isInteger(side.tool_calls) || side.tool_calls < 0) {
    errors.push(`${label}.tool_calls must be a non-negative integer, got: ${JSON.stringify(side.tool_calls)}`);
  }

  // time_to_relevant_file_ms: null (never found) or non-negative number
  const ttrf = side.time_to_relevant_file_ms;
  if (ttrf !== null && !(typeof ttrf === 'number' && ttrf >= 0)) {
    errors.push(
      `${label}.time_to_relevant_file_ms must be null or a non-negative number, got: ${JSON.stringify(ttrf)}`,
    );
  }

  // correct: boolean
  if (typeof side.correct !== 'boolean') {
    errors.push(`${label}.correct must be a boolean, got: ${JSON.stringify(side.correct)}`);
  }

  return errors;
}

// ---------------------------------------------------------------------------
// makeComparisonRun
// ---------------------------------------------------------------------------

/**
 * Construct a KnoSky `comparison-run` artifact envelope.
 *
 * @param {object}   opts
 * @param {string}   opts.task_id             Short identifier for this task.
 * @param {string}   opts.task_description    Human-readable description of the task.
 * @param {string[]} opts.target_files        Relative paths to the "relevant" files for this task.
 * @param {object}   opts.naive               Metrics for the naive agent (no KnoSky guidance).
 * @param {number}   opts.naive.tokens_in     Input tokens consumed.
 * @param {number}   opts.naive.tokens_out    Output tokens produced.
 * @param {number}   opts.naive.tool_calls    Total tool/function calls made.
 * @param {number|null} opts.naive.time_to_relevant_file_ms  ms until first relevant-file hit, or null.
 * @param {boolean}  opts.naive.correct       Whether the agent arrived at the correct answer.
 * @param {object}   opts.guided              Same metric shape for the KnoSky-guided agent.
 * @returns {object}
 */
export function makeComparisonRun({
  task_id,
  task_description,
  target_files = [],
  naive,
  guided,
} = {}) {
  return {
    knosky_protocol: PROTOCOL_VERSION,
    artifact_type: COMPARISON_ARTIFACT_TYPE,
    advisory: true,
    generated_at: new Date().toISOString(),
    task_id,
    task_description,
    target_files,
    naive,
    guided,
  };
}

// ---------------------------------------------------------------------------
// validateComparisonRun
// ---------------------------------------------------------------------------

/**
 * Validate a KnoSky `comparison-run` document.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {object} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateComparisonRun(doc) {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { ok: false, errors: ['doc must be an object'] };
  }

  if (doc.knosky_protocol !== PROTOCOL_VERSION) {
    errors.push(
      `knosky_protocol must be "${PROTOCOL_VERSION}", got: ${JSON.stringify(doc.knosky_protocol)}`,
    );
  }

  if (doc.artifact_type !== COMPARISON_ARTIFACT_TYPE) {
    errors.push(
      `artifact_type must be "${COMPARISON_ARTIFACT_TYPE}", got: ${JSON.stringify(doc.artifact_type)}`,
    );
  }

  if (doc.advisory !== true) {
    errors.push(`advisory must be true, got: ${JSON.stringify(doc.advisory)}`);
  }

  // task_id: non-empty string
  if (typeof doc.task_id !== 'string' || doc.task_id.length === 0) {
    errors.push(`task_id must be a non-empty string, got: ${JSON.stringify(doc.task_id)}`);
  }

  // task_description: non-empty string
  if (typeof doc.task_description !== 'string' || doc.task_description.length === 0) {
    errors.push(
      `task_description must be a non-empty string, got: ${JSON.stringify(doc.task_description)}`,
    );
  }

  // target_files: non-empty array of relative-safe path strings
  if (!Array.isArray(doc.target_files) || doc.target_files.length === 0) {
    errors.push('target_files must be a non-empty array');
  } else {
    for (let i = 0; i < doc.target_files.length; i++) {
      const p = doc.target_files[i];
      if (typeof p !== 'string' || p.length === 0) {
        errors.push(`target_files[${i}] must be a non-empty string`);
      } else if (!isRelativeSafePath(p)) {
        errors.push(`target_files[${i}] must be a relative path with no ".." segments: ${JSON.stringify(p)}`);
      }
    }
  }

  // naive and guided sides
  for (const side of ['naive', 'guided']) {
    errors.push(...validateSide(doc[side], side));
  }

  return { ok: errors.length === 0, errors };
}
