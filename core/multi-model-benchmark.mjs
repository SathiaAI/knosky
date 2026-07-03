// KnoSky simultaneous multi-model benchmark harness (SAT-459).
//
// Defines the artifact schema and validators for a multi-model benchmark run:
// the same benchmark tasks from the comparison-run protocol (core/comparison.mjs)
// executed simultaneously across all supported model families in parallel — not
// sequentially — and collected into a single artifact for analysis.
//
// Paul's explicit instruction: "run simultaneous tests" — every model family
// (Claude, GPT, Gemini, DeepSeek, Grok) receives the same tasks at the same
// time via Promise.all.  This module owns the protocol shape; the actual
// dispatch (HTTP + Promise.all) lives in tools/ (see tools/ai-review.mjs for
// the established pattern).
//
// Pure Node stdlib, ESM — no new deps.

import { PROTOCOL_VERSION } from './schema.mjs';
// NOTE (D-176, post-PR#50 review): this file does NOT import validateComparisonRun from
// core/comparison.mjs -- it defines and validates its own multi-model artifact shape and
// never delegates to the single-model comparison-run validator. An earlier version had an
// unused import of it (dead code, flagged by review); removed rather than left in.

// ---------------------------------------------------------------------------
// Artifact type constant
// ---------------------------------------------------------------------------

/** @type {string} */
export const MULTI_MODEL_ARTIFACT_TYPE = 'multi-model-benchmark';

// ---------------------------------------------------------------------------
// Supported model families — the canonical list for simultaneous dispatch.
// Names must be stable identifiers (used as keys in per-model result maps).
// ---------------------------------------------------------------------------

/**
 * The five model families that the simultaneous harness fans out to.
 * Each entry is a { family, modelId } pair:
 *   family  — short name used as a key in multi-model result artifacts
 *   modelId — the LiteLLM / routing model string for the dispatch layer
 *
 * @type {Array<{ family: string, modelId: string }>}
 */
export const MODEL_FAMILIES = [
  { family: 'claude',   modelId: 'sathia-standard'    },
  { family: 'gpt',      modelId: 'sathia-gpt'         },
  { family: 'gemini',   modelId: 'sathia-gemini'      },
  { family: 'deepseek', modelId: 'sathia-deepseek'    },
  { family: 'grok',     modelId: 'sathia-grok'        },
];

/**
 * The set of valid family names — used in validation.
 * @type {Set<string>}
 */
const KNOWN_FAMILIES = new Set(MODEL_FAMILIES.map(m => m.family));

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
 * Validate one per-model result object.
 * Returns an array of violation strings; empty means valid.
 *
 * @param {unknown} result
 * @param {string}  label   — e.g. "results[claude]"
 * @returns {string[]}
 */
function validateModelResult(result, label) {
  const errors = [];

  if (!result || typeof result !== 'object') {
    errors.push(`${label} must be an object`);
    return errors;
  }

  // family: known non-empty string
  if (typeof result.family !== 'string' || !KNOWN_FAMILIES.has(result.family)) {
    errors.push(
      `${label}.family must be one of [${[...KNOWN_FAMILIES].join(', ')}], ` +
      `got: ${JSON.stringify(result.family)}`,
    );
  }

  // model_id: non-empty string
  if (typeof result.model_id !== 'string' || result.model_id.length === 0) {
    errors.push(`${label}.model_id must be a non-empty string, got: ${JSON.stringify(result.model_id)}`);
  }

  // status: 'ok' | 'failed'
  if (result.status !== 'ok' && result.status !== 'failed') {
    errors.push(`${label}.status must be "ok" or "failed", got: ${JSON.stringify(result.status)}`);
  }

  // error: string or null
  if (result.error !== null && typeof result.error !== 'string') {
    errors.push(`${label}.error must be null or a string, got: ${JSON.stringify(result.error)}`);
  }

  // metrics: required when status === 'ok', must pass comparison-run side validation
  if (result.status === 'ok') {
    if (!result.metrics || typeof result.metrics !== 'object') {
      errors.push(`${label}.metrics must be an object when status is "ok"`);
    } else {
      // metrics carries tokens_in / tokens_out / tool_calls / time_to_relevant_file_ms / correct
      const m = result.metrics;
      if (!Number.isInteger(m.tokens_in) || m.tokens_in < 0) {
        errors.push(`${label}.metrics.tokens_in must be a non-negative integer, got: ${JSON.stringify(m.tokens_in)}`);
      }
      if (!Number.isInteger(m.tokens_out) || m.tokens_out < 0) {
        errors.push(`${label}.metrics.tokens_out must be a non-negative integer, got: ${JSON.stringify(m.tokens_out)}`);
      }
      if (!Number.isInteger(m.tool_calls) || m.tool_calls < 0) {
        errors.push(`${label}.metrics.tool_calls must be a non-negative integer, got: ${JSON.stringify(m.tool_calls)}`);
      }
      const ttrf = m.time_to_relevant_file_ms;
      if (ttrf !== null && !(typeof ttrf === 'number' && ttrf >= 0)) {
        errors.push(
          `${label}.metrics.time_to_relevant_file_ms must be null or a non-negative number, ` +
          `got: ${JSON.stringify(ttrf)}`,
        );
      }
      if (typeof m.correct !== 'boolean') {
        errors.push(`${label}.metrics.correct must be a boolean, got: ${JSON.stringify(m.correct)}`);
      }
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// makeMultiModelRun
// ---------------------------------------------------------------------------

/**
 * Construct a KnoSky `multi-model-benchmark` artifact envelope.
 *
 * The artifact records:
 *   - the task that was run (same fields as comparison-run: id, description, target_files)
 *   - per-model results collected simultaneously via Promise.all dispatch
 *   - a summary: which models succeeded, total latency, fastest model
 *
 * @param {object}   opts
 * @param {string}   opts.task_id             Short identifier for this task.
 * @param {string}   opts.task_description    Human-readable description of the task.
 * @param {string[]} opts.target_files        Relative paths to the "relevant" files.
 * @param {object[]} opts.results             Per-model result objects (one per family).
 * @param {object}   [opts.dispatch]          Dispatch metadata: how models were invoked.
 * @param {string}   [opts.dispatch.mode]     Always "parallel" — simultaneous Promise.all.
 * @param {number}   [opts.dispatch.started_at_ms]  Wall-clock ms when the fan-out started.
 * @param {number}   [opts.dispatch.settled_at_ms]  Wall-clock ms when all settled.
 * @returns {object}
 */
export function makeMultiModelRun({
  task_id,
  task_description,
  target_files = [],
  results = [],
  dispatch = null,
} = {}) {
  // Derive summary from results
  const succeeded = results.filter(r => r && r.status === 'ok').map(r => r.family);
  const failed    = results.filter(r => r && r.status === 'failed').map(r => r.family);

  // Fastest model = min time_to_relevant_file_ms among successful runs that found the file
  let fastest_family = null;
  let minTtrf = Infinity;
  for (const r of results) {
    if (r && r.status === 'ok' && r.metrics) {
      const t = r.metrics.time_to_relevant_file_ms;
      if (typeof t === 'number' && t >= 0 && t < minTtrf) {
        minTtrf = t;
        fastest_family = r.family;
      }
    }
  }

  return {
    knosky_protocol:  PROTOCOL_VERSION,
    artifact_type:    MULTI_MODEL_ARTIFACT_TYPE,
    advisory:         true,
    generated_at:     new Date().toISOString(),
    task_id,
    task_description,
    target_files,
    dispatch: dispatch || { mode: 'parallel' },
    results,
    summary: {
      total:          results.length,
      succeeded:      succeeded.length,
      failed:         failed.length,
      succeeded_families: succeeded,
      failed_families:    failed,
      fastest_family,
    },
  };
}

// ---------------------------------------------------------------------------
// validateMultiModelRun
// ---------------------------------------------------------------------------

/**
 * Validate a KnoSky `multi-model-benchmark` document.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {object} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateMultiModelRun(doc) {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { ok: false, errors: ['doc must be an object'] };
  }

  if (doc.knosky_protocol !== PROTOCOL_VERSION) {
    errors.push(
      `knosky_protocol must be "${PROTOCOL_VERSION}", got: ${JSON.stringify(doc.knosky_protocol)}`,
    );
  }

  if (doc.artifact_type !== MULTI_MODEL_ARTIFACT_TYPE) {
    errors.push(
      `artifact_type must be "${MULTI_MODEL_ARTIFACT_TYPE}", ` +
      `got: ${JSON.stringify(doc.artifact_type)}`,
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
        errors.push(
          `target_files[${i}] must be a relative path with no ".." segments: ${JSON.stringify(p)}`,
        );
      }
    }
  }

  // dispatch: object with mode === 'parallel'
  if (!doc.dispatch || typeof doc.dispatch !== 'object') {
    errors.push('dispatch must be an object');
  } else if (doc.dispatch.mode !== 'parallel') {
    errors.push(
      `dispatch.mode must be "parallel" (simultaneous fan-out), ` +
      `got: ${JSON.stringify(doc.dispatch.mode)}`,
    );
  }

  // results: non-empty array
  if (!Array.isArray(doc.results) || doc.results.length === 0) {
    errors.push('results must be a non-empty array');
  } else {
    for (let i = 0; i < doc.results.length; i++) {
      errors.push(...validateModelResult(doc.results[i], `results[${i}]`));
    }
  }

  // summary: structural check
  if (!doc.summary || typeof doc.summary !== 'object') {
    errors.push('summary must be an object');
  } else {
    const s = doc.summary;
    if (!Number.isInteger(s.total) || s.total < 0) {
      errors.push(`summary.total must be a non-negative integer, got: ${JSON.stringify(s.total)}`);
    }
    if (!Number.isInteger(s.succeeded) || s.succeeded < 0) {
      errors.push(`summary.succeeded must be a non-negative integer, got: ${JSON.stringify(s.succeeded)}`);
    }
    if (!Number.isInteger(s.failed) || s.failed < 0) {
      errors.push(`summary.failed must be a non-negative integer, got: ${JSON.stringify(s.failed)}`);
    }
    if (!Array.isArray(s.succeeded_families)) {
      errors.push('summary.succeeded_families must be an array');
    }
    if (!Array.isArray(s.failed_families)) {
      errors.push('summary.failed_families must be an array');
    }
    // fastest_family: null or a known family string
    if (s.fastest_family !== null && typeof s.fastest_family !== 'string') {
      errors.push(
        `summary.fastest_family must be null or a string, got: ${JSON.stringify(s.fastest_family)}`,
      );
    }
  }

  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// runMultiModelBenchmark
// ---------------------------------------------------------------------------

/**
 * Execute one benchmark task simultaneously across all model families.
 *
 * This is the harness entry point that implements Paul's "simultaneous tests"
 * requirement: all models are dispatched in a single Promise.all fan-out so
 * no model waits for another to finish.
 *
 * `dispatch` is an async function provided by the caller (typically the tools/
 * layer, which owns the HTTPS + LiteLLM wiring).  It receives a { family,
 * modelId, task } descriptor and must resolve to a per-model result object:
 *
 *   {
 *     family:   string,           // must match MODEL_FAMILIES[n].family
 *     model_id: string,
 *     status:   'ok' | 'failed',
 *     error:    string | null,    // non-null on failure
 *     metrics:  {                 // present when status === 'ok'
 *       tokens_in:               number,
 *       tokens_out:              number,
 *       tool_calls:              number,
 *       time_to_relevant_file_ms: number | null,
 *       correct:                 boolean,
 *     } | null,
 *   }
 *
 * Failed dispatches (rejected promise, uncaught throw) are caught and stored
 * as `{ status: 'failed', error: <message> }` — one model failing never
 * prevents the others from completing (Promise.allSettled semantics on top
 * of the individual error handling).
 *
 * @param {object}   task
 * @param {string}   task.task_id
 * @param {string}   task.task_description
 * @param {string[]} task.target_files
 * @param {Function} dispatchFn   async (descriptor) => modelResult
 * @param {Array<{ family: string, modelId: string }>} [models]  Defaults to MODEL_FAMILIES.
 * @returns {Promise<object>}  A validated multi-model-benchmark artifact.
 */
export async function runMultiModelBenchmark(task, dispatchFn, models = MODEL_FAMILIES) {
  const startedAtMs = Date.now();

  // Fan out simultaneously — Promise.all so all models start at the same time.
  // Individual dispatch errors are caught per-slot so one failure cannot abort others.
  const results = await Promise.all(
    models.map(async ({ family, modelId }) => {
      try {
        return await dispatchFn({ family, modelId, task });
      } catch (err) {
        return {
          family,
          model_id: modelId,
          status:   'failed',
          error:    err && err.message ? err.message : String(err),
          metrics:  null,
        };
      }
    }),
  );

  const settledAtMs = Date.now();

  return makeMultiModelRun({
    task_id:          task.task_id,
    task_description: task.task_description,
    target_files:     task.target_files,
    results,
    dispatch: {
      mode:            'parallel',
      started_at_ms:   startedAtMs,
      settled_at_ms:   settledAtMs,
    },
  });
}
