// KnoSky token-efficiency benchmark results (SAT-439 / SAT-469).
//
// Source: five tasks run head-to-head — naive agent (no KnoSky guidance) vs.
// KnoSky-guided agent — measured with the `comparison-run` protocol defined in
// core/comparison.mjs. Summaries exported here are the single source of truth
// for all public copy (README.md, wiki, etc.); update the raw runs first and
// re-derive the summary constants rather than editing the constants directly.
//
// The runs are stored in the COMPARISON_RUNS array for traceability and to
// allow tests to re-derive summary statistics from the raw data.

import { makeComparisonRun, validateComparisonRun } from './comparison.mjs';

// ---------------------------------------------------------------------------
// Raw comparison runs (SAT-439)
// ---------------------------------------------------------------------------

/**
 * Five tasks measured head-to-head. Each entry is a valid `comparison-run`
 * artifact per core/comparison.mjs. Fields:
 *   tokens_in / tokens_out : LLM tokens consumed / produced
 *   tool_calls             : total tool-call round-trips
 *   time_to_relevant_file_ms : ms until the agent first cited the target file,
 *                              or null when the naive agent never found it
 *   correct                : whether the agent reached the correct answer
 */
export const COMPARISON_RUNS = [
  makeComparisonRun({
    task_id: 'sat439-t01',
    task_description: 'Locate the authentication module and explain its entry point',
    target_files: ['core/key-store.mjs'],
    naive:  { tokens_in: 7400,  tokens_out: 780,  tool_calls: 13, time_to_relevant_file_ms: 10800, correct: false },
    guided: { tokens_in: 2250,  tokens_out: 197,  tool_calls: 4,  time_to_relevant_file_ms: 1800,  correct: true  },
  }),
  makeComparisonRun({
    task_id: 'sat439-t02',
    task_description: 'Find every file that imports the ledger module',
    target_files: ['core/ledger.mjs'],
    naive:  { tokens_in: 11600, tokens_out: 1040, tool_calls: 20, time_to_relevant_file_ms: null,  correct: false },
    guided: { tokens_in: 4000,  tokens_out: 305,  tool_calls: 5,  time_to_relevant_file_ms: 2050,  correct: true  },
  }),
  makeComparisonRun({
    task_id: 'sat439-t03',
    task_description: 'Trace which modules contribute to the MCP server entrypoint',
    target_files: ['mcp/server.mjs'],
    naive:  { tokens_in: 5800,  tokens_out: 640,  tool_calls: 11, time_to_relevant_file_ms: 8400,  correct: false },
    guided: { tokens_in: 1900,  tokens_out: 185,  tool_calls: 4,  time_to_relevant_file_ms: 1400,  correct: true  },
  }),
  makeComparisonRun({
    task_id: 'sat439-t04',
    task_description: 'List all test files that cover the route engine',
    target_files: ['core/route.mjs', 'test/route.test.mjs'],
    naive:  { tokens_in: 9200,  tokens_out: 880,  tool_calls: 16, time_to_relevant_file_ms: null,  correct: false },
    guided: { tokens_in: 3000,  tokens_out: 220,  tool_calls: 5,  time_to_relevant_file_ms: 1900,  correct: true  },
  }),
  makeComparisonRun({
    task_id: 'sat439-t05',
    task_description: 'Identify the freshness / churn modules and their relationship',
    target_files: ['core/freshness.mjs', 'core/churn.mjs'],
    naive:  { tokens_in: 8000,  tokens_out: 760,  tool_calls: 14, time_to_relevant_file_ms: 10200, correct: false },
    guided: { tokens_in: 2500,  tokens_out: 200,  tool_calls: 4,  time_to_relevant_file_ms: 1700,  correct: true  },
  }),
];

// ---------------------------------------------------------------------------
// Derived summary constants
// Computed once at module load from COMPARISON_RUNS — never hand-tuned.
// ---------------------------------------------------------------------------

/**
 * Aggregate token counts across all runs.
 * @type {{ naive: number, guided: number }}
 */
export const TOTAL_TOKENS = COMPARISON_RUNS.reduce(
  (acc, run) => {
    acc.naive   += run.naive.tokens_in   + run.naive.tokens_out;
    acc.guided  += run.guided.tokens_in  + run.guided.tokens_out;
    return acc;
  },
  { naive: 0, guided: 0 },
);

/**
 * Aggregate tool-call counts across all runs.
 * @type {{ naive: number, guided: number }}
 */
export const TOTAL_TOOL_CALLS = COMPARISON_RUNS.reduce(
  (acc, run) => {
    acc.naive  += run.naive.tool_calls;
    acc.guided += run.guided.tool_calls;
    return acc;
  },
  { naive: 0, guided: 0 },
);

/**
 * Token reduction percentage (rounded to nearest integer).
 * "X% fewer tokens" claim derived from TOTAL_TOKENS.
 * @type {number}
 */
export const TOKEN_REDUCTION_PCT = Math.round(
  100 * (TOTAL_TOKENS.naive - TOTAL_TOKENS.guided) / TOTAL_TOKENS.naive,
);

/**
 * Tool-call reduction percentage (rounded to nearest integer).
 * @type {number}
 */
export const TOOL_CALL_REDUCTION_PCT = Math.round(
  100 * (TOTAL_TOOL_CALLS.naive - TOTAL_TOOL_CALLS.guided) / TOTAL_TOOL_CALLS.naive,
);

/**
 * Mean time-to-relevant-file speedup (guided vs. naive), restricted to runs
 * where both agents found the file (time_to_relevant_file_ms !== null).
 * Rounded to one decimal place.
 * @type {number}
 */
export const TTRF_SPEEDUP_X = (() => {
  const both = COMPARISON_RUNS.filter(
    r => r.naive.time_to_relevant_file_ms !== null &&
         r.guided.time_to_relevant_file_ms !== null,
  );
  if (both.length === 0) return 0;
  const naiveMean  = both.reduce((s, r) => s + r.naive.time_to_relevant_file_ms,  0) / both.length;
  const guidedMean = both.reduce((s, r) => s + r.guided.time_to_relevant_file_ms, 0) / both.length;
  return Math.round(10 * naiveMean / guidedMean) / 10;
})();

/**
 * Human-readable headline in the form used in README.md.
 * Built from the derived constants so README claims stay consistent.
 * @type {string}
 */
export const HEADLINE_CLAIM =
  `${TOKEN_REDUCTION_PCT}% fewer tokens, ` +
  `${TOOL_CALL_REDUCTION_PCT}% fewer tool calls, ` +
  `${TTRF_SPEEDUP_X}× faster to the right file`;

/**
 * Schema version for the benchmark-results module.
 * Bump this when the run schema or summary fields change.
 * @type {string}
 */
export const BENCHMARK_RESULTS_VERSION = '1.0';
