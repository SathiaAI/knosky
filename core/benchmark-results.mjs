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

// ---------------------------------------------------------------------------
// formatBenchmarkReport (SAT-460)
// ---------------------------------------------------------------------------

/**
 * Produce a human-readable Markdown benchmark report from the comparison runs
 * stored in this module.  The report is deterministic — same input → same
 * output — and safe to embed in wikis, PR comments, or printed to stdout.
 *
 * Layout:
 *   1. Headline summary block (the three key numbers)
 *   2. Per-run table (task id, tokens naive/guided, tool calls, TTRF, correct)
 *   3. Footer with provenance note
 *
 * @param {object}   [opts]
 * @param {object[]} [opts.runs=COMPARISON_RUNS]   — override for testing.
 * @returns {string}  Markdown string, no trailing newline.
 */
export function formatBenchmarkReport({ runs = COMPARISON_RUNS } = {}) {
  // --- summary numbers (re-derived from the provided runs so the function is
  //     self-contained and testable with custom run sets) -------------------
  const totalNaiveTok   = runs.reduce((s, r) => s + r.naive.tokens_in  + r.naive.tokens_out,  0);
  const totalGuidedTok  = runs.reduce((s, r) => s + r.guided.tokens_in + r.guided.tokens_out, 0);
  const totalNaiveCalls = runs.reduce((s, r) => s + r.naive.tool_calls,  0);
  const totalGuidedCalls = runs.reduce((s, r) => s + r.guided.tool_calls, 0);

  const tokenPct = totalNaiveTok > 0
    ? Math.round(100 * (totalNaiveTok - totalGuidedTok) / totalNaiveTok)
    : 0;
  const callPct = totalNaiveCalls > 0
    ? Math.round(100 * (totalNaiveCalls - totalGuidedCalls) / totalNaiveCalls)
    : 0;

  const both = runs.filter(
    r => r.naive.time_to_relevant_file_ms !== null &&
         r.guided.time_to_relevant_file_ms !== null,
  );
  const speedup = both.length > 0
    ? Math.round(
        10 * (both.reduce((s, r) => s + r.naive.time_to_relevant_file_ms,  0) / both.length) /
             (both.reduce((s, r) => s + r.guided.time_to_relevant_file_ms, 0) / both.length),
      ) / 10
    : 0;
  const speedupStr = Number.isInteger(speedup) ? String(speedup) : speedup.toFixed(1);

  const guidedCorrect = runs.filter(r => r.guided.correct).length;
  const naiveCorrect  = runs.filter(r => r.naive.correct).length;

  // --- headline block -------------------------------------------------------
  const lines = [
    '## KnoSky token-efficiency benchmark (SAT-439)',
    '',
    `**${tokenPct}% fewer tokens · ${callPct}% fewer tool calls · ${speedupStr}× faster to the right file**`,
    '',
    `_${runs.length} tasks, naive agent vs. KnoSky-guided agent._`,
    `_Guided: ${guidedCorrect}/${runs.length} correct. Naive: ${naiveCorrect}/${runs.length} correct._`,
    '',
    '### Per-task results',
    '',
    '| Task | Tokens (naive) | Tokens (guided) | Tool calls (naive) | Tool calls (guided) | TTRF naive (ms) | TTRF guided (ms) | Guided correct |',
    '|------|---------------:|----------------:|-------------------:|--------------------:|----------------:|-----------------:|:--------------:|',
  ];

  for (const run of runs) {
    const tnaive  = run.naive.tokens_in  + run.naive.tokens_out;
    const tguided = run.guided.tokens_in + run.guided.tokens_out;
    const ttrfN = run.naive.time_to_relevant_file_ms  === null ? '—' : String(run.naive.time_to_relevant_file_ms);
    const ttrfG = run.guided.time_to_relevant_file_ms === null ? '—' : String(run.guided.time_to_relevant_file_ms);
    const correct = run.guided.correct ? '✓' : '✗';
    lines.push(
      `| ${run.task_id} | ${tnaive} | ${tguided} | ${run.naive.tool_calls} | ${run.guided.tool_calls} | ${ttrfN} | ${ttrfG} | ${correct} |`,
    );
  }

  lines.push('');
  lines.push(`_Data source: \`core/benchmark-results.mjs\` (BENCHMARK_RESULTS_VERSION ${BENCHMARK_RESULTS_VERSION})._`);

  return lines.join('\n');
}
