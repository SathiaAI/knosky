// KnoSky benchmark-results module tests (SAT-460).
// Covers the module-level constants and the formatBenchmarkReport() reporter.
// Run: node test/benchmark-results.test.mjs
import {
  COMPARISON_RUNS,
  TOTAL_TOKENS,
  TOTAL_TOOL_CALLS,
  TOKEN_REDUCTION_PCT,
  TOOL_CALL_REDUCTION_PCT,
  TTRF_SPEEDUP_X,
  HEADLINE_CLAIM,
  BENCHMARK_RESULTS_VERSION,
  formatBenchmarkReport,
} from '../core/benchmark-results.mjs';

import { validateComparisonRun } from '../core/comparison.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) Module-level exports exist and have correct types
// ---------------------------------------------------------------------------
{
  ok('(a) BENCHMARK_RESULTS_VERSION is "1.0"', BENCHMARK_RESULTS_VERSION === '1.0');
  ok('(a) COMPARISON_RUNS is a non-empty array',
     Array.isArray(COMPARISON_RUNS) && COMPARISON_RUNS.length > 0);
  ok('(a) TOTAL_TOKENS has naive and guided number fields',
     typeof TOTAL_TOKENS.naive === 'number' && typeof TOTAL_TOKENS.guided === 'number');
  ok('(a) TOTAL_TOOL_CALLS has naive and guided number fields',
     typeof TOTAL_TOOL_CALLS.naive === 'number' && typeof TOTAL_TOOL_CALLS.guided === 'number');
  ok('(a) TOKEN_REDUCTION_PCT is a number', typeof TOKEN_REDUCTION_PCT === 'number');
  ok('(a) TOOL_CALL_REDUCTION_PCT is a number', typeof TOOL_CALL_REDUCTION_PCT === 'number');
  ok('(a) TTRF_SPEEDUP_X is a number', typeof TTRF_SPEEDUP_X === 'number');
  ok('(a) HEADLINE_CLAIM is a non-empty string',
     typeof HEADLINE_CLAIM === 'string' && HEADLINE_CLAIM.length > 0);
  ok('(a) formatBenchmarkReport is a function', typeof formatBenchmarkReport === 'function');
}

// ---------------------------------------------------------------------------
// (b) Every COMPARISON_RUN passes the comparison-run schema validator
// ---------------------------------------------------------------------------
{
  for (let i = 0; i < COMPARISON_RUNS.length; i++) {
    const result = validateComparisonRun(COMPARISON_RUNS[i]);
    ok(`(b) COMPARISON_RUNS[${i}] passes schema validation`, result.ok === true,
       result.ok ? '' : JSON.stringify(result.errors));
  }
}

// ---------------------------------------------------------------------------
// (c) Derived totals are consistent with COMPARISON_RUNS
// ---------------------------------------------------------------------------
{
  const naiveTok  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tokens_in  + r.naive.tokens_out,  0);
  const guidedTok = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tokens_in + r.guided.tokens_out, 0);
  ok('(c) TOTAL_TOKENS.naive  matches sum over runs', TOTAL_TOKENS.naive  === naiveTok,
     `expected ${naiveTok}, got ${TOTAL_TOKENS.naive}`);
  ok('(c) TOTAL_TOKENS.guided matches sum over runs', TOTAL_TOKENS.guided === guidedTok,
     `expected ${guidedTok}, got ${TOTAL_TOKENS.guided}`);

  const naiveCalls  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tool_calls,  0);
  const guidedCalls = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tool_calls, 0);
  ok('(c) TOTAL_TOOL_CALLS.naive  matches sum over runs', TOTAL_TOOL_CALLS.naive  === naiveCalls,
     `expected ${naiveCalls}, got ${TOTAL_TOOL_CALLS.naive}`);
  ok('(c) TOTAL_TOOL_CALLS.guided matches sum over runs', TOTAL_TOOL_CALLS.guided === guidedCalls,
     `expected ${guidedCalls}, got ${TOTAL_TOOL_CALLS.guided}`);
}

// ---------------------------------------------------------------------------
// (d) Derived percentage constants are correctly computed
// ---------------------------------------------------------------------------
{
  const naiveTok  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tokens_in  + r.naive.tokens_out,  0);
  const guidedTok = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tokens_in + r.guided.tokens_out, 0);
  const expectedTokenPct = Math.round(100 * (naiveTok - guidedTok) / naiveTok);
  ok('(d) TOKEN_REDUCTION_PCT is correctly derived', TOKEN_REDUCTION_PCT === expectedTokenPct,
     `expected ${expectedTokenPct}, got ${TOKEN_REDUCTION_PCT}`);

  const naiveCalls  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tool_calls,  0);
  const guidedCalls = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tool_calls, 0);
  const expectedCallPct = Math.round(100 * (naiveCalls - guidedCalls) / naiveCalls);
  ok('(d) TOOL_CALL_REDUCTION_PCT is correctly derived', TOOL_CALL_REDUCTION_PCT === expectedCallPct,
     `expected ${expectedCallPct}, got ${TOOL_CALL_REDUCTION_PCT}`);

  const both = COMPARISON_RUNS.filter(
    r => r.naive.time_to_relevant_file_ms !== null &&
         r.guided.time_to_relevant_file_ms !== null,
  );
  const naiveMean  = both.reduce((s, r) => s + r.naive.time_to_relevant_file_ms,  0) / both.length;
  const guidedMean = both.reduce((s, r) => s + r.guided.time_to_relevant_file_ms, 0) / both.length;
  const expectedSpeedup = Math.round(10 * naiveMean / guidedMean) / 10;
  ok('(d) TTRF_SPEEDUP_X is correctly derived', TTRF_SPEEDUP_X === expectedSpeedup,
     `expected ${expectedSpeedup}, got ${TTRF_SPEEDUP_X}`);
}

// ---------------------------------------------------------------------------
// (e) Guided always beats naive (sanity checks on the real data)
// ---------------------------------------------------------------------------
{
  ok('(e) TOKEN_REDUCTION_PCT > 0 (guided uses fewer tokens)',    TOKEN_REDUCTION_PCT   > 0);
  ok('(e) TOOL_CALL_REDUCTION_PCT > 0 (guided fewer tool calls)', TOOL_CALL_REDUCTION_PCT > 0);
  ok('(e) TTRF_SPEEDUP_X > 1 (guided reaches file faster)',       TTRF_SPEEDUP_X > 1);
  ok('(e) all guided runs answered correctly',
     COMPARISON_RUNS.every(r => r.guided.correct === true));
  ok('(e) no naive runs answered correctly',
     COMPARISON_RUNS.every(r => r.naive.correct === false));
}

// ---------------------------------------------------------------------------
// (f) formatBenchmarkReport — structural checks on the real data
// ---------------------------------------------------------------------------
{
  const report = formatBenchmarkReport();

  ok('(f) formatBenchmarkReport returns a non-empty string',
     typeof report === 'string' && report.length > 0);

  // Must contain the SAT-439 provenance label
  ok('(f) report contains SAT-439 provenance', report.includes('SAT-439'));

  // Must contain each of the three headline numbers
  const speedupStr = Number.isInteger(TTRF_SPEEDUP_X)
    ? String(TTRF_SPEEDUP_X) : TTRF_SPEEDUP_X.toFixed(1);
  ok(`(f) report contains "${TOKEN_REDUCTION_PCT}% fewer tokens"`,
     report.includes(`${TOKEN_REDUCTION_PCT}% fewer tokens`));
  ok(`(f) report contains "${TOOL_CALL_REDUCTION_PCT}% fewer tool calls"`,
     report.includes(`${TOOL_CALL_REDUCTION_PCT}% fewer tool calls`));
  ok(`(f) report contains "${speedupStr}× faster to the right file"`,
     report.includes(`${speedupStr}× faster to the right file`));

  // Must contain an H2 heading
  ok('(f) report has at least one Markdown H2 heading', /^##\s+\S/m.test(report));

  // Must contain a Markdown table (pipe-delimited header row)
  ok('(f) report contains a Markdown table', /^\|.+\|$/m.test(report));

  // Every task_id from COMPARISON_RUNS must appear
  for (const run of COMPARISON_RUNS) {
    ok(`(f) report mentions task_id "${run.task_id}"`, report.includes(run.task_id));
  }

  // Must contain the version string for traceability
  ok(`(f) report contains BENCHMARK_RESULTS_VERSION "${BENCHMARK_RESULTS_VERSION}"`,
     report.includes(BENCHMARK_RESULTS_VERSION));

  // No absolute filesystem paths baked in
  ok('(f) report has no hardcoded absolute paths',
     !/(?<!\w)(\/home\/|\/Users\/|C:\\)/.test(report));
}

// ---------------------------------------------------------------------------
// (g) formatBenchmarkReport — custom runs override (unit-tests isolation)
// ---------------------------------------------------------------------------
{
  // A single synthetic run — guided clearly better
  const singleRun = {
    knosky_protocol: '1.0',
    artifact_type: 'comparison-run',
    advisory: true,
    generated_at: '2026-01-01T00:00:00.000Z',
    task_id: 'test-t01',
    task_description: 'Synthetic test task',
    target_files: ['core/route.mjs'],
    naive:  { tokens_in: 1000, tokens_out: 100, tool_calls: 10, time_to_relevant_file_ms: 5000, correct: false },
    guided: { tokens_in:  400, tokens_out:  40, tool_calls:  4, time_to_relevant_file_ms: 1000, correct: true  },
  };

  const report = formatBenchmarkReport({ runs: [singleRun] });

  ok('(g) custom runs: returns a string', typeof report === 'string');
  ok('(g) custom runs: task_id appears in report', report.includes('test-t01'));

  // Token reduction: (1100 - 440) / 1100 = 660 / 1100 = 60%
  ok('(g) custom runs: TOKEN_REDUCTION correct (60%)', report.includes('60% fewer tokens'));

  // Tool-call reduction: (10 - 4) / 10 = 60%
  ok('(g) custom runs: TOOL_CALL_REDUCTION correct (60%)', report.includes('60% fewer tool calls'));

  // TTRF speedup: 5000 / 1000 = 5×
  ok('(g) custom runs: TTRF speedup correct (5×)', report.includes('5× faster to the right file'));
}

// ---------------------------------------------------------------------------
// (h) formatBenchmarkReport — null TTRF on one side is handled gracefully
// ---------------------------------------------------------------------------
{
  const runNullTTRF = {
    knosky_protocol: '1.0',
    artifact_type: 'comparison-run',
    advisory: true,
    generated_at: '2026-01-01T00:00:00.000Z',
    task_id: 'test-t02',
    task_description: 'Naive agent never found the file',
    target_files: ['core/ledger.mjs'],
    naive:  { tokens_in: 2000, tokens_out: 200, tool_calls: 15, time_to_relevant_file_ms: null, correct: false },
    guided: { tokens_in:  500, tokens_out:  50, tool_calls:  5, time_to_relevant_file_ms: 1200, correct: true  },
  };

  let threw = false;
  let report = '';
  try {
    report = formatBenchmarkReport({ runs: [runNullTTRF] });
  } catch (e) {
    threw = true;
  }

  ok('(h) null TTRF on naive side does not throw', threw === false);
  ok('(h) report is still a non-empty string', typeof report === 'string' && report.length > 0);
  // When no run has both sides non-null, the speedup is 0 and that row shows "—"
  ok('(h) table row shows "—" for null TTRF', report.includes('—'));
}

// ---------------------------------------------------------------------------
// (i) formatBenchmarkReport — empty runs array returns a string (no crash)
// ---------------------------------------------------------------------------
{
  let threw = false;
  let report = '';
  try {
    report = formatBenchmarkReport({ runs: [] });
  } catch (e) {
    threw = true;
  }
  ok('(i) empty runs array does not throw',           threw === false);
  ok('(i) empty-runs report is a non-empty string',   typeof report === 'string' && report.length > 0);
  ok('(i) empty-runs report still has an H2 heading', /^##\s+\S/m.test(report));
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
