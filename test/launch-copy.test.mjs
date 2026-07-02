// KnoSky launch-copy regression test (SAT-469).
// Locks README.md benchmark claims to the measured SAT-439 results stored in
// core/benchmark-results.mjs.  Any change to raw runs flows through the
// module's derived constants — edit runs there, not here.
// Run: node test/launch-copy.test.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  TOKEN_REDUCTION_PCT,
  TOOL_CALL_REDUCTION_PCT,
  TTRF_SPEEDUP_X,
  HEADLINE_CLAIM,
  COMPARISON_RUNS,
  TOTAL_TOKENS,
  TOTAL_TOOL_CALLS,
  BENCHMARK_RESULTS_VERSION,
} from '../core/benchmark-results.mjs';

import { validateComparisonRun } from '../core/comparison.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// ---------------------------------------------------------------------------
// (a) Module invariants — constants are self-consistent and well-formed
// ---------------------------------------------------------------------------
{
  ok('(a) BENCHMARK_RESULTS_VERSION is "1.0"', BENCHMARK_RESULTS_VERSION === '1.0');
  ok('(a) COMPARISON_RUNS is a non-empty array', Array.isArray(COMPARISON_RUNS) && COMPARISON_RUNS.length > 0);

  // Each run must pass the comparison-run schema validator
  for (let i = 0; i < COMPARISON_RUNS.length; i++) {
    const result = validateComparisonRun(COMPARISON_RUNS[i]);
    ok(`(a) COMPARISON_RUNS[${i}] passes schema validation`, result.ok === true,
       result.ok ? '' : JSON.stringify(result.errors));
  }

  // Derived totals are consistent with COMPARISON_RUNS
  const expectedNaiveTok  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tokens_in  + r.naive.tokens_out,  0);
  const expectedGuidedTok = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tokens_in + r.guided.tokens_out, 0);
  ok('(a) TOTAL_TOKENS.naive matches run sum',   TOTAL_TOKENS.naive  === expectedNaiveTok);
  ok('(a) TOTAL_TOKENS.guided matches run sum',  TOTAL_TOKENS.guided === expectedGuidedTok);

  const expectedNaiveCalls  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tool_calls,  0);
  const expectedGuidedCalls = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tool_calls, 0);
  ok('(a) TOTAL_TOOL_CALLS.naive matches run sum',   TOTAL_TOOL_CALLS.naive  === expectedNaiveCalls);
  ok('(a) TOTAL_TOOL_CALLS.guided matches run sum',  TOTAL_TOOL_CALLS.guided === expectedGuidedCalls);
}

// ---------------------------------------------------------------------------
// (b) Derived summary constants match re-derivation from raw runs
// ---------------------------------------------------------------------------
{
  const reNaiveTok  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tokens_in  + r.naive.tokens_out,  0);
  const reGuidedTok = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tokens_in + r.guided.tokens_out, 0);
  const expectedTokenPct = Math.round(100 * (reNaiveTok - reGuidedTok) / reNaiveTok);
  ok('(b) TOKEN_REDUCTION_PCT is correct', TOKEN_REDUCTION_PCT === expectedTokenPct,
     `expected ${expectedTokenPct}, got ${TOKEN_REDUCTION_PCT}`);

  const reNaiveCalls  = COMPARISON_RUNS.reduce((s, r) => s + r.naive.tool_calls,  0);
  const reGuidedCalls = COMPARISON_RUNS.reduce((s, r) => s + r.guided.tool_calls, 0);
  const expectedCallPct = Math.round(100 * (reNaiveCalls - reGuidedCalls) / reNaiveCalls);
  ok('(b) TOOL_CALL_REDUCTION_PCT is correct', TOOL_CALL_REDUCTION_PCT === expectedCallPct,
     `expected ${expectedCallPct}, got ${TOOL_CALL_REDUCTION_PCT}`);

  const both = COMPARISON_RUNS.filter(
    r => r.naive.time_to_relevant_file_ms !== null &&
         r.guided.time_to_relevant_file_ms !== null,
  );
  const naiveMean  = both.reduce((s, r) => s + r.naive.time_to_relevant_file_ms,  0) / both.length;
  const guidedMean = both.reduce((s, r) => s + r.guided.time_to_relevant_file_ms, 0) / both.length;
  const expectedSpeedup = Math.round(10 * naiveMean / guidedMean) / 10;
  ok('(b) TTRF_SPEEDUP_X is correct', TTRF_SPEEDUP_X === expectedSpeedup,
     `expected ${expectedSpeedup}, got ${TTRF_SPEEDUP_X}`);

  // Sanity: guided is better on every axis
  ok('(b) TOKEN_REDUCTION_PCT > 0 (guided uses fewer tokens)',   TOKEN_REDUCTION_PCT   > 0);
  ok('(b) TOOL_CALL_REDUCTION_PCT > 0 (guided fewer tool calls)', TOOL_CALL_REDUCTION_PCT > 0);
  ok('(b) TTRF_SPEEDUP_X > 1 (guided reaches file faster)',       TTRF_SPEEDUP_X > 1);
}

// ---------------------------------------------------------------------------
// (c) HEADLINE_CLAIM is built from the derived constants
// ---------------------------------------------------------------------------
{
  const speedupStr = Number.isInteger(TTRF_SPEEDUP_X)
    ? String(TTRF_SPEEDUP_X)
    : TTRF_SPEEDUP_X.toFixed(1);
  const expected =
    `${TOKEN_REDUCTION_PCT}% fewer tokens, ` +
    `${TOOL_CALL_REDUCTION_PCT}% fewer tool calls, ` +
    `${speedupStr}× faster to the right file`;
  ok('(c) HEADLINE_CLAIM matches derived components', HEADLINE_CLAIM === expected,
     `expected: "${expected}", got: "${HEADLINE_CLAIM}"`);
}

// ---------------------------------------------------------------------------
// (d) README.md contains the benchmark claims
// ---------------------------------------------------------------------------
{
  const readme = read('README.md');

  // The three headline numbers must appear verbatim
  ok(`(d) README contains "${TOKEN_REDUCTION_PCT}% fewer tokens"`,
     readme.includes(`${TOKEN_REDUCTION_PCT}% fewer tokens`));
  ok(`(d) README contains "${TOOL_CALL_REDUCTION_PCT}% fewer tool calls"`,
     readme.includes(`${TOOL_CALL_REDUCTION_PCT}% fewer tool calls`));

  const speedupStr = Number.isInteger(TTRF_SPEEDUP_X)
    ? String(TTRF_SPEEDUP_X)
    : TTRF_SPEEDUP_X.toFixed(1);
  ok(`(d) README contains "${speedupStr}× faster to the right file"`,
     readme.includes(`${speedupStr}× faster to the right file`));

  // SAT-439 provenance label must be present
  ok('(d) README mentions SAT-439 provenance', readme.includes('SAT-439'));

  // The claims must appear before the first H2 section that follows "The problem"
  // i.e., they sit in the "What you get" section (numbers-first requirement)
  const whatYouGetIdx = readme.indexOf('## What you get');
  const whoItsForIdx  = readme.indexOf('## Who it');
  ok('(d) benchmark numbers appear in "What you get" section',
     whatYouGetIdx !== -1 &&
     readme.indexOf(`${TOKEN_REDUCTION_PCT}% fewer tokens`) > whatYouGetIdx &&
     readme.indexOf(`${TOKEN_REDUCTION_PCT}% fewer tokens`) < whoItsForIdx,
     `whatYouGetIdx=${whatYouGetIdx}, whoItsForIdx=${whoItsForIdx}`);
}

// ---------------------------------------------------------------------------
// (e) all guided runs answered correctly; correctness accounting
// ---------------------------------------------------------------------------
{
  const allGuidedCorrect = COMPARISON_RUNS.every(r => r.guided.correct === true);
  ok('(e) all guided runs answered correctly', allGuidedCorrect);

  const naiveCorrect = COMPARISON_RUNS.filter(r => r.naive.correct === true).length;
  ok('(e) no naive runs answered correctly (0/5)', naiveCorrect === 0,
     `naive correct count: ${naiveCorrect}`);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
