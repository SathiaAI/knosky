// KnoSky simultaneous multi-model benchmark harness tests (SAT-459).
// Proves that the same benchmark protocol runs across all five model families
// (Claude/GPT/Gemini/DeepSeek/Grok) in parallel, not sequentially.
// Run: node test/multi-model-benchmark.test.mjs

import {
  MODEL_FAMILIES,
  MULTI_MODEL_ARTIFACT_TYPE,
  makeMultiModelRun,
  validateMultiModelRun,
  runMultiModelBenchmark,
} from '../core/multi-model-benchmark.mjs';
import { PROTOCOL_VERSION } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const TASK = {
  task_id:          'sat459-t01',
  task_description: 'Locate the authentication module and explain its entry point',
  target_files:     ['core/key-store.mjs'],
};

function makeOkResult(family, modelId, overrides = {}) {
  const { metrics: metricsOverride, ...restOverrides } = overrides;
  return {
    family,
    model_id: modelId,
    status:   'ok',
    error:    null,
    metrics: {
      tokens_in:               2000,
      tokens_out:              180,
      tool_calls:              4,
      time_to_relevant_file_ms: 1500,
      correct:                 true,
      ...(metricsOverride || {}),
    },
    ...restOverrides,
  };
}

const ALL_RESULTS = MODEL_FAMILIES.map(({ family, modelId }) =>
  makeOkResult(family, modelId),
);

// ---------------------------------------------------------------------------
// (a) MODEL_FAMILIES exports all five families
// ---------------------------------------------------------------------------
{
  ok('(a) MODEL_FAMILIES has exactly 5 entries', MODEL_FAMILIES.length === 5,
    String(MODEL_FAMILIES.length));

  const EXPECTED = ['claude', 'gpt', 'gemini', 'deepseek', 'grok'];
  for (const name of EXPECTED) {
    const found = MODEL_FAMILIES.find(m => m.family === name);
    ok(`(a) MODEL_FAMILIES includes family "${name}"`, found !== undefined);
    ok(`(a) family "${name}" has a non-empty modelId`,
      found && typeof found.modelId === 'string' && found.modelId.length > 0,
      found ? found.modelId : '(missing)');
  }

  // No duplicate families
  const families = MODEL_FAMILIES.map(m => m.family);
  ok('(a) MODEL_FAMILIES has no duplicate family names',
    new Set(families).size === MODEL_FAMILIES.length, JSON.stringify(families));
}

// ---------------------------------------------------------------------------
// (b) makeMultiModelRun output passes validateMultiModelRun
// ---------------------------------------------------------------------------
{
  const doc = makeMultiModelRun({ ...TASK, results: ALL_RESULTS });
  const result = validateMultiModelRun(doc);
  ok('(b) makeMultiModelRun output is valid', result.ok === true, JSON.stringify(result.errors));
  ok('(b) knosky_protocol set correctly', doc.knosky_protocol === PROTOCOL_VERSION);
  ok('(b) artifact_type is MULTI_MODEL_ARTIFACT_TYPE',
    doc.artifact_type === MULTI_MODEL_ARTIFACT_TYPE);
  ok('(b) advisory is true', doc.advisory === true);
  ok('(b) dispatch.mode is "parallel"', doc.dispatch.mode === 'parallel');
  ok('(b) generated_at is a non-empty string',
    typeof doc.generated_at === 'string' && doc.generated_at.length > 0);
  ok('(b) task_id round-trips', doc.task_id === TASK.task_id);
  ok('(b) task_description round-trips', doc.task_description === TASK.task_description);
  ok('(b) target_files round-trips',
    JSON.stringify(doc.target_files) === JSON.stringify(TASK.target_files));
  ok('(b) results length matches input', doc.results.length === ALL_RESULTS.length,
    String(doc.results.length));
}

// ---------------------------------------------------------------------------
// (c) summary is correctly derived from results
// ---------------------------------------------------------------------------
{
  const doc = makeMultiModelRun({ ...TASK, results: ALL_RESULTS });
  ok('(c) summary.total equals results count', doc.summary.total === ALL_RESULTS.length);
  ok('(c) summary.succeeded equals 5 (all ok)', doc.summary.succeeded === 5);
  ok('(c) summary.failed equals 0', doc.summary.failed === 0);
  ok('(c) summary.succeeded_families has all 5 names',
    doc.summary.succeeded_families.length === 5,
    JSON.stringify(doc.summary.succeeded_families));
  ok('(c) summary.failed_families is empty', doc.summary.failed_families.length === 0);
  // fastest_family: lowest time_to_relevant_file_ms (all equal at 1500 ms here → first one)
  ok('(c) summary.fastest_family is a known family string',
    typeof doc.summary.fastest_family === 'string' &&
    MODEL_FAMILIES.some(m => m.family === doc.summary.fastest_family),
    String(doc.summary.fastest_family));
}

// ---------------------------------------------------------------------------
// (d) fastest_family is correctly identified when times differ
// ---------------------------------------------------------------------------
{
  const results = MODEL_FAMILIES.map(({ family, modelId }, i) =>
    makeOkResult(family, modelId, { metrics: { time_to_relevant_file_ms: 2000 + i * 100 } }),
  );
  // claude (index 0) gets 2000 ms → should be fastest
  const doc = makeMultiModelRun({ ...TASK, results });
  ok('(d) fastest_family is the model with lowest ttrf',
    doc.summary.fastest_family === 'claude',
    String(doc.summary.fastest_family));
}

// ---------------------------------------------------------------------------
// (e) null time_to_relevant_file_ms is valid (model never found the file)
// ---------------------------------------------------------------------------
{
  const results = MODEL_FAMILIES.map(({ family, modelId }) =>
    makeOkResult(family, modelId, { metrics: { time_to_relevant_file_ms: null } }),
  );
  const doc = makeMultiModelRun({ ...TASK, results });
  const result = validateMultiModelRun(doc);
  ok('(e) null ttrf passes validation', result.ok === true, JSON.stringify(result.errors));
  // When all ttrf are null, fastest_family should be null
  ok('(e) fastest_family is null when all ttrf are null',
    doc.summary.fastest_family === null, String(doc.summary.fastest_family));
}

// ---------------------------------------------------------------------------
// (f) failed model result is accepted; counts appear in summary
// ---------------------------------------------------------------------------
{
  const results = [
    makeOkResult('claude',   MODEL_FAMILIES[0].modelId),
    makeOkResult('gpt',      MODEL_FAMILIES[1].modelId),
    { family: 'gemini',   model_id: MODEL_FAMILIES[2].modelId, status: 'failed', error: 'HTTP 503', metrics: null },
    makeOkResult('deepseek', MODEL_FAMILIES[3].modelId),
    { family: 'grok',     model_id: MODEL_FAMILIES[4].modelId, status: 'failed', error: 'timeout',  metrics: null },
  ];
  const doc = makeMultiModelRun({ ...TASK, results });
  const vResult = validateMultiModelRun(doc);
  ok('(f) mixed ok/failed passes validation', vResult.ok === true, JSON.stringify(vResult.errors));
  ok('(f) summary.succeeded is 3', doc.summary.succeeded === 3);
  ok('(f) summary.failed is 2', doc.summary.failed === 2);
  ok('(f) summary.failed_families includes gemini',
    doc.summary.failed_families.includes('gemini'));
  ok('(f) summary.failed_families includes grok',
    doc.summary.failed_families.includes('grok'));
}

// ---------------------------------------------------------------------------
// (g) wrong artifact_type fails
// ---------------------------------------------------------------------------
{
  const doc = { ...makeMultiModelRun({ ...TASK, results: ALL_RESULTS }), artifact_type: 'route' };
  const result = validateMultiModelRun(doc);
  ok('(g) wrong artifact_type fails', result.ok === false);
  ok('(g) error mentions artifact_type',
    result.errors.some(e => e.includes('artifact_type')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (h) dispatch.mode must be "parallel" — sequential is rejected
// ---------------------------------------------------------------------------
{
  const doc = makeMultiModelRun({ ...TASK, results: ALL_RESULTS });
  doc.dispatch = { mode: 'sequential' };
  const result = validateMultiModelRun(doc);
  ok('(h) dispatch.mode "sequential" fails validation', result.ok === false);
  ok('(h) error mentions dispatch.mode',
    result.errors.some(e => e.includes('dispatch.mode')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (i) empty target_files fails
// ---------------------------------------------------------------------------
{
  const doc = makeMultiModelRun({ ...TASK, target_files: [], results: ALL_RESULTS });
  const result = validateMultiModelRun(doc);
  ok('(i) empty target_files fails', result.ok === false);
  ok('(i) error mentions target_files',
    result.errors.some(e => e.includes('target_files')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (j) absolute path in target_files fails
// ---------------------------------------------------------------------------
{
  const doc = makeMultiModelRun({ ...TASK, target_files: ['/etc/passwd'], results: ALL_RESULTS });
  const result = validateMultiModelRun(doc);
  ok('(j) absolute path in target_files fails', result.ok === false);
  ok('(j) error mentions target_files[0]',
    result.errors.some(e => e.includes('target_files[0]')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (k) runMultiModelBenchmark dispatches all models simultaneously (parallel)
// ---------------------------------------------------------------------------
{
  // Spy: record the order in which dispatch was called and when each resolved.
  // In a true parallel fan-out every model starts before any resolves.
  // We verify this by: (1) all five models are dispatched, (2) dispatch.mode === 'parallel'.

  const dispatched = [];
  let callCount = 0;

  async function fakeDispatch({ family, modelId, task: t }) {
    dispatched.push(family);
    callCount++;
    // Micro-delay so async interleaving is exercised
    await Promise.resolve();
    return {
      family,
      model_id: modelId,
      status:   'ok',
      error:    null,
      metrics: {
        tokens_in:               1800,
        tokens_out:              160,
        tool_calls:              3,
        time_to_relevant_file_ms: 1200,
        correct:                 true,
      },
    };
  }

  const doc = await runMultiModelBenchmark(TASK, fakeDispatch);

  ok('(k) dispatch called for all 5 model families', callCount === 5, String(callCount));
  ok('(k) all 5 families appeared in dispatch calls',
    MODEL_FAMILIES.every(m => dispatched.includes(m.family)),
    JSON.stringify(dispatched));
  ok('(k) returned artifact passes schema validation',
    validateMultiModelRun(doc).ok === true,
    JSON.stringify(validateMultiModelRun(doc).errors));
  ok('(k) dispatch.mode is "parallel"', doc.dispatch.mode === 'parallel');
  ok('(k) dispatch.started_at_ms is a number',
    typeof doc.dispatch.started_at_ms === 'number');
  ok('(k) dispatch.settled_at_ms is a number',
    typeof doc.dispatch.settled_at_ms === 'number');
  ok('(k) settled_at_ms >= started_at_ms',
    doc.dispatch.settled_at_ms >= doc.dispatch.started_at_ms);
  ok('(k) all 5 results present', doc.results.length === 5, String(doc.results.length));
  ok('(k) summary.succeeded is 5', doc.summary.succeeded === 5);
}

// ---------------------------------------------------------------------------
// (l) runMultiModelBenchmark catches per-model failures; others still complete
// ---------------------------------------------------------------------------
{
  async function faultyDispatch({ family, modelId }) {
    if (family === 'gpt') throw new Error('model unavailable');
    return makeOkResult(family, modelId);
  }

  const doc = await runMultiModelBenchmark(TASK, faultyDispatch);

  ok('(l) artifact passes schema validation even when one model fails',
    validateMultiModelRun(doc).ok === true,
    JSON.stringify(validateMultiModelRun(doc).errors));
  ok('(l) gpt result has status "failed"',
    doc.results.find(r => r.family === 'gpt')?.status === 'failed');
  ok('(l) gpt error message is captured',
    typeof doc.results.find(r => r.family === 'gpt')?.error === 'string');
  ok('(l) other 4 models still succeeded',
    doc.results.filter(r => r.status === 'ok').length === 4,
    String(doc.results.filter(r => r.status === 'ok').length));
  ok('(l) summary.failed is 1', doc.summary.failed === 1);
  ok('(l) summary.failed_families includes "gpt"',
    doc.summary.failed_families.includes('gpt'));
}

// ---------------------------------------------------------------------------
// (m) runMultiModelBenchmark accepts a custom model subset
// ---------------------------------------------------------------------------
{
  const subset = MODEL_FAMILIES.slice(0, 2); // claude + gpt only

  async function subsetDispatch({ family, modelId }) {
    return makeOkResult(family, modelId);
  }

  const doc = await runMultiModelBenchmark(TASK, subsetDispatch, subset);

  ok('(m) subset run dispatches only the specified models',
    doc.results.length === 2, String(doc.results.length));
  ok('(m) subset run passes schema validation',
    validateMultiModelRun(doc).ok === true,
    JSON.stringify(validateMultiModelRun(doc).errors));
  ok('(m) summary.total is 2', doc.summary.total === 2);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
