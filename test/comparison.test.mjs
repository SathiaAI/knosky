// KnoSky comparison-protocol tests (SAT-458). Run: node test/comparison.test.mjs
import {
  COMPARISON_ARTIFACT_TYPE,
  makeComparisonRun,
  validateComparisonRun,
} from '../core/comparison.mjs';
import { PROTOCOL_VERSION } from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const MINIMAL = {
  task_id: 'task-001',
  task_description: 'Locate the authentication module',
  target_files: ['src/auth.js'],
  naive: {
    tokens_in: 4000,
    tokens_out: 500,
    tool_calls: 12,
    time_to_relevant_file_ms: 8200,
    correct: false,
  },
  guided: {
    tokens_in: 1800,
    tokens_out: 220,
    tool_calls: 4,
    time_to_relevant_file_ms: 1100,
    correct: true,
  },
};

// ---------------------------------------------------------------------------
// (a) makeComparisonRun output passes validateComparisonRun
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun(MINIMAL);
  const result = validateComparisonRun(doc);
  ok('(a) makeComparisonRun output is valid', result.ok === true, JSON.stringify(result.errors));
  ok('(a) knosky_protocol set correctly', doc.knosky_protocol === PROTOCOL_VERSION);
  ok('(a) artifact_type set correctly', doc.artifact_type === COMPARISON_ARTIFACT_TYPE);
  ok('(a) advisory is true', doc.advisory === true);
  ok('(a) generated_at is ISO string', typeof doc.generated_at === 'string' && doc.generated_at.length > 0);
  ok('(a) task_id round-trips', doc.task_id === MINIMAL.task_id);
  ok('(a) task_description round-trips', doc.task_description === MINIMAL.task_description);
  ok('(a) target_files round-trips', JSON.stringify(doc.target_files) === JSON.stringify(MINIMAL.target_files));
}

// ---------------------------------------------------------------------------
// (b) naive and guided sides are stored verbatim
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun(MINIMAL);
  for (const side of ['naive', 'guided']) {
    const s = doc[side];
    const m = MINIMAL[side];
    ok(`(b) ${side}.tokens_in stored`, s.tokens_in === m.tokens_in);
    ok(`(b) ${side}.tokens_out stored`, s.tokens_out === m.tokens_out);
    ok(`(b) ${side}.tool_calls stored`, s.tool_calls === m.tool_calls);
    ok(`(b) ${side}.time_to_relevant_file_ms stored`, s.time_to_relevant_file_ms === m.time_to_relevant_file_ms);
    ok(`(b) ${side}.correct stored`, s.correct === m.correct);
  }
}

// ---------------------------------------------------------------------------
// (c) null time_to_relevant_file_ms is valid (agent never found the file)
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({
    ...MINIMAL,
    naive: { ...MINIMAL.naive, time_to_relevant_file_ms: null },
  });
  const result = validateComparisonRun(doc);
  ok('(c) null time_to_relevant_file_ms passes validation', result.ok === true, JSON.stringify(result.errors));
  ok('(c) null value round-trips', doc.naive.time_to_relevant_file_ms === null);
}

// ---------------------------------------------------------------------------
// (d) missing task_id fails
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({ ...MINIMAL, task_id: '' });
  const result = validateComparisonRun(doc);
  ok('(d) empty task_id fails', result.ok === false, JSON.stringify(result.errors));
  ok('(d) error mentions task_id', result.errors.some(e => e.includes('task_id')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (e) empty target_files fails
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({ ...MINIMAL, target_files: [] });
  const result = validateComparisonRun(doc);
  ok('(e) empty target_files fails', result.ok === false, JSON.stringify(result.errors));
  ok('(e) error mentions target_files', result.errors.some(e => e.includes('target_files')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (f) absolute path in target_files fails
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({ ...MINIMAL, target_files: ['/etc/passwd'] });
  const result = validateComparisonRun(doc);
  ok('(f) absolute path in target_files fails', result.ok === false, JSON.stringify(result.errors));
  ok('(f) error mentions target_files[0]', result.errors.some(e => e.includes('target_files[0]')), JSON.stringify(result.errors));
}

// (f cont.) ".." in target_files also fails
{
  const doc = makeComparisonRun({ ...MINIMAL, target_files: ['../secrets/key.pem'] });
  const result = validateComparisonRun(doc);
  ok('(f) ".." in target_files fails', result.ok === false, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (g) negative tokens_in fails
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({
    ...MINIMAL,
    naive: { ...MINIMAL.naive, tokens_in: -1 },
  });
  const result = validateComparisonRun(doc);
  ok('(g) negative tokens_in fails', result.ok === false, JSON.stringify(result.errors));
  ok('(g) error mentions naive.tokens_in', result.errors.some(e => e.includes('naive.tokens_in')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (h) non-boolean correct fails
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({
    ...MINIMAL,
    guided: { ...MINIMAL.guided, correct: 'yes' },
  });
  const result = validateComparisonRun(doc);
  ok('(h) non-boolean correct fails', result.ok === false, JSON.stringify(result.errors));
  ok('(h) error mentions guided.correct', result.errors.some(e => e.includes('guided.correct')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (i) wrong artifact_type fails
// ---------------------------------------------------------------------------
{
  const doc = { ...makeComparisonRun(MINIMAL), artifact_type: 'route' };
  const result = validateComparisonRun(doc);
  ok('(i) wrong artifact_type fails', result.ok === false, JSON.stringify(result.errors));
  ok('(i) error mentions artifact_type', result.errors.some(e => e.includes('artifact_type')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (j) multiple target_files are accepted
// ---------------------------------------------------------------------------
{
  const doc = makeComparisonRun({
    ...MINIMAL,
    target_files: ['src/auth.js', 'test/auth.test.js', 'docs/auth.md'],
  });
  const result = validateComparisonRun(doc);
  ok('(j) multiple target_files passes validation', result.ok === true, JSON.stringify(result.errors));
  ok('(j) all three files stored', doc.target_files.length === 3);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
