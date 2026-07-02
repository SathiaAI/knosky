// KnoSky generic onboarding contract tests (SAT-463). Run: node test/onboarding.test.mjs
import {
  ONBOARDING_SCHEMA_VERSION,
  TOOL_DEFS,
  CONSTRAINTS,
  EXAMPLES,
  makeOnboardingDoc,
  validateOnboardingDoc,
  renderOnboardingText,
} from '../core/onboarding.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) Constant shapes
// ---------------------------------------------------------------------------
{
  ok('ONBOARDING_SCHEMA_VERSION is "1.0"', ONBOARDING_SCHEMA_VERSION === '1.0');
  ok('TOOL_DEFS is non-empty array', Array.isArray(TOOL_DEFS) && TOOL_DEFS.length > 0);
  ok('CONSTRAINTS is non-empty array', Array.isArray(CONSTRAINTS) && CONSTRAINTS.length > 0);
  ok('EXAMPLES is non-empty array', Array.isArray(EXAMPLES) && EXAMPLES.length > 0);
}

// Each tool def has the required fields
{
  for (let i = 0; i < TOOL_DEFS.length; i++) {
    const t = TOOL_DEFS[i];
    ok(`TOOL_DEFS[${i}] has name string`, typeof t.name === 'string' && t.name.length > 0);
    ok(`TOOL_DEFS[${i}] has description string`, typeof t.description === 'string' && t.description.length > 0);
    ok(`TOOL_DEFS[${i}] has params object`, t.params !== null && typeof t.params === 'object');
    ok(`TOOL_DEFS[${i}] has example string`, typeof t.example === 'string' && t.example.length > 0);
  }
}

// All six MCP tools are present
{
  const names = new Set(TOOL_DEFS.map(t => t.name));
  for (const expected of ['kc_search', 'kc_get_node', 'kc_list_categories', 'kc_get_provenance', 'kc_related', 'kc_route']) {
    ok(`TOOL_DEFS contains ${expected}`, names.has(expected));
  }
}

// ---------------------------------------------------------------------------
// (b) makeOnboardingDoc output passes validateOnboardingDoc
// ---------------------------------------------------------------------------
{
  const doc = makeOnboardingDoc();
  const result = validateOnboardingDoc(doc);
  ok('makeOnboardingDoc output is valid', result.ok === true, JSON.stringify(result.errors));
  ok('makeOnboardingDoc sets knosky_protocol "1.0"', doc.knosky_protocol === '1.0');
  ok('makeOnboardingDoc sets artifact_type "onboarding"', doc.artifact_type === 'onboarding');
  ok('makeOnboardingDoc sets advisory true', doc.advisory === true);
  ok('makeOnboardingDoc generated_at is ISO string', typeof doc.generated_at === 'string' && doc.generated_at.length > 0);
  ok('makeOnboardingDoc tools is non-empty array', Array.isArray(doc.tools) && doc.tools.length > 0);
  ok('makeOnboardingDoc constraints is array', Array.isArray(doc.constraints) && doc.constraints.length > 0);
  ok('makeOnboardingDoc examples is array', Array.isArray(doc.examples) && doc.examples.length > 0);
}

// makeOnboardingDoc accepts an explicit generatedAt
{
  const ts = '2026-07-02T00:00:00.000Z';
  const doc = makeOnboardingDoc({ generatedAt: ts });
  ok('makeOnboardingDoc uses provided generatedAt', doc.generated_at === ts);
}

// makeOnboardingDoc does not share the same tools/constraints/examples array references
{
  const doc1 = makeOnboardingDoc();
  const doc2 = makeOnboardingDoc();
  ok('makeOnboardingDoc tools arrays are distinct', doc1.tools !== TOOL_DEFS);
  ok('makeOnboardingDoc constraints arrays are distinct', doc1.constraints !== CONSTRAINTS);
  ok('makeOnboardingDoc examples arrays are distinct', doc1.examples !== EXAMPLES);
  ok('two calls produce independent docs', doc1.tools !== doc2.tools);
}

// ---------------------------------------------------------------------------
// (c) validateOnboardingDoc rejects bad envelopes
// ---------------------------------------------------------------------------

// wrong artifact_type
{
  const doc = { ...makeOnboardingDoc(), artifact_type: 'route' };
  const result = validateOnboardingDoc(doc);
  ok('wrong artifact_type fails validation', result.ok === false);
  ok('error mentions artifact_type', result.errors.some(e => e.includes('artifact_type')), JSON.stringify(result.errors));
}

// wrong protocol version
{
  const doc = { ...makeOnboardingDoc(), knosky_protocol: '0.9' };
  const result = validateOnboardingDoc(doc);
  ok('wrong knosky_protocol fails validation', result.ok === false);
  ok('error mentions knosky_protocol', result.errors.some(e => e.includes('knosky_protocol')), JSON.stringify(result.errors));
}

// advisory not true
{
  const doc = { ...makeOnboardingDoc(), advisory: false };
  const result = validateOnboardingDoc(doc);
  ok('advisory false fails validation', result.ok === false);
  ok('error mentions advisory', result.errors.some(e => e.includes('advisory')), JSON.stringify(result.errors));
}

// empty tools array
{
  const doc = { ...makeOnboardingDoc(), tools: [] };
  const result = validateOnboardingDoc(doc);
  ok('empty tools[] fails validation', result.ok === false);
  ok('error mentions tools', result.errors.some(e => e.includes('tools')), JSON.stringify(result.errors));
}

// tool missing name
{
  const doc = makeOnboardingDoc();
  doc.tools = [{ description: 'no name here', params: {}, example: 'x()' }];
  const result = validateOnboardingDoc(doc);
  ok('tool missing name fails validation', result.ok === false, JSON.stringify(result.errors));
  ok('error mentions tools[0].name', result.errors.some(e => e.includes('tools[0].name')), JSON.stringify(result.errors));
}

// constraints not an array
{
  const doc = { ...makeOnboardingDoc(), constraints: 'a string' };
  const result = validateOnboardingDoc(doc);
  ok('constraints not array fails validation', result.ok === false);
  ok('error mentions constraints', result.errors.some(e => e.includes('constraints')), JSON.stringify(result.errors));
}

// examples not an array
{
  const doc = { ...makeOnboardingDoc(), examples: null };
  const result = validateOnboardingDoc(doc);
  ok('examples null fails validation', result.ok === false);
  ok('error mentions examples', result.errors.some(e => e.includes('examples')), JSON.stringify(result.errors));
}

// non-object input
{
  const result = validateOnboardingDoc(null);
  ok('null doc fails validation', result.ok === false);
  ok('null produces "not an object" error', result.errors.some(e => e.includes('not an object')), JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (d) renderOnboardingText — plain text shape checks
// ---------------------------------------------------------------------------
{
  const doc = makeOnboardingDoc();
  const text = renderOnboardingText(doc);
  ok('renderOnboardingText returns a string', typeof text === 'string');
  ok('rendered text contains "KnoSky"', text.includes('KnoSky'));
  ok('rendered text contains "Available tools"', text.includes('Available tools'));
  ok('rendered text contains "Rules"', text.includes('Rules'));
  ok('rendered text contains "Starter prompts"', text.includes('Starter prompts'));

  // Every tool name appears in the rendered output
  for (const t of doc.tools) {
    ok(`rendered text contains tool "${t.name}"`, text.includes(t.name));
  }

  // At least one constraint appears
  ok('rendered text contains first constraint', text.includes(doc.constraints[0]));

  // At least one example appears
  ok('rendered text contains first example', text.includes(doc.examples[0]));
}

// renderOnboardingText with an empty constraints / examples list still runs
{
  const doc = makeOnboardingDoc();
  doc.constraints = [];
  doc.examples = [];
  let threw = false;
  let out = '';
  try { out = renderOnboardingText(doc); } catch { threw = true; }
  ok('renderOnboardingText with empty constraints/examples does not throw', !threw);
  ok('renderOnboardingText with empty arrays returns string', typeof out === 'string');
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
