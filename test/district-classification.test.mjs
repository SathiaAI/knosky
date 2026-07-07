// District classification model tests (SAT-505 / KS2-F1-2).
// Run: node test/district-classification.test.mjs
import {
  CLASS_PUBLIC,
  CLASS_INTERNAL,
  CLASS_RESTRICTED,
  CLASS_CONFIDENTIAL,
  CLASS_BLOCKED,
  CLASSES,
  DEFAULT_CLASS,
  isValidClass,
  validateClass,
  loadClass,
} from '../core/district-classification.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) Constants — all five levels are defined and distinct strings
// ---------------------------------------------------------------------------
ok('(a) CLASS_PUBLIC is a string',       typeof CLASS_PUBLIC       === 'string');
ok('(a) CLASS_INTERNAL is a string',     typeof CLASS_INTERNAL     === 'string');
ok('(a) CLASS_RESTRICTED is a string',   typeof CLASS_RESTRICTED   === 'string');
ok('(a) CLASS_CONFIDENTIAL is a string', typeof CLASS_CONFIDENTIAL === 'string');
ok('(a) CLASS_BLOCKED is a string',      typeof CLASS_BLOCKED      === 'string');
ok('(a) all five levels are distinct',
   new Set([CLASS_PUBLIC, CLASS_INTERNAL, CLASS_RESTRICTED, CLASS_CONFIDENTIAL, CLASS_BLOCKED]).size === 5);

// ---------------------------------------------------------------------------
// (b) CLASSES array contains exactly the five levels in least→most order
// ---------------------------------------------------------------------------
ok('(b) CLASSES has exactly 5 entries', CLASSES.length === 5);
ok('(b) CLASSES[0] is public',       CLASSES[0] === CLASS_PUBLIC);
ok('(b) CLASSES[1] is internal',     CLASSES[1] === CLASS_INTERNAL);
ok('(b) CLASSES[2] is restricted',   CLASSES[2] === CLASS_RESTRICTED);
ok('(b) CLASSES[3] is confidential', CLASSES[3] === CLASS_CONFIDENTIAL);
ok('(b) CLASSES[4] is blocked',      CLASSES[4] === CLASS_BLOCKED);
ok('(b) CLASSES is frozen (immutable)', Object.isFrozen(CLASSES));

// ---------------------------------------------------------------------------
// (c) DEFAULT_CLASS is the most-restrictive level
// ---------------------------------------------------------------------------
ok('(c) DEFAULT_CLASS === CLASS_BLOCKED', DEFAULT_CLASS === CLASS_BLOCKED);
ok('(c) DEFAULT_CLASS is in CLASSES',     CLASSES.includes(DEFAULT_CLASS));

// ---------------------------------------------------------------------------
// (d) isValidClass — accepts each known class, rejects unknowns / bad types
// ---------------------------------------------------------------------------
for (const cls of CLASSES) {
  ok(`(d) isValidClass("${cls}") === true`, isValidClass(cls) === true);
}
ok('(d) isValidClass("unknown") === false',    isValidClass('unknown') === false);
ok('(d) isValidClass("") === false',           isValidClass('') === false);
ok('(d) isValidClass(null) === false',         isValidClass(null) === false);
ok('(d) isValidClass(undefined) === false',    isValidClass(undefined) === false);
ok('(d) isValidClass(0) === false',            isValidClass(0) === false);
ok('(d) isValidClass(true) === false',         isValidClass(true) === false);
ok('(d) isValidClass("PUBLIC") === false',     isValidClass('PUBLIC') === false); // case-sensitive

// ---------------------------------------------------------------------------
// (e) validateClass — ok:true per valid class
// ---------------------------------------------------------------------------
{
  const r = validateClass(CLASS_PUBLIC);
  ok('(e) validateClass(public) ok:true', r.ok === true);
  ok('(e) validateClass(public) no error field', r.error === undefined);
}
{
  const r = validateClass(CLASS_INTERNAL);
  ok('(e) validateClass(internal) ok:true', r.ok === true);
}
{
  const r = validateClass(CLASS_RESTRICTED);
  ok('(e) validateClass(restricted) ok:true', r.ok === true);
}
{
  const r = validateClass(CLASS_CONFIDENTIAL);
  ok('(e) validateClass(confidential) ok:true', r.ok === true);
}
{
  const r = validateClass(CLASS_BLOCKED);
  ok('(e) validateClass(blocked) ok:true', r.ok === true);
}

// ---------------------------------------------------------------------------
// (f) validateClass — ok:false for unknowns, error message includes allowed list
// ---------------------------------------------------------------------------
{
  const r = validateClass('secret');
  ok('(f) validateClass("secret") ok:false', r.ok === false);
  ok('(f) validateClass("secret") has error string', typeof r.error === 'string' && r.error.length > 0);
  ok('(f) error mentions the input value', r.error.includes('secret'));
}
{
  const r = validateClass(null);
  ok('(f) validateClass(null) ok:false', r.ok === false);
  ok('(f) validateClass(null) has error string', typeof r.error === 'string');
}
{
  const r = validateClass(undefined);
  ok('(f) validateClass(undefined) ok:false', r.ok === false);
}

// ---------------------------------------------------------------------------
// (g) loadClass — per-class: node with known district_class resolves correctly
// ---------------------------------------------------------------------------
ok('(g) loadClass({district_class:"public"}) → public',
   loadClass({ district_class: CLASS_PUBLIC }) === CLASS_PUBLIC);
ok('(g) loadClass({district_class:"internal"}) → internal',
   loadClass({ district_class: CLASS_INTERNAL }) === CLASS_INTERNAL);
ok('(g) loadClass({district_class:"restricted"}) → restricted',
   loadClass({ district_class: CLASS_RESTRICTED }) === CLASS_RESTRICTED);
ok('(g) loadClass({district_class:"confidential"}) → confidential',
   loadClass({ district_class: CLASS_CONFIDENTIAL }) === CLASS_CONFIDENTIAL);
ok('(g) loadClass({district_class:"blocked"}) → blocked',
   loadClass({ district_class: CLASS_BLOCKED }) === CLASS_BLOCKED);

// ---------------------------------------------------------------------------
// (h) loadClass — unknown / absent values → DEFAULT_CLASS (fail-closed)
// ---------------------------------------------------------------------------
ok('(h) loadClass({district_class:"mystery"}) → DEFAULT_CLASS',
   loadClass({ district_class: 'mystery' }) === DEFAULT_CLASS);
ok('(h) loadClass({district_class:null}) → DEFAULT_CLASS',
   loadClass({ district_class: null }) === DEFAULT_CLASS);
ok('(h) loadClass({district_class:undefined}) → DEFAULT_CLASS',
   loadClass({ district_class: undefined }) === DEFAULT_CLASS);
ok('(h) loadClass({}) → DEFAULT_CLASS (field absent)',
   loadClass({}) === DEFAULT_CLASS);
ok('(h) loadClass({district_class:0}) → DEFAULT_CLASS (wrong type)',
   loadClass({ district_class: 0 }) === DEFAULT_CLASS);
ok('(h) loadClass({district_class:""}) → DEFAULT_CLASS (empty string)',
   loadClass({ district_class: '' }) === DEFAULT_CLASS);
ok('(h) loadClass({district_class:"BLOCKED"}) → DEFAULT_CLASS (wrong case)',
   loadClass({ district_class: 'BLOCKED' }) === DEFAULT_CLASS);

// ---------------------------------------------------------------------------
// (i) loadClass — always returns a value from CLASSES
// ---------------------------------------------------------------------------
const probes = [
  { district_class: CLASS_PUBLIC },
  { district_class: CLASS_INTERNAL },
  { district_class: CLASS_RESTRICTED },
  { district_class: CLASS_CONFIDENTIAL },
  { district_class: CLASS_BLOCKED },
  { district_class: 'unknown' },
  {},
  { district_class: null },
];
for (const node of probes) {
  const cls = loadClass(node);
  ok(`(i) loadClass always returns a CLASSES member (input=${JSON.stringify(node.district_class ?? '(absent)')})`,
     CLASSES.includes(cls),
     `got: ${JSON.stringify(cls)}`);
}

// ---------------------------------------------------------------------------
// (j) loadClass — edge: non-object inputs gracefully return DEFAULT_CLASS
// ---------------------------------------------------------------------------
ok('(j) loadClass(null) → DEFAULT_CLASS',      loadClass(null)      === DEFAULT_CLASS);
ok('(j) loadClass(undefined) → DEFAULT_CLASS', loadClass(undefined) === DEFAULT_CLASS);
ok('(j) loadClass("string") → DEFAULT_CLASS',  loadClass('string')  === DEFAULT_CLASS);
ok('(j) loadClass(42) → DEFAULT_CLASS',        loadClass(42)        === DEFAULT_CLASS);

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
