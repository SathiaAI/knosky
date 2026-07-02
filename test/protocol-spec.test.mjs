// KnoSky machine-readable protocol spec tests (SAT-462). Run: node test/protocol-spec.test.mjs
//
// Checks that protocol-spec.mjs exports well-formed JSON-Schema objects and that each schema
// stays consistent with the runtime validators in core/schema.mjs, core/config.mjs, and
// core/contract.mjs.
import {
  PROTOCOL_VERSION,
  CITY_SCHEMA_VERSION,
  ROUTE_SCHEMA,
  INTENT_MANIFEST_SCHEMA,
  CONFIG_SCHEMA,
  CITY_SCHEMA,
} from '../core/protocol-spec.mjs';
import {
  PROTOCOL_VERSION as RT_PROTOCOL_VERSION,
  makeRouteDoc,
  validateRouteDoc,
  makeIntentManifest,
  validateIntentManifest,
} from '../core/schema.mjs';
import {
  DEFAULTS,
  validateConfig,
} from '../core/config.mjs';
import {
  SCHEMA_VERSION as RT_CITY_SCHEMA_VERSION,
  NODE_FIELD_ALLOWLIST,
  validateCity,
  deriveCategories,
} from '../core/contract.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) exports exist and are objects
// ---------------------------------------------------------------------------
ok('ROUTE_SCHEMA is exported as an object', ROUTE_SCHEMA !== null && typeof ROUTE_SCHEMA === 'object');
ok('INTENT_MANIFEST_SCHEMA is exported as an object', INTENT_MANIFEST_SCHEMA !== null && typeof INTENT_MANIFEST_SCHEMA === 'object');
ok('CONFIG_SCHEMA is exported as an object', CONFIG_SCHEMA !== null && typeof CONFIG_SCHEMA === 'object');
ok('CITY_SCHEMA is exported as an object', CITY_SCHEMA !== null && typeof CITY_SCHEMA === 'object');

// ---------------------------------------------------------------------------
// (b) protocol version constants match the runtime
// ---------------------------------------------------------------------------
ok(
  'PROTOCOL_VERSION matches runtime PROTOCOL_VERSION',
  PROTOCOL_VERSION === RT_PROTOCOL_VERSION,
  `spec=${PROTOCOL_VERSION} runtime=${RT_PROTOCOL_VERSION}`,
);
ok(
  'CITY_SCHEMA_VERSION matches runtime SCHEMA_VERSION',
  CITY_SCHEMA_VERSION === RT_CITY_SCHEMA_VERSION,
  `spec=${CITY_SCHEMA_VERSION} runtime=${RT_CITY_SCHEMA_VERSION}`,
);

// ---------------------------------------------------------------------------
// (c) schemas carry $schema, $id, title, type, required[]
// ---------------------------------------------------------------------------
for (const [name, schema] of [
  ['ROUTE_SCHEMA', ROUTE_SCHEMA],
  ['INTENT_MANIFEST_SCHEMA', INTENT_MANIFEST_SCHEMA],
  ['CONFIG_SCHEMA', CONFIG_SCHEMA],
  ['CITY_SCHEMA', CITY_SCHEMA],
]) {
  ok(`${name} has $schema`, typeof schema.$schema === 'string' && schema.$schema.length > 0);
  ok(`${name} has $id`, typeof schema.$id === 'string' && schema.$id.length > 0);
  ok(`${name} has title`, typeof schema.title === 'string' && schema.title.length > 0);
  ok(`${name} has description`, typeof schema.description === 'string' && schema.description.length > 0);
  ok(`${name} type is "object"`, schema.type === 'object');
  ok(`${name} has required[] (non-empty array)`, Array.isArray(schema.required) && schema.required.length > 0);
  ok(`${name} has properties object`, schema.properties !== null && typeof schema.properties === 'object');
}

// ---------------------------------------------------------------------------
// (d) ROUTE_SCHEMA required fields agree with what makeRouteDoc emits
// ---------------------------------------------------------------------------
{
  const doc = makeRouteDoc({ destination: 'src/foo.mjs' });
  const required = ROUTE_SCHEMA.required;
  for (const field of required) {
    ok(
      `ROUTE_SCHEMA required field "${field}" is present in makeRouteDoc output`,
      Object.prototype.hasOwnProperty.call(doc, field),
    );
  }
}

// (d cont.) artifact_type const matches the validator's expectation
ok(
  'ROUTE_SCHEMA artifact_type const is "route"',
  ROUTE_SCHEMA.properties.artifact_type.const === 'route',
);

// (d cont.) knosky_protocol const matches the runtime constant
ok(
  'ROUTE_SCHEMA knosky_protocol const matches PROTOCOL_VERSION',
  ROUTE_SCHEMA.properties.knosky_protocol.const === PROTOCOL_VERSION,
);

// (d cont.) confidence schema bounds agree with the runtime validator [0..1]
{
  const confProp = ROUTE_SCHEMA.properties.confidence;
  ok('ROUTE_SCHEMA confidence minimum is 0', confProp.minimum === 0);
  ok('ROUTE_SCHEMA confidence maximum is 1', confProp.maximum === 1);
}

// ---------------------------------------------------------------------------
// (e) INTENT_MANIFEST_SCHEMA required fields agree with makeIntentManifest
// ---------------------------------------------------------------------------
{
  const doc = makeIntentManifest({ secret_scan: { status: 'clean' } });
  for (const field of INTENT_MANIFEST_SCHEMA.required) {
    ok(
      `INTENT_MANIFEST_SCHEMA required field "${field}" is in makeIntentManifest output`,
      Object.prototype.hasOwnProperty.call(doc, field),
    );
  }
}

// (e cont.) discriminator fields
ok(
  'INTENT_MANIFEST_SCHEMA artifact_type const is "intent-manifest"',
  INTENT_MANIFEST_SCHEMA.properties.artifact_type.const === 'intent-manifest',
);
ok(
  'INTENT_MANIFEST_SCHEMA knosky_protocol const matches PROTOCOL_VERSION',
  INTENT_MANIFEST_SCHEMA.properties.knosky_protocol.const === PROTOCOL_VERSION,
);

// (e cont.) secret_scan.status enum exactly matches the runtime validator
{
  const statusEnum = INTENT_MANIFEST_SCHEMA.properties.secret_scan.properties.status.enum;
  ok(
    'INTENT_MANIFEST_SCHEMA secret_scan.status enum includes "clean"',
    Array.isArray(statusEnum) && statusEnum.includes('clean'),
  );
  ok(
    'INTENT_MANIFEST_SCHEMA secret_scan.status enum includes "blocked"',
    Array.isArray(statusEnum) && statusEnum.includes('blocked'),
  );
  ok(
    'INTENT_MANIFEST_SCHEMA secret_scan.status enum has exactly 2 values',
    Array.isArray(statusEnum) && statusEnum.length === 2,
  );
}

// (e cont.) paths items require path + sha256 (matches validateIntentManifest)
{
  const pathsItems = INTENT_MANIFEST_SCHEMA.properties.paths.items;
  ok(
    'INTENT_MANIFEST_SCHEMA paths items require "path"',
    Array.isArray(pathsItems.required) && pathsItems.required.includes('path'),
  );
  ok(
    'INTENT_MANIFEST_SCHEMA paths items require "sha256"',
    Array.isArray(pathsItems.required) && pathsItems.required.includes('sha256'),
  );
}

// ---------------------------------------------------------------------------
// (f) CONFIG_SCHEMA required fields agree with DEFAULTS keys
// ---------------------------------------------------------------------------
{
  const defaultsKeys = Object.keys(DEFAULTS);
  const specRequired = CONFIG_SCHEMA.required;

  // Every DEFAULTS key should be required in the schema (config applies all defaults)
  for (const k of defaultsKeys) {
    ok(
      `CONFIG_SCHEMA required includes DEFAULTS key "${k}"`,
      specRequired.includes(k),
    );
  }

  // Every required schema field should be in properties
  for (const k of specRequired) {
    ok(
      `CONFIG_SCHEMA properties has required field "${k}"`,
      Object.prototype.hasOwnProperty.call(CONFIG_SCHEMA.properties, k),
    );
  }
}

// (f cont.) validateConfig on DEFAULTS emits no errors
{
  const result = validateConfig({ ...DEFAULTS });
  ok('validateConfig(DEFAULTS) passes', result.ok === true, JSON.stringify(result.errors));
}

// (f cont.) additionalProperties: false matches the runtime "unknown keys" check
ok(
  'CONFIG_SCHEMA additionalProperties is false (mirrors unknown-key rejection)',
  CONFIG_SCHEMA.additionalProperties === false,
);

// (f cont.) knosky_protocol const matches runtime
ok(
  'CONFIG_SCHEMA knosky_protocol const matches PROTOCOL_VERSION',
  CONFIG_SCHEMA.properties.knosky_protocol.const === PROTOCOL_VERSION,
);

// (f cont.) max_excerpt_chars minimum matches runtime (must be >= 0)
ok(
  'CONFIG_SCHEMA max_excerpt_chars minimum is 0',
  CONFIG_SCHEMA.properties.max_excerpt_chars.minimum === 0,
);

// ---------------------------------------------------------------------------
// (g) CITY_SCHEMA node properties exactly match the runtime NODE_FIELD_ALLOWLIST
// ---------------------------------------------------------------------------
{
  const schemaNodeProps = Object.keys(CITY_SCHEMA.properties.nodes.items.properties);
  const allowlist = NODE_FIELD_ALLOWLIST.slice().sort();
  const schemaNodePropsSorted = schemaNodeProps.slice().sort();

  ok(
    'CITY_SCHEMA node properties match NODE_FIELD_ALLOWLIST exactly',
    JSON.stringify(schemaNodePropsSorted) === JSON.stringify(allowlist),
    `schema=[${schemaNodePropsSorted}] allowlist=[${allowlist}]`,
  );
}

// (g cont.) schema_version const matches runtime
ok(
  'CITY_SCHEMA schema_version const matches CITY_SCHEMA_VERSION',
  CITY_SCHEMA.properties.schema_version.const === CITY_SCHEMA_VERSION,
);

// (g cont.) required node fields agree with contract.mjs NODE_REQUIRED
{
  const { NODE_REQUIRED } = await import('../core/contract.mjs');
  const schemaNodeRequired = CITY_SCHEMA.properties.nodes.items.required;
  for (const k of NODE_REQUIRED) {
    ok(
      `CITY_SCHEMA node required includes NODE_REQUIRED field "${k}"`,
      schemaNodeRequired.includes(k),
    );
  }
}

// (g cont.) additionalProperties: false on node items (enforces allowlist)
ok(
  'CITY_SCHEMA node items additionalProperties is false (enforces allowlist)',
  CITY_SCHEMA.properties.nodes.items.additionalProperties === false,
);

// (g cont.) summary maxLength is 200 (matches SUMMARY_MAX)
{
  const summaryMax = CITY_SCHEMA.properties.nodes.items.properties.summary.maxLength;
  const { SUMMARY_MAX } = await import('../core/contract.mjs');
  ok(
    'CITY_SCHEMA summary maxLength matches SUMMARY_MAX',
    summaryMax === SUMMARY_MAX,
    `schema=${summaryMax} runtime=${SUMMARY_MAX}`,
  );
}

// ---------------------------------------------------------------------------
// (h) schemas are JSON-serializable (pure data, no functions or circular refs)
// ---------------------------------------------------------------------------
for (const [name, schema] of [
  ['ROUTE_SCHEMA', ROUTE_SCHEMA],
  ['INTENT_MANIFEST_SCHEMA', INTENT_MANIFEST_SCHEMA],
  ['CONFIG_SCHEMA', CONFIG_SCHEMA],
  ['CITY_SCHEMA', CITY_SCHEMA],
]) {
  let serializable = true;
  let roundTripped = null;
  try {
    const json = JSON.stringify(schema);
    roundTripped = JSON.parse(json);
  } catch {
    serializable = false;
  }
  ok(`${name} is JSON-serializable`, serializable);
  ok(`${name} round-trips to JSON without data loss`, roundTripped !== null && roundTripped.$id === schema.$id);
}

// ---------------------------------------------------------------------------
// (i) $id URIs are distinct across schemas (no collision)
// ---------------------------------------------------------------------------
{
  const ids = [
    ROUTE_SCHEMA.$id,
    INTENT_MANIFEST_SCHEMA.$id,
    CONFIG_SCHEMA.$id,
    CITY_SCHEMA.$id,
  ];
  const uniqueIds = new Set(ids);
  ok('all schema $id URIs are distinct', uniqueIds.size === ids.length, JSON.stringify(ids));
}

// ---------------------------------------------------------------------------
// (j) ROUTE_SCHEMA and INTENT_MANIFEST_SCHEMA advisory const is true
// ---------------------------------------------------------------------------
ok(
  'ROUTE_SCHEMA advisory const is true',
  ROUTE_SCHEMA.properties.advisory.const === true,
);
ok(
  'INTENT_MANIFEST_SCHEMA advisory const is true',
  INTENT_MANIFEST_SCHEMA.properties.advisory.const === true,
);

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
