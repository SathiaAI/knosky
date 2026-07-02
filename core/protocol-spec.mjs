// KnoSky machine-readable protocol spec (SAT-462).
// Exports authoritative JSON Schema (Draft 2020-12) objects for every protocol artifact.
// Pure ESM, no dependencies — the objects are plain JSON-serializable data.
//
// Four schemas are published:
//   ROUTE_SCHEMA          — the `route` artifact written by kc_route / kcRoute()
//   INTENT_MANIFEST_SCHEMA — the `intent-manifest` artifact written by kc_bundle / kcBundle()
//   CONFIG_SCHEMA          — the `.knosky/config.yml` file (after YAML → JS object parse)
//   CITY_SCHEMA            — the city-data v2 envelope (core/CONTRACT.md)
//
// These complement, and must stay consistent with, the runtime validators in:
//   core/schema.mjs   (route + intent-manifest)
//   core/config.mjs   (config)
//   core/contract.mjs (city)
//
// Protocol version constants (mirrors runtime constants in schema.mjs / config.mjs).
export const PROTOCOL_VERSION = '1.0';   // knosky_protocol field value
export const CITY_SCHEMA_VERSION = '2.0'; // schema_version field value

// ---------------------------------------------------------------------------
// Reusable sub-schemas
// ---------------------------------------------------------------------------

/** A path entry inside route[] / alternates[]: either a bare string or an object with a `path` field. */
const PATH_ENTRY = {
  oneOf: [
    { type: 'string', minLength: 1 },
    {
      type: 'object',
      required: ['path'],
      properties: {
        path: { type: 'string', minLength: 1 },
      },
      additionalProperties: true,
    },
  ],
};

/** A KnoSky secret-scan result object embedded in the intent-manifest. */
const SECRET_SCAN_RESULT = {
  type: 'object',
  required: ['status'],
  properties: {
    status: { type: 'string', enum: ['clean', 'blocked'] },
    detail: { type: 'string' },
  },
  additionalProperties: true,
};

/** A provenance object embedded in every city node. */
const PROVENANCE = {
  type: 'object',
  required: ['store', 'ref'],
  properties: {
    store: { type: 'string', minLength: 1 },
    ref: { type: 'string', minLength: 1 },
    source_rev: { type: 'string' },
    fetched_at: { type: 'string' },
  },
  additionalProperties: true,
};

// ---------------------------------------------------------------------------
// ROUTE_SCHEMA
// ---------------------------------------------------------------------------

/**
 * JSON Schema (Draft 2020-12) for the KnoSky `route` artifact.
 * Produced by kc_route / kcRoute().  Must agree with validateRouteDoc() in core/schema.mjs.
 *
 * @type {object}
 */
export const ROUTE_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://knosky.com/schemas/route.json',
  title: 'KnoSky Route',
  description:
    'Advisory navigation route produced by kc_route. ' +
    'Structural metadata only — never code analysis. ' +
    'Always advisory: the `advisory` field is invariantly true.',
  type: 'object',
  required: [
    'knosky_protocol',
    'artifact_type',
    'advisory',
    'generated_at',
    'destination',
    'route',
    'alternates',
    'caveats',
    'confidence',
  ],
  additionalProperties: true,
  properties: {
    knosky_protocol: {
      type: 'string',
      const: '1.0',
      description: 'Protocol version. Always "1.0" for this schema.',
    },
    artifact_type: {
      type: 'string',
      const: 'route',
      description: 'Discriminator field. Always "route" for this artifact.',
    },
    advisory: {
      type: 'boolean',
      const: true,
      description: 'Invariantly true — routes are advisory, never authoritative.',
    },
    generated_at: {
      type: 'string',
      format: 'date-time',
      description: 'ISO-8601 timestamp at which this document was generated.',
    },
    source_rev: {
      type: ['string', 'null'],
      description: 'VCS revision (e.g. git commit SHA) of the city index used. Null when unknown.',
    },
    destination: {
      type: 'string',
      description: 'The navigation target string supplied by the caller.',
    },
    route: {
      type: 'array',
      items: PATH_ENTRY,
      description: 'Ordered primary waypoints. Each entry is a path string or { path, id, reason, score }.',
    },
    alternates: {
      type: 'array',
      items: PATH_ENTRY,
      description: 'Alternate waypoints beyond the primary route limit.',
    },
    caveats: {
      type: 'array',
      items: { type: 'string' },
      description:
        'Advisory notes. Always contains at least the mandatory advisory caveat. ' +
        'May include churn, coverage, and staleness warnings.',
    },
    confidence: {
      type: 'number',
      minimum: 0,
      maximum: 1,
      description: 'Estimated confidence of the route [0..1]. 0 = no signal; ~0.95 = direct file match.',
    },
    tests: {
      type: 'array',
      items: { type: 'object' },
      description: 'Test files in the candidate neighbourhood (informational).',
    },
    docs: {
      type: 'array',
      items: { type: 'object' },
      description: 'Documentation files in the candidate neighbourhood (informational).',
    },
  },
};

// ---------------------------------------------------------------------------
// INTENT_MANIFEST_SCHEMA
// ---------------------------------------------------------------------------

/**
 * JSON Schema (Draft 2020-12) for the KnoSky `intent-manifest` artifact.
 * Produced by kc_bundle / kcBundle().  Must agree with validateIntentManifest() in core/schema.mjs.
 *
 * @type {object}
 */
export const INTENT_MANIFEST_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://knosky.com/schemas/intent-manifest.json',
  title: 'KnoSky Intent Manifest',
  description:
    'Shareable, verifiable file-set manifest produced by kc_bundle. ' +
    'Each path entry carries a SHA-256 digest. ' +
    'The secret_scan field signals whether the manifest was produced by a clean or blocked scan.',
  type: 'object',
  required: [
    'knosky_protocol',
    'artifact_type',
    'advisory',
    'generated_at',
    'paths',
    'edges',
    'secret_scan',
  ],
  additionalProperties: true,
  properties: {
    knosky_protocol: {
      type: 'string',
      const: '1.0',
      description: 'Protocol version. Always "1.0" for this schema.',
    },
    artifact_type: {
      type: 'string',
      const: 'intent-manifest',
      description: 'Discriminator field. Always "intent-manifest" for this artifact.',
    },
    advisory: {
      type: 'boolean',
      const: true,
      description: 'Invariantly true.',
    },
    generated_at: {
      type: 'string',
      format: 'date-time',
      description: 'ISO-8601 timestamp at which this document was generated.',
    },
    paths: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'sha256'],
        properties: {
          path: {
            type: 'string',
            minLength: 1,
            description: 'Repo-relative path. Must not be absolute or contain ".." segments.',
          },
          sha256: {
            type: 'string',
            description: 'Hex-encoded SHA-256 digest of the file at bundle time. Empty string when unreadable.',
          },
        },
        additionalProperties: true,
      },
      description: 'Ordered list of files covered by this manifest.',
    },
    edges: {
      type: 'array',
      items: { type: 'object' },
      description: 'Dependency edges among the covered files.',
    },
    expiry: {
      type: ['string', 'null'],
      description: 'ISO-8601 expiry timestamp, or null for no expiry.',
    },
    secret_scan: {
      ...SECRET_SCAN_RESULT,
      description:
        'Result of the fail-closed secret scan run at bundle time. ' +
        '"clean" means no secret-like values were detected; ' +
        '"blocked" means the scan found a pattern match and the bundle should not be shared.',
    },
  },
};

// ---------------------------------------------------------------------------
// CONFIG_SCHEMA
// ---------------------------------------------------------------------------

/**
 * JSON Schema (Draft 2020-12) for a KnoSky project config object
 * (`.knosky/config.yml`, parsed to a JS object by loadConfig()).
 * Must agree with validateConfig() in core/config.mjs.
 *
 * @type {object}
 */
export const CONFIG_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://knosky.com/schemas/config.json',
  title: 'KnoSky Project Config',
  description:
    'KnoSky project configuration. Read from `.knosky/config.yml`; ' +
    'missing fields default to the values shown in `default`. ' +
    'Unknown keys are rejected by validateConfig().',
  type: 'object',
  required: [
    'knosky_protocol',
    'telemetry',
    'absolute_paths',
    'fail_on_secret',
    'allow_excerpts',
    'max_excerpt_chars',
    'categories',
    'ignore',
  ],
  additionalProperties: false,
  properties: {
    knosky_protocol: {
      type: 'string',
      const: '1.0',
      default: '1.0',
      description: 'Protocol version. Must be "1.0".',
    },
    telemetry: {
      type: 'boolean',
      default: false,
      description: 'Whether to emit telemetry. Defaults to false (never sends data out).',
    },
    absolute_paths: {
      type: 'boolean',
      default: false,
      description: 'Embed absolute filesystem paths in the city output. Defaults to false (basename only).',
    },
    fail_on_secret: {
      type: 'boolean',
      default: true,
      description: 'Abort the build if a secret-like value is detected. Defaults to true (fail-closed).',
    },
    allow_excerpts: {
      type: 'boolean',
      default: false,
      description: 'Include file-content excerpts in the index. Defaults to false.',
    },
    max_excerpt_chars: {
      type: 'integer',
      minimum: 0,
      default: 0,
      description: 'Maximum characters per excerpt. 0 = no excerpts even when allow_excerpts is true.',
    },
    categories: {
      type: 'array',
      items: { type: 'string' },
      default: [],
      description: 'Explicit category (district) labels. Empty array = derived automatically.',
    },
    ignore: {
      type: 'array',
      items: { type: 'string' },
      default: [],
      description: 'Additional glob-style ignore patterns (appended to the built-in defaults and .gitignore).',
    },
  },
};

// ---------------------------------------------------------------------------
// CITY_SCHEMA
// ---------------------------------------------------------------------------

/**
 * JSON Schema (Draft 2020-12) for a KnoSky city-data v2 envelope.
 * Produced by the fs-indexer and consumed by the renderer / MCP server.
 * Must agree with validateCity() + NODE_FIELD_ALLOWLIST in core/contract.mjs.
 *
 * @type {object}
 */
export const CITY_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://knosky.com/schemas/city.json',
  title: 'KnoSky City Data (v2)',
  description:
    'N-category city-data envelope (contract v2). ' +
    'Contains pointers and projections only — never full file bodies (decision D-146). ' +
    'See core/CONTRACT.md for narrative spec.',
  type: 'object',
  required: ['schema_version', 'generated_at', 'categories', 'nodes'],
  additionalProperties: true,
  properties: {
    schema_version: {
      type: 'string',
      const: '2.0',
      description: 'City contract version. Always "2.0" for this schema.',
    },
    generated_at: {
      type: 'string',
      format: 'date-time',
      description: 'ISO-8601 timestamp at which the city was built.',
    },
    source: {
      type: 'object',
      required: ['kind', 'ref'],
      properties: {
        kind: { type: 'string', enum: ['fs', 'github', 'board', 'legacy'] },
        ref: { type: 'string' },
        rev: { type: 'string' },
      },
      additionalProperties: false,
      description: 'Where the city was built from.',
    },
    categories: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'label', 'order'],
        properties: {
          id: { type: 'string', minLength: 1 },
          label: { type: 'string', minLength: 1 },
          color: { type: 'string' },
          order: { type: 'integer', minimum: 0 },
        },
        additionalProperties: false,
      },
      description: 'N-category manifest. Replaces the hardcoded 4-district v1 model.',
    },
    node_count: {
      type: 'integer',
      minimum: 0,
      description: 'Expected number of nodes. Must equal nodes.length when present.',
    },
    nodes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'kind', 'title', 'category', 'links', 'provenance'],
        // additionalProperties:false enforces the serialization allowlist from contract.mjs.
        additionalProperties: false,
        properties: {
          id: {
            type: 'string',
            minLength: 1,
            description: 'Stable, source-derived node identifier.',
          },
          kind: {
            type: 'string',
            description: 'Node kind: decision, spec, file, dir, doc, …',
          },
          title: {
            type: 'string',
            description: 'Short projection title (scrubbed; never a full file body).',
          },
          summary: {
            type: 'string',
            maxLength: 200,
            description:
              'Short excerpt projection (≤ 200 chars, scrubbed; never a full file body).',
          },
          category: {
            type: 'string',
            description: 'Category id. Must match an entry in the top-level categories[] manifest.',
          },
          status: { type: 'string' },
          fact_date: { type: 'string' },
          tags: {
            type: 'array',
            items: { type: 'string' },
          },
          headings: {
            type: 'array',
            items: { type: 'string' },
          },
          links: {
            type: 'array',
            items: { type: 'string' },
            description: 'Edges to other node ids.',
          },
          churn: {
            description: 'Recent-change signal. Object with `c` (commit count) or a plain number.',
          },
          provenance: {
            ...PROVENANCE,
            description: 'Back-pointer to the live source. Fields: store (required), ref (required).',
          },
          visibility: {
            type: 'string',
            enum: ['internal', 'public'],
          },
          sensitive: {
            type: 'boolean',
            description: 'Scrub/flag marker. True when a sensitive-term match was found.',
          },
        },
      },
      description:
        'All nodes in the city. Node fields are strictly limited to the serialization allowlist ' +
        '(id, kind, title, summary, category, status, fact_date, tags, headings, links, churn, ' +
        'provenance, visibility, sensitive).',
    },
  },
};
