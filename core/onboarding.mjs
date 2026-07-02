// KnoSky generic onboarding contract (SAT-463).
// Model-agnostic system-prompt artifact: enumerates every available tool,
// hard usage rules, and starter examples — no model-specific formatting or IDs.
// Pure data + make/validate/render. No I/O, no external imports.

export const ONBOARDING_SCHEMA_VERSION = '1.0';

// ---------------------------------------------------------------------------
// Tool catalogue — must stay in sync with mcp/server.mjs registrations.
// ---------------------------------------------------------------------------

/** @type {Array<{ name: string, description: string, params: Record<string,string>, example: string }>} */
export const TOOL_DEFS = [
  {
    name: 'kc_search',
    description:
      'Search the knowledge index by keywords. Returns ranked items (title, summary, category) ' +
      'each with a provenance citation (source path + revision) that links back to the live file. ' +
      'Use for "where does X live / what was decided about Y / how does this connect". ' +
      'Navigation, not full-text code search.',
    params: {
      query: 'keywords (string, max 500 chars)',
      limit: 'max results (integer 1–50, default 10)',
      category: 'restrict to a category id (optional)',
    },
    example: 'kc_search("authentication")',
  },
  {
    name: 'kc_get_node',
    description:
      'Fetch a single indexed item by id (title, summary, category, kind) with its provenance citation.',
    params: { id: 'node id, e.g. fs:src/index.ts (string, max 400 chars)' },
    example: 'kc_get_node("fs:src/auth.js")',
  },
  {
    name: 'kc_list_categories',
    description: 'List the knowledge categories (city districts) with item counts.',
    params: {},
    example: 'kc_list_categories()',
  },
  {
    name: 'kc_get_provenance',
    description:
      'Get the citation for an item: the live source ref + revision, plus its links to related items.',
    params: { id: 'node id (string, max 400 chars)' },
    example: 'kc_get_provenance("fs:src/auth.js")',
  },
  {
    name: 'kc_related',
    description:
      'How a file connects to others: which files it imports (out-edges), which import it (in-edges), ' +
      'and its recent-change (churn) signal. File-level structure with citations, not code analysis.',
    params: { id: 'node id, e.g. fs:src/auth.js (string, max 400 chars)' },
    example: 'kc_related("fs:src/auth.js")',
  },
  {
    name: 'kc_route',
    description:
      'Advisory, metadata-only route through the repo towards a destination. Returns ranked ' +
      'waypoints (where to look first), alternates, related tests, related docs, caveats, and a ' +
      'confidence score. Structural navigation only — does NOT read or analyse code meaning.',
    params: {
      destination:
        'navigation target — file:src/auth.js, folder:src/auth, or keywords (string, max 400 chars)',
      limit: 'max route entries (integer 1–20, default 8)',
    },
    example: 'kc_route("file:src/auth.js")',
  },
];

// ---------------------------------------------------------------------------
// Hard usage rules — model-agnostic, applies to every deployment.
// ---------------------------------------------------------------------------

export const CONSTRAINTS = [
  'All results are advisory-only — verify before acting on any waypoint or route.',
  'KnoSky reads metadata and pointers only; it never reads or uploads full file bodies.',
  'All paths in results are repo-relative (never absolute). Do not construct absolute paths from them.',
  'Citations (provenance) reference the live file; the index may be stale — treat confidence scores accordingly.',
  'Secret and PII patterns are scrubbed from projections; do not assume scrubbing is exhaustive (see LIMITATIONS.md).',
  'kc_route is structural / file-level only — it does not understand code semantics.',
];

// ---------------------------------------------------------------------------
// Starter prompts — illustrative, not exhaustive.
// ---------------------------------------------------------------------------

export const EXAMPLES = [
  'Using KnoSky, where does authentication live in this repo?',
  'Using KnoSky, what are the entry points of this project?',
  'Using KnoSky, which files should I read to understand billing?',
  'Using KnoSky, list the categories in this codebase.',
  'Using KnoSky, what connects to src/auth.js?',
];

// ---------------------------------------------------------------------------
// makeOnboardingDoc — construct a KnoSky `onboarding` artifact envelope.
// ---------------------------------------------------------------------------

/**
 * Construct a KnoSky `onboarding` artifact envelope.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.generatedAt]  ISO-8601 timestamp; defaults to now.
 * @returns {object}
 */
export function makeOnboardingDoc({ generatedAt } = {}) {
  return {
    knosky_protocol: ONBOARDING_SCHEMA_VERSION,
    artifact_type: 'onboarding',
    advisory: true,
    generated_at: generatedAt || new Date().toISOString(),
    tools: TOOL_DEFS.map(t => ({ ...t, params: { ...t.params } })),
    constraints: [...CONSTRAINTS],
    examples: [...EXAMPLES],
  };
}

// ---------------------------------------------------------------------------
// validateOnboardingDoc — collect all constraint violations; ok iff empty.
// ---------------------------------------------------------------------------

/**
 * Validate a KnoSky `onboarding` document.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {object} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateOnboardingDoc(doc) {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { ok: false, errors: ['doc is not an object'] };
  }

  if (doc.knosky_protocol !== '1.0') {
    errors.push(`knosky_protocol must be "1.0", got: ${JSON.stringify(doc.knosky_protocol)}`);
  }

  if (doc.artifact_type !== 'onboarding') {
    errors.push(`artifact_type must be "onboarding", got: ${JSON.stringify(doc.artifact_type)}`);
  }

  if (doc.advisory !== true) {
    errors.push(`advisory must be true, got: ${JSON.stringify(doc.advisory)}`);
  }

  if (!Array.isArray(doc.tools) || doc.tools.length === 0) {
    errors.push('tools must be a non-empty array');
  } else {
    for (let i = 0; i < doc.tools.length; i++) {
      const t = doc.tools[i];
      if (!t || typeof t !== 'object') {
        errors.push(`tools[${i}] must be an object`);
        continue;
      }
      if (typeof t.name !== 'string' || t.name.length === 0) {
        errors.push(`tools[${i}].name must be a non-empty string`);
      }
      if (typeof t.description !== 'string' || t.description.length === 0) {
        errors.push(`tools[${i}].description must be a non-empty string`);
      }
    }
  }

  if (!Array.isArray(doc.constraints)) {
    errors.push('constraints must be an array');
  }

  if (!Array.isArray(doc.examples)) {
    errors.push('examples must be an array');
  }

  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// renderOnboardingText — plain text suitable for any model system prompt.
// ---------------------------------------------------------------------------

/**
 * Render a KnoSky `onboarding` document as plain text.
 * Suitable for pasting directly into any model system prompt.
 *
 * @param {object} doc  Validated onboarding document.
 * @returns {string}
 */
export function renderOnboardingText(doc) {
  const lines = [];

  lines.push('# KnoSky — onboarding');
  lines.push('');
  lines.push(
    'KnoSky is a local, offline knowledge city. It turns a repo or docs folder into a navigable ' +
    'index of pointers and projections. It reads metadata only — it never uploads code.',
  );
  lines.push('');

  lines.push('## Available tools');
  lines.push('');
  for (const t of (doc.tools || [])) {
    lines.push(`### ${t.name}`);
    lines.push(t.description || '');
    if (t.example) lines.push(`Example: ${t.example}`);
    lines.push('');
  }

  lines.push('## Rules');
  lines.push('');
  for (const c of (doc.constraints || [])) {
    lines.push(`- ${c}`);
  }
  lines.push('');

  lines.push('## Starter prompts');
  lines.push('');
  for (const e of (doc.examples || [])) {
    lines.push(`- ${e}`);
  }

  return lines.join('\n');
}
