// KnoSky protocol artifact schemas and validators (SAT-427 / KSV2-P2).
// Covers: route.json and intent-manifest.json envelope shapes.
// Pure Node stdlib, ESM — no third-party dependencies.

// ---------------------------------------------------------------------------
// Protocol version constant
// ---------------------------------------------------------------------------

/** @type {string} */
export const PROTOCOL_VERSION = '1.0';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Return true if `str` is an absolute path (Unix or Windows).
 * @param {string} str
 * @returns {boolean}
 */
function isAbsolutePath(str) {
  if (str.startsWith('/')) return true;
  // Windows: C:\ or C:/
  if (/^[A-Za-z]:[\\\/]/.test(str)) return true;
  return false;
}

/**
 * Return true if `str` contains a `..` path segment.
 * Splits on both `/` and `\`.
 * @param {string} str
 * @returns {boolean}
 */
function hasDotDotSegment(str) {
  return str.split(/[/\\]/).some(seg => seg === '..');
}

/**
 * Extract the path string from a route/manifest entry.
 * An entry is either a plain string or an object with a `path` field.
 * Returns null if the entry carries no recognisable path.
 *
 * @param {unknown} entry
 * @returns {string|null}
 */
function extractPathString(entry) {
  if (typeof entry === 'string') return entry;
  if (entry !== null && typeof entry === 'object' && typeof entry.path === 'string') {
    return entry.path;
  }
  return null;
}

/**
 * Validate the absolute-path invariant over an array of entries.
 * Pushes error messages into `errors` for each violation found.
 *
 * @param {unknown[]} entries   Array of string or { path } objects.
 * @param {string}    fieldName Label for error messages.
 * @param {string[]}  errors    Accumulator array.
 */
function checkAbsolutePaths(entries, fieldName, errors) {
  for (let i = 0; i < entries.length; i++) {
    const p = extractPathString(entries[i]);
    if (p === null) continue; // non-path entry — skip
    if (isAbsolutePath(p)) {
      errors.push(`${fieldName}[${i}] must not be an absolute path: ${JSON.stringify(p)}`);
    }
    if (hasDotDotSegment(p)) {
      errors.push(`${fieldName}[${i}] must not contain a ".." path segment: ${JSON.stringify(p)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// makeRouteDoc
// ---------------------------------------------------------------------------

/**
 * Construct a KnoSky `route` artifact envelope.
 *
 * @param {object}   opts
 * @param {string}   opts.destination    Navigation target.
 * @param {unknown[]} [opts.route]       Ordered waypoints.
 * @param {unknown[]} [opts.alternates]  Alternate routes.
 * @param {string[]}  [opts.caveats]     Advisory notes.
 * @param {number}    [opts.confidence]  Confidence score [0..1].
 * @param {string|null} [opts.source_rev] VCS revision that produced this doc.
 * @returns {object}
 */
export function makeRouteDoc({
  destination,
  route = [],
  alternates = [],
  caveats = [],
  confidence = 0,
  source_rev = null,
} = {}) {
  return {
    knosky_protocol: PROTOCOL_VERSION,
    artifact_type: 'route',
    advisory: true,
    generated_at: new Date().toISOString(),
    source_rev,
    destination,
    route,
    alternates,
    caveats,
    confidence,
  };
}

// ---------------------------------------------------------------------------
// validateRouteDoc
// ---------------------------------------------------------------------------

/**
 * Validate a KnoSky `route` document.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {object} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateRouteDoc(doc) {
  const errors = [];

  if (doc.knosky_protocol !== '1.0') {
    errors.push(`knosky_protocol must be "1.0", got: ${JSON.stringify(doc.knosky_protocol)}`);
  }

  if (doc.artifact_type !== 'route') {
    errors.push(`artifact_type must be "route", got: ${JSON.stringify(doc.artifact_type)}`);
  }

  if (doc.advisory !== true) {
    errors.push(`advisory must be true, got: ${JSON.stringify(doc.advisory)}`);
  }

  for (const field of ['route', 'alternates', 'caveats']) {
    if (!Array.isArray(doc[field])) {
      errors.push(`${field} must be an array, got: ${JSON.stringify(doc[field])}`);
    }
  }

  if (typeof doc.confidence !== 'number' || doc.confidence < 0 || doc.confidence > 1) {
    errors.push(`confidence must be a number in [0, 1], got: ${JSON.stringify(doc.confidence)}`);
  }

  // Absolute-path invariant applies to route[] and alternates[]
  if (Array.isArray(doc.route)) {
    checkAbsolutePaths(doc.route, 'route', errors);
  }
  if (Array.isArray(doc.alternates)) {
    checkAbsolutePaths(doc.alternates, 'alternates', errors);
  }

  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// makeIntentManifest
// ---------------------------------------------------------------------------

/**
 * Construct a KnoSky `intent-manifest` artifact envelope.
 *
 * @param {object}   opts
 * @param {Array<{ path: string, sha256: string }>} [opts.paths]  Files covered.
 * @param {unknown[]} [opts.edges]       Dependency edges.
 * @param {string|null} [opts.expiry]    ISO-8601 expiry timestamp or null.
 * @param {object}   opts.secret_scan    REQUIRED secret-scan result object.
 * @returns {object}
 */
export function makeIntentManifest({
  paths = [],
  edges = [],
  expiry = null,
  secret_scan,
} = {}) {
  return {
    knosky_protocol: PROTOCOL_VERSION,
    artifact_type: 'intent-manifest',
    advisory: true,
    generated_at: new Date().toISOString(),
    paths,
    edges,
    expiry,
    secret_scan,
  };
}

// ---------------------------------------------------------------------------
// validateIntentManifest
// ---------------------------------------------------------------------------

/**
 * Validate a KnoSky `intent-manifest` document.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {object} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateIntentManifest(doc) {
  const errors = [];

  if (doc.knosky_protocol !== '1.0') {
    errors.push(`knosky_protocol must be "1.0", got: ${JSON.stringify(doc.knosky_protocol)}`);
  }

  if (doc.artifact_type !== 'intent-manifest') {
    errors.push(`artifact_type must be "intent-manifest", got: ${JSON.stringify(doc.artifact_type)}`);
  }

  if (doc.advisory !== true) {
    errors.push(`advisory must be true, got: ${JSON.stringify(doc.advisory)}`);
  }

  // paths must be an array of { path: string (non-empty), sha256: string }
  if (!Array.isArray(doc.paths)) {
    errors.push(`paths must be an array, got: ${JSON.stringify(doc.paths)}`);
  } else {
    for (let i = 0; i < doc.paths.length; i++) {
      const entry = doc.paths[i];
      if (!entry || typeof entry !== 'object') {
        errors.push(`paths[${i}] must be an object`);
        continue;
      }
      if (typeof entry.path !== 'string' || entry.path.length === 0) {
        errors.push(`paths[${i}].path must be a non-empty string, got: ${JSON.stringify(entry.path)}`);
      }
      if (typeof entry.sha256 !== 'string') {
        errors.push(`paths[${i}].sha256 must be a string, got: ${JSON.stringify(entry.sha256)}`);
      }
    }

    // Absolute-path invariant on paths[].path
    checkAbsolutePaths(doc.paths, 'paths', errors);
  }

  // secret_scan must be present and have a valid status
  if (!doc.secret_scan || typeof doc.secret_scan !== 'object') {
    errors.push('secret_scan is required and must be an object');
  } else if (doc.secret_scan.status !== 'clean' && doc.secret_scan.status !== 'blocked') {
    errors.push(
      `secret_scan.status must be "clean" or "blocked", got: ${JSON.stringify(doc.secret_scan.status)}`,
    );
  }

  return { ok: errors.length === 0, errors };
}
