// KnoSky district classification model, loader, and validator (SAT-505 / KS2-F1-2).
//
// Defines the five classification levels for KnoSky district nodes, ordered
// from least to most restrictive.  Any node whose `district_class` field is
// absent, null, or unrecognised resolves to the most-restrictive level
// (BLOCKED) — fail-closed by design.
//
// Pure module: no I/O, no external dependencies, safe to import anywhere.

// ---------------------------------------------------------------------------
// Classification level constants
// ---------------------------------------------------------------------------

/** Least-restrictive level — visible to anyone. */
export const CLASS_PUBLIC       = 'public';

/** Visible within the organisation but not externally. */
export const CLASS_INTERNAL     = 'internal';

/** Access limited to specific roles or teams. */
export const CLASS_RESTRICTED   = 'restricted';

/** Highly sensitive — tightly controlled access. */
export const CLASS_CONFIDENTIAL = 'confidential';

/** Most-restrictive level — node is blocked from general access. */
export const CLASS_BLOCKED      = 'blocked';

// ---------------------------------------------------------------------------
// Ordered set and default
// ---------------------------------------------------------------------------

/**
 * All valid classification levels, ordered from least to most restrictive.
 * Index 0 is the least restrictive; the last index is the most restrictive.
 * @type {readonly string[]}
 */
export const CLASSES = Object.freeze([
  CLASS_PUBLIC,
  CLASS_INTERNAL,
  CLASS_RESTRICTED,
  CLASS_CONFIDENTIAL,
  CLASS_BLOCKED,
]);

/**
 * The default classification applied when a node carries no recognisable
 * `district_class` value.  Fail-closed: most restrictive.
 * @type {string}
 */
export const DEFAULT_CLASS = CLASS_BLOCKED;

// ---------------------------------------------------------------------------
// isValidClass
// ---------------------------------------------------------------------------

/**
 * Return `true` if `cls` is a recognised classification level string.
 *
 * @param {unknown} cls
 * @returns {boolean}
 */
export function isValidClass(cls) {
  return CLASSES.includes(cls);
}

// ---------------------------------------------------------------------------
// validateClass
// ---------------------------------------------------------------------------

/**
 * Validate a classification level string.
 * Returns `{ ok: true }` for valid values; `{ ok: false, error: string }`
 * for anything else.
 *
 * @param {unknown} cls
 * @returns {{ ok: boolean, error?: string }}
 */
export function validateClass(cls) {
  if (isValidClass(cls)) return { ok: true };
  return {
    ok: false,
    error: `district_class must be one of ${JSON.stringify(CLASSES)}, got: ${JSON.stringify(cls)}`,
  };
}

// ---------------------------------------------------------------------------
// loadClass
// ---------------------------------------------------------------------------

/**
 * Resolve the district classification of a node.
 *
 * Reads `node.district_class`.  If the value is a recognised classification
 * string it is returned as-is.  Otherwise — absent, null, undefined, or any
 * unrecognised string — the most-restrictive default ({@link DEFAULT_CLASS})
 * is returned so that unknown nodes never escape to a permissive class.
 *
 * The function always returns a non-null string from {@link CLASSES}.
 *
 * @param {object} node  Any node-like object (may carry a `district_class` field).
 * @returns {string}  One of the {@link CLASSES} values.
 */
export function loadClass(node) {
  if (node !== null && typeof node === 'object') {
    const cls = node.district_class;
    if (isValidClass(cls)) return cls;
  }
  return DEFAULT_CLASS;
}
