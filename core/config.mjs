// KnoSky protocol config schema, loader, and validator (SAT-426 / KSV2-P1).
// Pure Node stdlib, ESM — no third-party dependencies.
import fs from 'node:fs';
import path from 'node:path';

// ---------------------------------------------------------------------------
// DEFAULTS — the canonical safe config for every knosky project.
// ---------------------------------------------------------------------------

/** @type {Readonly<KnoskyConfig>} */
export const DEFAULTS = Object.freeze({
  knosky_protocol: '1.0',
  telemetry: false,
  absolute_paths: false,
  fail_on_secret: true,
  allow_excerpts: false,
  max_excerpt_chars: 0,
  categories: [],
  ignore: [],
});

// ---------------------------------------------------------------------------
// parseConfigYaml — minimal YAML-subset parser, no deps.
// Supports: `key: value` lines, booleans, integers, bare/quoted strings,
// block lists (`- item` lines following a `key:` line with no inline value).
// Ignores blank lines and # comments.
// Throws on any line it cannot interpret for a known key.
// ---------------------------------------------------------------------------

/**
 * Parse a minimal YAML subset used by `.knosky/config.yml`.
 *
 * @param {string} text  Raw file contents.
 * @returns {Record<string, unknown>}  Parsed key/value map.
 */
export function parseConfigYaml(text) {
  const result = {};
  const lines = text.split(/\r?\n/);
  let i = 0;

  while (i < lines.length) {
    const raw = lines[i];
    // Strip inline comment and trim
    const line = raw.replace(/#.*$/, '').trimEnd();
    i++;

    if (!line.trim()) continue; // blank / comment-only

    // Must be a `key: [value]` line at the top level (no leading spaces)
    const kvMatch = line.match(/^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)/);
    if (!kvMatch) {
      throw new Error(`parseConfigYaml: unexpected line: ${JSON.stringify(raw)}`);
    }
    const key = kvMatch[1];
    const rest = kvMatch[2].trim();

    if (rest === '') {
      // Possibly a block list — collect `  - item` lines that follow
      const items = [];
      while (i < lines.length) {
        const next = lines[i].replace(/#.*$/, '');
        if (/^\s*-\s/.test(next)) {
          items.push(next.replace(/^\s*-\s*/, '').trim());
          i++;
        } else {
          break;
        }
      }
      result[key] = items;
    } else {
      result[key] = parseScalar(rest, key);
    }
  }

  return result;
}

/**
 * Parse a scalar YAML value: boolean, integer, or string (bare or quoted).
 *
 * @param {string} raw  The raw value string (already trimmed).
 * @param {string} key  The key name, used for error messages.
 * @returns {boolean|number|string}
 */
function parseScalar(raw, key) {
  if (raw === 'true') return true;
  if (raw === 'false') return false;

  // Integer
  if (/^-?\d+$/.test(raw)) return parseInt(raw, 10);

  // Double-quoted string
  if (raw.startsWith('"') && raw.endsWith('"')) return raw.slice(1, -1);

  // Single-quoted string
  if (raw.startsWith("'") && raw.endsWith("'")) return raw.slice(1, -1);

  // Bare string — must not contain characters that signal unhandled YAML
  if (/^[A-Za-z0-9._\-/ ]+$/.test(raw)) return raw;

  throw new Error(`parseConfigYaml: cannot parse value for key "${key}": ${JSON.stringify(raw)}`);
}

// ---------------------------------------------------------------------------
// loadConfig — read + parse `.knosky/config.yml`, merge over DEFAULTS.
// Fail-closed: throws on parse error; returns DEFAULTS copy if file absent.
// ---------------------------------------------------------------------------

/**
 * Load `.knosky/config.yml` from `root` and merge it over {@link DEFAULTS}.
 * Returns a plain object (not frozen).  Throws if the file exists but is
 * malformed.
 *
 * @param {string} root  Absolute (or relative) project root.
 * @returns {Record<string, unknown>}  Merged config object.
 */
export function loadConfig(root) {
  const cfgPath = path.join(root, '.knosky', 'config.yml');

  let text;
  try {
    text = fs.readFileSync(cfgPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      // File absent — return a safe copy of defaults
      return { ...DEFAULTS, categories: [], ignore: [] };
    }
    throw err; // permission error, etc — still fail-closed
  }

  // File exists: parse (throws on malformed — never silently fall back)
  const parsed = parseConfigYaml(text);

  // Deep-merge: parsed wins per-key; arrays are replaced, not concatenated.
  return { ...DEFAULTS, categories: [], ignore: [], ...parsed };
}

// ---------------------------------------------------------------------------
// validateConfig — collect all constraint violations, return { ok, errors }.
// ---------------------------------------------------------------------------

const BOOLEAN_KEYS = ['telemetry', 'absolute_paths', 'fail_on_secret', 'allow_excerpts'];

/**
 * Validate a config object against the KnoSky protocol schema.
 * Collects every violation; `ok` is true only when `errors` is empty.
 *
 * @param {Record<string, unknown>} cfg  Config object (e.g. from {@link loadConfig}).
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateConfig(cfg) {
  const errors = [];
  const knownKeys = new Set(Object.keys(DEFAULTS));

  // knosky_protocol must be the string "1.0"
  if (cfg.knosky_protocol !== '1.0') {
    errors.push(`knosky_protocol must be "1.0", got: ${JSON.stringify(cfg.knosky_protocol)}`);
  }

  // Boolean fields
  for (const k of BOOLEAN_KEYS) {
    if (typeof cfg[k] !== 'boolean') {
      errors.push(`${k} must be a boolean, got: ${JSON.stringify(cfg[k])}`);
    }
  }

  // max_excerpt_chars must be integer >= 0
  const mec = cfg.max_excerpt_chars;
  if (!Number.isInteger(mec) || mec < 0) {
    errors.push(`max_excerpt_chars must be an integer >= 0, got: ${JSON.stringify(mec)}`);
  }

  // categories and ignore must be arrays of strings
  for (const k of ['categories', 'ignore']) {
    const val = cfg[k];
    if (!Array.isArray(val) || val.some(v => typeof v !== 'string')) {
      errors.push(`${k} must be an array of strings, got: ${JSON.stringify(val)}`);
    }
  }

  // Unknown keys
  for (const k of Object.keys(cfg)) {
    if (!knownKeys.has(k)) {
      errors.push(`unknown config key: ${k}`);
    }
  }

  return { ok: errors.length === 0, errors };
}
