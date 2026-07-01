// KnoSky bundle engine (KSV2-R4) — intent-manifest builder with fail-closed secret scan.
// Pure Node stdlib + internal imports only. ESM. No new deps.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { findSecrets } from './contract.mjs';
import { makeIntentManifest, validateIntentManifest } from './schema.mjs';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Return true when `ref` is a safe, repo-relative path (not absolute, no "..").
 * @param {string|undefined} ref
 * @returns {boolean}
 */
function isSafeRef(ref) {
  if (!ref || typeof ref !== 'string') return false;
  if (ref.startsWith('/')) return false;
  // Windows drive: C:\ or C:/
  if (/^[A-Za-z]:[\\\/]/.test(ref)) return false;
  if (ref.split(/[/\\]/).some(seg => seg === '..')) return false;
  return true;
}

/**
 * Compute the hex SHA-256 of a file. Returns "" on any error.
 * @param {string|undefined} root   Repo root directory, or undefined.
 * @param {string}           ref    Repo-relative path.
 * @returns {string}
 */
function sha256OfFile(root, ref) {
  if (!root) return '';
  try {
    const fullPath = join(root, ref);
    const buf = readFileSync(fullPath);
    return createHash('sha256').update(buf).digest('hex');
  } catch {
    return '';
  }
}

/**
 * Read a file's text for secret scanning. Returns null on any error.
 * @param {string|undefined} root
 * @param {string}           ref
 * @returns {string|null}
 */
function readText(root, ref) {
  if (!root) return null;
  try {
    return readFileSync(join(root, ref), 'utf8');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// kcBundle — main export
// ---------------------------------------------------------------------------

/**
 * Build an intent-manifest for the given node ids.
 *
 * @param {object}   ctx              — retrieve context {city:{nodes}, byId:Map}
 * @param {string[]} ids              — node ids to include
 * @param {object}   [opts]
 * @param {string}   [opts.root]      — repo root; used to read files for sha256 + secret scan
 * @param {string|null} [opts.expiry] — ISO-8601 expiry timestamp or null
 * @returns {object} intent-manifest (passes validateIntentManifest)
 */
export function kcBundle(ctx, ids, { root, expiry = null } = {}) {
  // Normalise ids to an array of strings
  const idList = Array.isArray(ids) ? ids.map(String) : [];

  // Build the set of included ids (only those with safe refs)
  const includedSet = new Set();
  const refByid = new Map(); // id -> safe ref string

  for (const id of idList) {
    const node = ctx.byId.get(id);
    if (!node) continue; // missing node — skip
    const ref = node.provenance && node.provenance.ref;
    if (!isSafeRef(ref)) continue; // absolute or ".." — skip
    includedSet.add(id);
    refByid.set(id, ref);
  }

  // Build paths[] with sha256
  const paths = [];
  for (const id of idList) {
    if (!includedSet.has(id)) continue;
    const ref = refByid.get(id);
    const sha256 = sha256OfFile(root, ref);
    paths.push({ path: ref, sha256 });
  }

  // Build edges[] — out-edges within the bundled set
  const edges = [];
  for (const id of idList) {
    if (!includedSet.has(id)) continue;
    const node = ctx.byId.get(id);
    const links = Array.isArray(node.links) ? node.links : [];
    for (const target of links) {
      if (includedSet.has(target)) {
        edges.push({ from: id, to: target });
      }
    }
  }

  // Secret scan — fail-closed: if any file is unreadable but has a hash, treat it as clean;
  // if root is provided we try to read; otherwise there is nothing to scan → clean.
  let totalMatches = 0;
  let blocked = false;

  for (const id of idList) {
    if (!includedSet.has(id)) continue;
    const ref = refByid.get(id);
    const text = readText(root, ref);
    if (text === null) continue; // unreadable — skip (no content to scan)
    const hits = findSecrets(text);
    if (hits.length > 0) {
      blocked = true;
      for (const [, count] of hits) totalMatches += count;
    }
  }

  const secret_scan = blocked
    ? { status: 'blocked', count: totalMatches }
    : { status: 'clean', count: 0 };

  const manifest = makeIntentManifest({ paths, edges, expiry, secret_scan });

  // Invariant: manifest MUST pass validateIntentManifest
  const validation = validateIntentManifest(manifest);
  if (!validation.ok) {
    throw new Error('kcBundle produced an invalid intent-manifest: ' + validation.errors.join('; '));
  }

  return manifest;
}
