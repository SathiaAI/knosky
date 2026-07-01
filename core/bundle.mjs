// KnoSky bundle engine (KSV2-R4) — intent-manifest builder with fail-closed secret scan.
// Pure Node stdlib + internal imports only. ESM. No new deps.
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { join, relative, isAbsolute, sep } from 'node:path';
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
 * Resolve `ref` under `root` and read it — following symlinks via realpathSync,
 * then verifying the REAL resolved path still lands inside `root` before the
 * file is ever opened. `isSafeRef` above only validates the path STRING; it
 * cannot see that a same-named file on disk is actually a symlink pointing
 * outside root. This is the actual read boundary (belt-and-suspenders on top
 * of fs-indexer's own symlink exclusion at index time — this is a separate
 * read path with its own live filesystem access, so it re-checks independently).
 *
 * Never throws. Distinguishes "nothing to scan by design" (no root given —
 * the caller explicitly opted out of content access) from "root given but the
 * file could not be verified safe/readable" (fail-closed: caller must treat
 * this as unscannable, NEVER as clean).
 *
 * @param {string|undefined} root
 * @param {string} ref
 * @returns {{ buf: Buffer } | { noRoot: true } | { unsafe: true }}
 */
function safeRead(root, ref) {
  if (!root) return { noRoot: true };
  const full = join(root, ref);
  let real, rootReal;
  try {
    real = realpathSync(full);
    rootReal = realpathSync(root);
  } catch {
    return { unsafe: true }; // missing / broken symlink / permission error — cannot verify
  }
  const rel = relative(rootReal, real);
  if (rel === sep || rel.startsWith('..' + sep) || rel === '..' || isAbsolute(rel)) {
    return { unsafe: true }; // real path escapes root (symlink pointed outside) — refuse
  }
  try {
    return { buf: readFileSync(real) };
  } catch {
    return { unsafe: true };
  }
}

/**
 * Compute the hex SHA-256 of a file. Returns "" when unreadable/unsafe/no-root.
 * @param {string|undefined} root   Repo root directory, or undefined.
 * @param {string}           ref    Repo-relative path.
 * @returns {string}
 */
function sha256OfFile(root, ref) {
  const r = safeRead(root, ref);
  if (!r.buf) return '';
  return createHash('sha256').update(r.buf).digest('hex');
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

  // Secret scan — FAIL-CLOSED. Three outcomes per included file:
  //   noRoot  → caller opted out of content access entirely; nothing to scan by
  //             design (sha256 is also "" in this mode — a deliberate no-read mode,
  //             not a failure).
  //   unsafe  → root WAS given but the file could not be verified safe-and-readable
  //             (missing, permission error, or a symlink resolving outside root).
  //             We can no longer prove it's secret-free, so we must NOT call it
  //             clean — treat it as blocked (the previous behavior silently
  //             skipped these and returned "clean", a fail-OPEN bug).
  //   text    → scanned normally.
  let totalMatches = 0;
  let blocked = false;
  let noRootMode = false;

  for (const id of idList) {
    if (!includedSet.has(id)) continue;
    const ref = refByid.get(id);
    const r = safeRead(root, ref);
    if (r.noRoot) { noRootMode = true; continue; }
    if (r.unsafe) { blocked = true; continue; }
    const hits = findSecrets(r.buf.toString('utf8'));
    if (hits.length > 0) {
      blocked = true;
      for (const [, count] of hits) totalMatches += count;
    }
  }
  void noRootMode; // no-root is intentionally a no-op above; named for readability

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
