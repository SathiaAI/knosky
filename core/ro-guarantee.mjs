// Read-only map guarantee helpers + stale city check (FR-KS-ENT-106/110).

import fs from 'node:fs';
import path from 'node:path';
import { capabilityMatrix } from './enterprise-mode.mjs';

/** Forbidden operation idioms for map/read-only surface (test + docs). */
export const FORBIDDEN_MAP_OPS = Object.freeze([
  'write_file',
  'delete_file',
  'run_command',
  'shell_exec',
  'network_fetch_body',
  'read_outside_root',
  'path_traversal',
]);

/**
 * Assert a relative path stays inside root (path traversal guard).
 * @param {string} root
 * @param {string} candidate
 * @returns {{ ok: boolean, reason?: string, resolved?: string }}
 */
export function assertInsideRoot(root, candidate) {
  const base = path.resolve(root);
  // Reject null bytes and URL tricks early
  if (String(candidate).includes('\0')) {
    return { ok: false, reason: 'null_byte' };
  }
  const resolved = path.resolve(base, candidate);
  const rel = path.relative(base, resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { ok: false, reason: 'outside_root', resolved };
  }
  // Windows: ensure same drive
  if (process.platform === 'win32') {
    if (path.parse(base).root.toLowerCase() !== path.parse(resolved).root.toLowerCase()) {
      return { ok: false, reason: 'outside_root_drive', resolved };
    }
  }
  return { ok: true, resolved };
}

/**
 * Static inspect: MCP server source should not expose write tools by name.
 * @param {string} serverSource
 */
export function inspectMapToolSurface(serverSource) {
  const src = String(serverSource || '');
  const matrix = capabilityMatrix();
  const registered = [];
  const re = /registerTool\(\s*["']([a-z0-9_]+)["']/g;
  let m;
  while ((m = re.exec(src))) registered.push(m[1]);
  const mapExpected = matrix.map_tools_read_only.allowed;
  const missingMap = mapExpected.filter((t) => !registered.includes(t) && !src.includes(t));
  const writey = ['write_file', 'delete_file', 'run_terminal', 'exec_command', 'kc_write', 'kc_delete'];
  const bad = writey.filter((t) => src.includes(`registerTool("${t}"`) || src.includes(`registerTool('${t}'`));
  const hasReadOnlyHints = /readOnlyHint:\s*true/.test(src);
  return {
    registered,
    missingMap,
    forbiddenRegistered: bad,
    hasReadOnlyHints,
    ok: bad.length === 0 && missingMap.length === 0,
  };
}

/**
 * Stale city detection: compare city's generated_at age and optional source mtime samples.
 * @param {object} opts
 * @param {object} opts.city
 * @param {string} [opts.root]
 * @param {number} [opts.maxAgeMs] default 7d
 */
export function checkCityFreshness(opts = {}) {
  const city = opts.city;
  const maxAgeMs = opts.maxAgeMs ?? 7 * 24 * 60 * 60 * 1000;
  const issues = [];
  if (!city?.generated_at) {
    return { ok: false, stale: true, issues: ['missing_generated_at'] };
  }
  const gen = Date.parse(city.generated_at);
  if (Number.isNaN(gen)) {
    return { ok: false, stale: true, issues: ['bad_generated_at'] };
  }
  const age = Date.now() - gen;
  if (age > maxAgeMs) {
    issues.push(`city_older_than_${maxAgeMs}ms`);
  }

  // Sample a few provenance refs — if source files are newer than city, flag stale.
  const root = opts.root ? path.resolve(opts.root) : null;
  let newerSources = 0;
  if (root && Array.isArray(city.nodes)) {
    for (const n of city.nodes.slice(0, 50)) {
      const ref = n?.provenance?.ref;
      if (!ref || ref.includes('..')) continue;
      const abs = path.join(root, ref);
      try {
        const st = fs.statSync(abs);
        if (st.mtimeMs > gen + 1000) newerSources += 1;
      } catch {
        /* missing file — different issue */
      }
    }
  }
  if (newerSources > 0) {
    issues.push(`source_newer_than_city:${newerSources}`);
  }

  const stale = issues.length > 0;
  return {
    ok: !stale,
    stale,
    age_ms: age,
    newer_source_samples: newerSources,
    issues,
    advice: stale
      ? 'Re-run knosky index (enterprise mode) before trusting citations as current.'
      : 'City timestamp looks fresh vs samples.',
  };
}
