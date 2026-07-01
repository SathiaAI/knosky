// KnoSky CI artifact generator (KSV2-CI1) — PR-GPS advisory artifact.
// Pure Node stdlib + node:child_process (git, args-array only) + internal imports.
// HARD RULE: exit 0 by default. Only --fail-on-secret can cause exit 1, and only
// when secrets are found in the emitted artifacts. Never throws, never breaks builds.
import { execFileSync } from 'node:child_process';
import { load } from './retrieve.mjs';
import { kcRoute } from './route.mjs';
import { findSecrets } from './contract.mjs';

// ---------------------------------------------------------------------------
// Path-safety guard (mirrors the one in route.mjs)
// ---------------------------------------------------------------------------

function isSafePath(p) {
  if (!p || typeof p !== 'string') return false;
  if (p.startsWith('/')) return false;
  if (/^[A-Za-z]:[\\\/]/.test(p)) return false;
  if (p.split(/[/\\]/).some(seg => seg === '..')) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Git helper — returns changed file list or [] on any error (advisory, never throws)
// ---------------------------------------------------------------------------

function gitChangedFiles(root, base, head) {
  try {
    const output = execFileSync(
      'git',
      ['-C', root, 'diff', '--name-only', base + '...' + head],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
    );
    return output.split('\n').map(l => l.trim()).filter(Boolean);
  } catch (_) {
    // Any git error → advisory empty set, never break the build
    return [];
  }
}

// ---------------------------------------------------------------------------
// summaryMd builder
// ---------------------------------------------------------------------------

function buildSummaryMd(generatedAt, base, head, routes) {
  const lines = [];
  lines.push('## KnoSky PR-GPS — Advisory Navigation Report');
  lines.push('');
  lines.push('> **ADVISORY ONLY** — metadata pointers only, no file bodies, never blocks the build.');
  lines.push('');
  lines.push(`- Generated: ${generatedAt}`);
  if (base) lines.push(`- Base: \`${base}\``);
  if (head) lines.push(`- Head: \`${head}\``);
  lines.push('');

  if (routes.length === 0) {
    lines.push('_No changed files detected in this PR._');
  } else {
    for (const { file, route: routeDoc } of routes) {
      lines.push(`### \`${file}\``);
      lines.push('');
      const topWaypoints = (routeDoc.route || []).slice(0, 5);
      if (topWaypoints.length === 0) {
        lines.push('_No route waypoints found in the index for this file._');
      } else {
        lines.push('**Route waypoints:**');
        lines.push('');
        for (const wp of topWaypoints) {
          const path = typeof wp === 'string' ? wp : (wp && wp.path) || '';
          const reason = (wp && wp.reason) || '';
          lines.push(`- \`${path}\`${reason ? ' — ' + reason : ''}`);
        }
      }
      const confidence = typeof routeDoc.confidence === 'number'
        ? Math.round(routeDoc.confidence * 100) + '%'
        : 'n/a';
      lines.push('');
      lines.push(`**Confidence:** ${confidence}`);
      const caveats = (routeDoc.caveats || []).filter(c =>
        c.includes('recently changed') || c.includes('stale') || c.includes('coverage'),
      );
      if (caveats.length > 0) {
        lines.push('');
        lines.push('**Caveats:**');
        for (const c of caveats) lines.push(`- ${c}`);
      }
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('_This report is advisory. KnoSky reads metadata only — it does not read code meaning._');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// knoskyCi — main export
// ---------------------------------------------------------------------------

/**
 * Generate the KnoSky PR-GPS advisory artifacts.
 *
 * @param {object} [opts]
 * @param {string}   [opts.root='.']         Repo root for git commands.
 * @param {string}   [opts.base]             Base ref for git diff.
 * @param {string}   [opts.head]             Head ref for git diff.
 * @param {string}   [opts.cityPath]         Path to city-data.json (city index).
 * @param {boolean}  [opts.failOnSecret=false] Exit 1 only if secrets found in artifacts.
 * @param {string[]} [opts.changedFiles]     Inject changed files directly (test seam — skips git).
 * @returns {{ exitCode: number, summaryMd: string, routeJson: object, safetyJson: object }}
 */
export async function knoskyCi({
  root = '.',
  base,
  head,
  cityPath,
  failOnSecret = false,
  changedFiles,
} = {}) {
  const generatedAt = new Date().toISOString();

  // 1. Resolve changed files
  let files;
  if (Array.isArray(changedFiles)) {
    // Test seam — use injected list directly, no git needed
    files = changedFiles;
  } else {
    // Resolve base/head from args, then environment, then fallback
    const resolvedBase = base || process.env.GITHUB_BASE_REF || 'HEAD~1';
    const resolvedHead = head || process.env.GITHUB_SHA || 'HEAD';
    files = gitChangedFiles(root, resolvedBase, resolvedHead);
  }

  const resolvedBase = base || process.env.GITHUB_BASE_REF || null;
  const resolvedHead = head || process.env.GITHUB_SHA || null;

  // 2. Load the city index — if absent/unreadable, produce advisory summary and exit 0
  let ctx;
  if (!cityPath) {
    const summaryMd = buildNoIndexSummary(generatedAt, resolvedBase, resolvedHead);
    return {
      exitCode: 0,
      summaryMd,
      routeJson: buildRouteJson(generatedAt, resolvedBase, resolvedHead, []),
      safetyJson: buildSafetyJson(generatedAt, 0),
    };
  }

  try {
    ctx = load(cityPath);
  } catch (_) {
    const summaryMd = buildNoIndexSummary(generatedAt, resolvedBase, resolvedHead);
    return {
      exitCode: 0,
      summaryMd,
      routeJson: buildRouteJson(generatedAt, resolvedBase, resolvedHead, []),
      safetyJson: buildSafetyJson(generatedAt, 0),
    };
  }

  // 3. For each changed file, call kcRoute — metadata only, no file bodies
  const routes = [];
  for (const relpath of files) {
    // Safety: skip any path that escapes the repo
    if (!isSafePath(relpath)) continue;
    let routeDoc;
    try {
      routeDoc = kcRoute(ctx, 'file:' + relpath);
    } catch (_) {
      // Route errors are advisory — skip this file, never break
      continue;
    }
    // Drop any route entries with unsafe paths (defense in depth)
    if (routeDoc && Array.isArray(routeDoc.route)) {
      routeDoc.route = routeDoc.route.filter(wp => {
        const p = typeof wp === 'string' ? wp : (wp && wp.path);
        return !p || isSafePath(p);
      });
    }
    if (routeDoc && Array.isArray(routeDoc.alternates)) {
      routeDoc.alternates = routeDoc.alternates.filter(wp => {
        const p = typeof wp === 'string' ? wp : (wp && wp.path);
        return !p || isSafePath(p);
      });
    }
    routes.push({ file: relpath, route: routeDoc });
  }

  // 4. Build routeJson
  const routeJson = buildRouteJson(generatedAt, resolvedBase, resolvedHead, routes);

  // 5. Build summaryMd
  const summaryMd = buildSummaryMd(generatedAt, resolvedBase, resolvedHead, routes);

  // 6. Scan ONLY the emitted artifacts for secrets (defense in depth)
  const artifactText = summaryMd + '\n' + JSON.stringify(routeJson);
  const secretHits = findSecrets(artifactText);
  const secretsFound = secretHits.reduce((n, [, count]) => n + count, 0);

  // 7. Build safetyJson
  const safetyJson = buildSafetyJson(generatedAt, secretsFound);

  // 8. exitCode: only failOnSecret+secrets_found > 0 can be non-zero
  const exitCode = (failOnSecret && secretsFound > 0) ? 1 : 0;

  return { exitCode, summaryMd, routeJson, safetyJson };
}

// ---------------------------------------------------------------------------
// Artifact builders
// ---------------------------------------------------------------------------

function buildNoIndexSummary(generatedAt, base, head) {
  const lines = [
    '## KnoSky PR-GPS — Advisory Navigation Report',
    '',
    '> **ADVISORY ONLY** — metadata pointers only, no file bodies, never blocks the build.',
    '',
    `- Generated: ${generatedAt}`,
  ];
  if (base) lines.push(`- Base: \`${base}\``);
  if (head) lines.push(`- Head: \`${head}\``);
  lines.push('');
  lines.push('_No index available — run `knosky <path>` to build the city index first._');
  lines.push('');
  lines.push('---');
  lines.push('_This report is advisory. KnoSky reads metadata only._');
  return lines.join('\n');
}

function buildRouteJson(generatedAt, base, head, routes) {
  return {
    knosky_protocol: '1.0',
    artifact_type: 'pr-route',
    advisory: true,
    generated_at: generatedAt,
    base: base || null,
    head: head || null,
    routes: routes.map(({ file, route }) => ({ file, route })),
  };
}

function buildSafetyJson(generatedAt, secretsFound) {
  return {
    knosky_protocol: '1.0',
    artifact_type: 'safety-report',
    advisory: true,
    generated_at: generatedAt,
    absolute_paths: false,
    secrets_found: secretsFound,
    redaction: 'metadata-only; no file bodies; no absolute paths',
  };
}
