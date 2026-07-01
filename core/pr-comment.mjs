// KnoSky PR-comment renderer (KSV2-CI2) — claims-disciplined public Markdown.
// Consumes CI1 artifacts (routeJson + safetyJson) and renders the polished
// PR-GPS comment that knosky ci posts on a pull request.
//
// CLAIMS DISCIPLINE — BINDING (D-162 §8):
//   USE:  "advisory PR-GPS report" / "advisory route you can ignore"
//   USE:  "route cache / freshness"
//   USE:  "reads metadata only / never uploads your code"
//   USE:  "network-silent (verify with --verify-airgap)"
//   USE:  "open protocol / reference implementation"
//   NEVER: CI gate / blocks the build / gates the build
//   NEVER: learns / learns your repo
//   NEVER: understands your code
//   NEVER: zero data risk
//   NEVER: official standard
//   NEVER: air-gap guarantee

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Format a confidence fraction [0..1] as a percent string, or 'n/a'.
 * @param {unknown} val
 * @returns {string}
 */
function fmtConfidence(val) {
  if (typeof val === 'number' && isFinite(val)) {
    return Math.round(val * 100) + '%';
  }
  return 'n/a';
}

/**
 * Extract path + reason from a waypoint entry (string | { path, reason }).
 * @param {unknown} wp
 * @returns {{ path: string, reason: string }}
 */
function parsWaypoint(wp) {
  if (typeof wp === 'string') return { path: wp, reason: '' };
  const path = (wp && typeof wp.path === 'string') ? wp.path : '';
  const reason = (wp && typeof wp.reason === 'string') ? wp.reason : '';
  return { path, reason };
}

// ---------------------------------------------------------------------------
// renderPrComment — main export
// ---------------------------------------------------------------------------

/**
 * Render the KnoSky PR-GPS comment as a Markdown string.
 *
 * This is a DRAFT — the final public wording is Paul's critical gate.
 *
 * @param {object} opts
 * @param {object} opts.routeJson   CI1 route artifact ({ routes, base, head, advisory, … })
 * @param {object} opts.safetyJson  CI1 safety artifact ({ secrets_found, absolute_paths, … })
 * @returns {string}  Markdown comment body.
 */
export function renderPrComment({ routeJson = {}, safetyJson = {} } = {}) {
  const lines = [];

  // -------------------------------------------------------------------------
  // Header
  // -------------------------------------------------------------------------
  lines.push('## 🧭 KnoSky PR-GPS');
  lines.push('');
  lines.push(
    '> **DRAFT — advisory PR-GPS report.** ' +
    'This is an advisory route you can ignore — it never gates or enforces a build outcome.',
  );
  lines.push('');

  // -------------------------------------------------------------------------
  // Per-file route sections
  // -------------------------------------------------------------------------
  const routes = Array.isArray(routeJson.routes) ? routeJson.routes : [];

  if (routes.length === 0) {
    lines.push('_No changed files detected in this PR — nothing to navigate._');
    lines.push('');
  } else {
    for (const { file, route: routeDoc } of routes) {
      lines.push(`### \`${file}\``);
      lines.push('');

      // Top ~5 waypoints
      const waypoints = (Array.isArray(routeDoc && routeDoc.route) ? routeDoc.route : []).slice(0, 5);
      if (waypoints.length === 0) {
        lines.push('_No route waypoints found in the route cache for this file._');
      } else {
        lines.push('**Advisory route waypoints** _(top ' + waypoints.length + ', from route cache):_');
        lines.push('');
        for (const wp of waypoints) {
          const { path, reason } = parsWaypoint(wp);
          lines.push(`- \`${path}\`${reason ? ' — ' + reason : ''}`);
        }
      }
      lines.push('');

      // Confidence
      const conf = fmtConfidence(routeDoc && routeDoc.confidence);
      lines.push(`**Confidence:** ${conf}`);
      lines.push('');

      // Freshness / coverage caveats
      const caveats = Array.isArray(routeDoc && routeDoc.caveats) ? routeDoc.caveats : [];
      const freshnessOrCoverage = caveats.filter(c =>
        /recently changed|stale|freshness|coverage/i.test(c),
      );
      if (freshnessOrCoverage.length > 0) {
        lines.push('**Route freshness / coverage caveats:**');
        lines.push('');
        for (const c of freshnessOrCoverage) lines.push(`- ${c}`);
        lines.push('');
      }

      // Related tests
      const tests = Array.isArray(routeDoc && routeDoc.tests) ? routeDoc.tests : [];
      if (tests.length > 0) {
        lines.push('**Related tests:**');
        lines.push('');
        for (const t of tests) lines.push(`- \`${t}\``);
        lines.push('');
      }

      // Related docs
      const docs = Array.isArray(routeDoc && routeDoc.docs) ? routeDoc.docs : [];
      if (docs.length > 0) {
        lines.push('**Related docs:**');
        lines.push('');
        for (const d of docs) lines.push(`- \`${d}\``);
        lines.push('');
      }
    }
  }

  // -------------------------------------------------------------------------
  // Suggested reviewer / agent prompt block
  // -------------------------------------------------------------------------
  lines.push('---');
  lines.push('');
  lines.push('### 💬 Suggested reviewer / agent prompt');
  lines.push('');

  if (routes.length > 0) {
    // Collect top waypoints across all changed files (unique, capped at 5)
    const seen = new Set();
    const topPaths = [];
    for (const { route: routeDoc } of routes) {
      const wps = Array.isArray(routeDoc && routeDoc.route) ? routeDoc.route : [];
      for (const wp of wps.slice(0, 3)) {
        const { path } = parsWaypoint(wp);
        if (path && !seen.has(path)) {
          seen.add(path);
          topPaths.push(path);
          if (topPaths.length >= 5) break;
        }
      }
      if (topPaths.length >= 5) break;
    }
    const waypointList = topPaths.map(p => `\`${p}\``).join(', ');
    lines.push(
      `> Start your review at: ${waypointList || '_see routes above_'}. ` +
      'Advisory only — verify before acting.',
    );
  } else {
    lines.push(
      '> No route waypoints available for this PR. ' +
      'Advisory only — verify before acting.',
    );
  }

  lines.push('');

  // -------------------------------------------------------------------------
  // Footer — safety / privacy
  // -------------------------------------------------------------------------
  lines.push('---');
  lines.push('');
  const secretsFound = (safetyJson && typeof safetyJson.secrets_found === 'number')
    ? safetyJson.secrets_found
    : 0;
  lines.push(
    '_KnoSky reads metadata only — it never uploads your code. ' +
    `Secrets scan: **${secretsFound}** potential secret(s) found in emitted artifacts. ` +
    'network-silent (verify with --verify-airgap). ' +
    'open protocol / reference implementation._',
  );

  return lines.join('\n');
}
