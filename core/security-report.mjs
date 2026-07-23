// KnoSky security report after index (FR-KS-ENT-102). Pure ESM, stdlib.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { findSecrets } from './contract.mjs';
import { capabilityMatrix, isEnterpriseMode } from './enterprise-mode.mjs';

function sha256File(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch {
    return null;
  }
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

/**
 * Build a structured security report for a city build.
 * @param {object} opts
 * @param {string} opts.root - source root indexed
 * @param {string} [opts.cityPath]
 * @param {object} [opts.city] - parsed city if already loaded
 * @param {number} [opts.filesScanned]
 * @param {number} [opts.filesSkipped]
 * @param {number} [opts.secretsPre]
 * @param {number} [opts.secretsResidual]
 * @param {string[]} [opts.secretKinds]
 * @param {boolean} [opts.shareSafe]
 * @param {boolean} [opts.absolutePaths]
 * @param {string} [opts.mode]
 * @param {string[]} [opts.mcpToolsEnabled]
 */
export function buildSecurityReport(opts = {}) {
  const mode = opts.mode || 'casual';
  const cityPath = opts.cityPath || null;
  let city = opts.city || null;
  if (!city && cityPath && fs.existsSync(cityPath)) {
    try {
      city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
    } catch {
      city = null;
    }
  }

  const cityHash = cityPath ? sha256File(cityPath) : city ? sha256Text(JSON.stringify(city)) : null;
  const sourceRef = city?.source?.ref || path.basename(opts.root || '');
  const generatedAt = city?.generated_at || new Date().toISOString();
  const nodeCount = city?.node_count ?? city?.nodes?.length ?? 0;

  // Provenance coverage
  let withProv = 0;
  const nodes = city?.nodes || [];
  for (const n of nodes) {
    if (n?.provenance?.ref) withProv += 1;
  }
  const provPct = nodeCount > 0 ? Math.round((1000 * withProv) / nodeCount) / 10 : 100;

  // Absolute path scan on artifact
  let absPathHits = 0;
  if (cityPath && fs.existsSync(cityPath)) {
    const blob = fs.readFileSync(cityPath, 'utf8');
    absPathHits += (blob.match(/[A-Za-z]:\\\\|\/(?:Users|home)\//g) || []).length;
  }

  const secretsPre = opts.secretsPre ?? 0;
  const secretsResidual = opts.secretsResidual ?? 0;
  const shareSafe = opts.shareSafe !== false;
  const blockedShare = shareSafe && (secretsPre > 0 || secretsResidual > 0);

  const matrix = capabilityMatrix();
  const mcpTools =
    opts.mcpToolsEnabled || matrix.map_tools_read_only.allowed.concat(matrix.mode_b_governed.tools);

  const report = {
    schema: 'knosky.security_report.v1',
    generated_at: new Date().toISOString(),
    mode,
    enterprise_profile: isEnterpriseMode(mode),
    source: {
      root_basename: path.basename(opts.root || sourceRef || ''),
      source_ref: sourceRef,
      indexed_at: generatedAt,
      ledger_seq: city?.ledger_seq ?? null,
    },
    scan: {
      files_scanned: opts.filesScanned ?? null,
      files_skipped_redact_path: opts.filesSkipped ?? null,
      node_count: nodeCount,
      secrets_pre_scrub: secretsPre,
      secrets_residual_after_scrub: secretsResidual,
      secret_kinds: opts.secretKinds || [],
    },
    share_safe: {
      enabled: shareSafe,
      absolute_paths_included: opts.absolutePaths === true,
      absolute_path_pattern_hits_in_artifact: absPathHits,
      fail_closed_on_secrets: true,
      shareable_verdict: blockedShare
        ? 'blocked_or_not_shareable'
        : shareSafe && absPathHits === 0
          ? 'share_safe_local_review_still_required'
          : 'local_use_only_review_paths',
    },
    hashes: {
      city_data_sha256: cityHash ? `sha256:${cityHash}` : null,
    },
    provenance: {
      nodes_with_provenance: withProv,
      node_count: nodeCount,
      coverage_percent: provPct,
      meets_enterprise_bar: provPct >= 99 || nodeCount === 0,
    },
    mcp: {
      read_only_map_tools: matrix.map_tools_read_only.allowed,
      mode_b_tools: matrix.mode_b_governed.tools,
      forbidden: matrix.forbidden_as_map_tools,
      tools_enabled_hint: mcpTools,
      read_only_mode_asserted: true,
    },
    dual_honesty: matrix.dual_table_honesty,
    summary: {
      risk_level: secretsPre || secretsResidual ? 'HIGH' : absPathHits ? 'MEDIUM' : 'LOW',
      ok_for_local_use: true,
      ok_to_share_externally: !blockedShare && shareSafe && absPathHits === 0 && secretsPre === 0,
    },
  };

  return report;
}

/**
 * Human-readable one-page audit/security summary (FR-KS-ENT-115).
 * @param {object} report
 * @returns {string}
 */
export function formatSecurityReportMarkdown(report) {
  const s = report.summary || {};
  const lines = [
    '# KnoSky Build Audit / Security Summary',
    '',
    `- **Mode:** ${report.mode}`,
    `- **Source (basename):** ${report.source?.root_basename || 'n/a'}`,
    `- **Indexed at:** ${report.source?.indexed_at || 'n/a'}`,
    `- **Nodes:** ${report.scan?.node_count ?? 'n/a'}`,
    `- **Secrets (pre-scrub):** ${report.scan?.secrets_pre_scrub ?? 'n/a'}`,
    `- **Secrets residual:** ${report.scan?.secrets_residual_after_scrub ?? 'n/a'}`,
    `- **Share-safe enabled:** ${report.share_safe?.enabled ? 'yes' : 'no'}`,
    `- **Absolute paths in output:** ${report.share_safe?.absolute_paths_included ? 'INCLUDED' : 'stripped / basename'}`,
    `- **Shareable verdict:** ${report.share_safe?.shareable_verdict}`,
    `- **City hash:** ${report.hashes?.city_data_sha256 || 'n/a'}`,
    `- **Provenance coverage:** ${report.provenance?.coverage_percent}% (${report.provenance?.nodes_with_provenance}/${report.provenance?.node_count})`,
    `- **MCP map tools:** read-only asserted`,
    `- **Risk level:** ${s.risk_level}`,
    `- **OK for local use:** ${s.ok_for_local_use ? 'yes' : 'no'}`,
    `- **OK to share externally without review:** ${s.ok_to_share_externally ? 'yes (still glance first)' : 'no — local or blocked'}`,
    '',
    '## Honesty',
    '',
    report.dual_honesty || '',
    '',
    '## Forbidden for map tools',
    '',
    ...(report.mcp?.forbidden || []).map((f) => `- ${f}`),
    '',
    '_Generated by knosky security report (enterprise phase 1)._',
    '',
  ];
  return lines.join('\n');
}

/**
 * Write report JSON + markdown next to city.
 * @param {string} outDir - usually project/.knosky
 * @param {object} report
 */
export function writeSecurityReportFiles(outDir, report) {
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'security-report.json');
  const mdPath = path.join(outDir, 'security-summary.md');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  fs.writeFileSync(mdPath, formatSecurityReportMarkdown(report), 'utf8');
  return { jsonPath, mdPath };
}

/**
 * Quick scan of an existing city file for secret-like residues (defense in depth).
 * @param {string} cityPath
 */
export function scanCityArtifactSecrets(cityPath) {
  if (!fs.existsSync(cityPath)) return { ok: false, hits: [], total: 0 };
  const text = fs.readFileSync(cityPath, 'utf8');
  const hits = findSecrets(text);
  const total = hits.reduce((a, h) => a + h[1], 0);
  return { ok: total === 0, hits, total, kinds: hits.map((h) => h[0]) };
}
