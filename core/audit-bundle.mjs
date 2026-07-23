// KnoSky audit bundle pack + verify (FR-KS-ENT-111/112). Pure ESM, stdlib.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { buildSecurityReport, formatSecurityReportMarkdown, scanCityArtifactSecrets } from './security-report.mjs';
import { capabilityMatrix, resolveRunMode, isEnterpriseMode } from './enterprise-mode.mjs';
import { loadConfig } from './config.mjs';

function sha256File(p) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  } catch {
    return null;
  }
}

function copyIfExists(src, dest) {
  if (!fs.existsSync(src)) return false;
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  return true;
}

function stampDir(base) {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const name = `knosky_audit_bundle_${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}_${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
  return path.join(base, name);
}

/**
 * Pack an audit bundle for a project root that already has .knosky/city-data.json
 * @param {object} opts
 * @param {string} opts.root
 * @param {string} [opts.outDir] parent dir for bundle folder
 * @param {string} [opts.mode]
 */
export function packAuditBundle(opts = {}) {
  const root = path.resolve(opts.root || '.');
  const knoskyDir = path.join(root, '.knosky');
  const cityPath = path.join(knoskyDir, 'city-data.json');
  if (!fs.existsSync(cityPath)) {
    return {
      ok: false,
      reason: 'missing_city',
      next_action: 'Run knosky with enterprise mode (or index first) so .knosky/city-data.json exists.',
    };
  }

  const mode = resolveRunMode({
    cliMode: opts.mode,
    config: (() => {
      try {
        return loadConfig(root);
      } catch {
        return {};
      }
    })(),
  });

  const parent = path.resolve(opts.outDir || knoskyDir);
  const bundleDir = stampDir(parent);
  fs.mkdirSync(bundleDir, { recursive: true });

  // Core files
  copyIfExists(cityPath, path.join(bundleDir, 'city-data.json'));
  copyIfExists(path.join(knoskyDir, 'config.yml'), path.join(bundleDir, 'config.yaml'));
  copyIfExists(path.join(root, '.kcignore'), path.join(bundleDir, 'ignore_kcignore.txt'));
  copyIfExists(path.join(root, '.gitignore'), path.join(bundleDir, 'ignore_gitignore.txt'));

  const secScan = scanCityArtifactSecrets(cityPath);
  let city = null;
  try {
    city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
  } catch {
    city = null;
  }

  const report =
    fs.existsSync(path.join(knoskyDir, 'security-report.json'))
      ? JSON.parse(fs.readFileSync(path.join(knoskyDir, 'security-report.json'), 'utf8'))
      : buildSecurityReport({
          root,
          cityPath,
          city,
          mode,
          shareSafe: true,
          absolutePaths: false,
          secretsResidual: secScan.total,
          secretKinds: secScan.kinds,
        });

  fs.writeFileSync(path.join(bundleDir, 'security_report.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(bundleDir, 'secret_scan_report.json'), JSON.stringify(secScan, null, 2) + '\n');
  fs.writeFileSync(
    path.join(bundleDir, 'city_data_hash.json'),
    JSON.stringify({ city_data_sha256: `sha256:${sha256File(cityPath)}` }, null, 2) + '\n',
  );

  // Provenance sample / full list light
  const provLines = [];
  for (const n of city?.nodes || []) {
    provLines.push(
      JSON.stringify({
        node_id: n.id,
        source_path: n.provenance?.ref,
        source_rev: n.provenance?.source_rev || n.provenance?.rev || null,
        source_hash: n.provenance?.hash || null,
        indexed_at: city.generated_at,
      }),
    );
  }
  fs.writeFileSync(path.join(bundleDir, 'node_provenance.jsonl'), provLines.join('\n') + (provLines.length ? '\n' : ''));

  const matrix = capabilityMatrix();
  fs.writeFileSync(path.join(bundleDir, 'mcp_tool_manifest.json'), JSON.stringify(matrix, null, 2) + '\n');

  // Ignore rules snapshot
  fs.writeFileSync(
    path.join(bundleDir, 'ignore_rules.json'),
    JSON.stringify(
      {
        defaults_note: 'Indexer honors .gitignore inside git repos and .kcignore; see LIMITATIONS.md for edge cases.',
        has_kcignore: fs.existsSync(path.join(root, '.kcignore')),
        has_gitignore: fs.existsSync(path.join(root, '.gitignore')),
      },
      null,
      2,
    ) + '\n',
  );

  const summaryMd = formatSecurityReportMarkdown(report);
  fs.writeFileSync(path.join(bundleDir, 'README.md'), summaryMd, 'utf8');
  fs.writeFileSync(
    path.join(bundleDir, 'share_safe_report.json'),
    JSON.stringify(report.share_safe || {}, null, 2) + '\n',
  );

  const buildLog = {
    packed_at: new Date().toISOString(),
    root_basename: path.basename(root),
    mode,
    enterprise: isEnterpriseMode(mode),
    files: fs.readdirSync(bundleDir),
  };
  fs.writeFileSync(path.join(bundleDir, 'build_log.jsonl'), JSON.stringify(buildLog) + '\n');

  // Source manifest
  fs.writeFileSync(
    path.join(bundleDir, 'source_manifest.json'),
    JSON.stringify(
      {
        root_basename: path.basename(root),
        city_source: city?.source || null,
        ledger_seq: city?.ledger_seq ?? null,
        node_count: city?.node_count ?? city?.nodes?.length ?? 0,
      },
      null,
      2,
    ) + '\n',
  );

  return { ok: true, bundleDir, mode, files: buildLog.files };
}

/**
 * Verify a previously packed audit bundle.
 * @param {string} bundlePath
 */
export function verifyAuditBundle(bundlePath) {
  const b = path.resolve(bundlePath);
  const errors = [];
  const warnings = [];
  const required = [
    'security_report.json',
    'city_data_hash.json',
    'mcp_tool_manifest.json',
    'README.md',
    'source_manifest.json',
  ];
  if (!fs.existsSync(b) || !fs.statSync(b).isDirectory()) {
    return { ok: false, errors: ['bundle path is not a directory'], warnings: [], summary: null };
  }
  for (const f of required) {
    if (!fs.existsSync(path.join(b, f))) errors.push(`missing ${f}`);
  }

  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(path.join(b, 'security_report.json'), 'utf8'));
  } catch (e) {
    errors.push('security_report.json unreadable: ' + (e.message || e));
  }

  // City present? rehash if so
  const cityInBundle = path.join(b, 'city-data.json');
  if (fs.existsSync(cityInBundle)) {
    const actual = sha256File(cityInBundle);
    try {
      const listed = JSON.parse(fs.readFileSync(path.join(b, 'city_data_hash.json'), 'utf8'));
      const want = String(listed.city_data_sha256 || '').replace(/^sha256:/, '');
      if (want && actual && want !== actual) errors.push('city-data.json hash mismatch vs city_data_hash.json');
    } catch {
      errors.push('city_data_hash.json unreadable');
    }
    const scan = scanCityArtifactSecrets(cityInBundle);
    if (!scan.ok) errors.push(`secret-like residual in city-data.json (${scan.total})`);
  } else {
    warnings.push('city-data.json not in bundle — hash-only verification');
  }

  // MCP RO tools — forbidden must not appear as allowed map names
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(b, 'mcp_tool_manifest.json'), 'utf8'));
    const allowed = new Set(manifest.map_tools_read_only?.allowed || []);
    for (const bad of ['Write File', 'Delete File', 'Run Commands']) {
      if (allowed.has(bad)) errors.push(`map allowed list contains forbidden: ${bad}`);
    }
    if (!(manifest.map_tools_read_only?.allowed || []).includes('kc_search')) {
      errors.push('map tools missing kc_search');
    }
  } catch (e) {
    errors.push('mcp_tool_manifest.json issue: ' + (e.message || e));
  }

  if (report?.provenance && report.provenance.coverage_percent < 99 && (report.provenance.node_count || 0) > 0) {
    warnings.push(`provenance coverage ${report.provenance.coverage_percent}% < 99%`);
  }

  const ok = errors.length === 0;
  const summary = {
    ok,
    source: report?.source?.root_basename || null,
    mode: report?.mode || null,
    shareable_verdict: report?.share_safe?.shareable_verdict || null,
    risk_level: report?.summary?.risk_level || null,
    city_hash: report?.hashes?.city_data_sha256 || null,
    read_only_map: true,
    errors,
    warnings,
  };

  return { ok, errors, warnings, summary, report };
}

/**
 * Plain English verify lines for CLI.
 * @param {ReturnType<typeof verifyAuditBundle>} result
 */
export function formatVerifyHuman(result) {
  const lines = [];
  lines.push('KnoSky audit verify');
  lines.push(result.ok ? 'RESULT: PASS' : 'RESULT: FAIL');
  if (result.summary) {
    lines.push(`Source basename : ${result.summary.source || 'n/a'}`);
    lines.push(`Mode            : ${result.summary.mode || 'n/a'}`);
    lines.push(`Risk            : ${result.summary.risk_level || 'n/a'}`);
    lines.push(`Share verdict   : ${result.summary.shareable_verdict || 'n/a'}`);
    lines.push(`City hash       : ${result.summary.city_hash || 'n/a'}`);
    lines.push('Map tools       : read-only list OK check applied');
  }
  for (const e of result.errors || []) lines.push('ERROR: ' + e);
  for (const w of result.warnings || []) lines.push('WARN:  ' + w);
  return lines;
}
