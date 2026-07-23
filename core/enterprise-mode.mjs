// KnoSky Enterprise / Regulated Mode profile (DEC-118, FR-KS-ENT-101+)
// Pure ESM, Node stdlib. Named profile — not a product fork.

import fs from 'node:fs';
import path from 'node:path';

/** @typedef {'casual'|'enterprise'|'regulated'} KnoskyRunMode */

export const ENTERPRISE_MODES = Object.freeze(['enterprise', 'regulated']);

/** Defaults applied when enterprise/regulated profile is active. */
export const ENTERPRISE_DEFAULTS = Object.freeze({
  knosky_protocol: '1.0',
  mode: 'enterprise',
  visibility_mode: 'local_user_only', // shared ACL = later FR-113 path
  telemetry: false,
  absolute_paths: false,
  fail_on_secret: true,
  allow_excerpts: true,
  max_excerpt_chars: 500,
  share_safe: true,
  strip_usernames: true,
  mcp_read_only_map: true,
  allow_external_network: false,
  write_tools_enabled: false,
  security_report: true,
  audit_bundle_on_index: false, // opt-in; pack via CLI
  provenance_required: true,
  stale_check: true,
  categories: [],
  ignore: [],
});

export const REGULATED_DEFAULTS = Object.freeze({
  ...ENTERPRISE_DEFAULTS,
  mode: 'regulated',
  // Same safety floor; name signals regulated-org packaging.
});

/**
 * Resolve run mode from env / cli / config.
 * @param {object} [opts]
 * @param {string} [opts.cliMode]
 * @param {string} [opts.envMode]
 * @param {Record<string, unknown>} [opts.config]
 * @returns {KnoskyRunMode}
 */
export function resolveRunMode(opts = {}) {
  const raw = String(
    opts.cliMode || opts.envMode || process.env.KC_MODE || opts.config?.mode || 'casual',
  )
    .trim()
    .toLowerCase();
  if (raw === 'enterprise' || raw === 'ent') return 'enterprise';
  if (raw === 'regulated' || raw === 'reg') return 'regulated';
  return 'casual';
}

export function isEnterpriseMode(mode) {
  return mode === 'enterprise' || mode === 'regulated';
}

/**
 * Merge enterprise defaults over casual config when mode is enterprise/regulated.
 * @param {KnoskyRunMode} mode
 * @param {Record<string, unknown>} [base]
 */
export function applyEnterpriseProfile(mode, base = {}) {
  if (!isEnterpriseMode(mode)) {
    return { ...base, mode: 'casual' };
  }
  const floor = mode === 'regulated' ? REGULATED_DEFAULTS : ENTERPRISE_DEFAULTS;
  return {
    ...floor,
    ...base,
    mode,
    // Non-negotiables on enterprise profile (cannot be relaxed by partial yaml)
    telemetry: false,
    fail_on_secret: true,
    absolute_paths: false,
    share_safe: true,
    mcp_read_only_map: true,
    write_tools_enabled: false,
    allow_external_network: false,
    security_report: true,
    provenance_required: true,
  };
}

/**
 * Write a starter .knosky/config.yml for enterprise mode (idempotent if absent).
 * @param {string} projectRoot
 * @param {'enterprise'|'regulated'} [mode]
 */
export function writeEnterpriseConfigStub(projectRoot, mode = 'enterprise') {
  const dir = path.join(projectRoot, '.knosky');
  fs.mkdirSync(dir, { recursive: true });
  const cfgPath = path.join(dir, 'config.yml');
  if (fs.existsSync(cfgPath)) {
    return { ok: true, path: cfgPath, created: false, note: 'config.yml already exists — left untouched' };
  }
  const body = `# KnoSky ${mode} profile (DEC-118)
# Local-first. Fail-closed on secret-like values when sharing.
# visibility_mode: local_user_only | team_acl | enterprise_acl
knosky_protocol: "1.0"
mode: ${mode}
visibility_mode: local_user_only
telemetry: false
absolute_paths: false
fail_on_secret: true
allow_excerpts: true
max_excerpt_chars: 500
share_safe: true
strip_usernames: true
mcp_read_only_map: true
write_tools_enabled: false
allow_external_network: false
security_report: true
provenance_required: true
stale_check: true
categories: []
ignore: []
`;
  fs.writeFileSync(cfgPath, body, 'utf8');
  return { ok: true, path: cfgPath, created: true };
}

/**
 * Capability matrix: map tools RO vs Mode B vs forbidden.
 * Machine + human (FR-KS-ENT-107).
 */
export function capabilityMatrix() {
  return {
    version: '1.0.0',
    updated: '2026-07-23',
    map_tools_read_only: {
      allowed: [
        'kc_search',
        'kc_get_node',
        'kc_list_categories',
        'kc_get_provenance',
        'kc_related',
      ],
      guarantees: [
        'Do not write or delete workspace files',
        'Do not execute shell commands',
        'Do not open arbitrary network connections for retrieval',
        'Do not read outside indexed root (path traversal denied)',
        'Not a Mode B authorization — navigation / citation only',
      ],
    },
    mode_b_governed: {
      tools: ['kc_route', 'kc_bundle', 'kc_policy_check'],
      note: 'Identity + policy + audit. Decisions and pointer bundles — not silent full-repo writers.',
    },
    forbidden_as_map_tools: [
      'Write File',
      'Delete File',
      'Run Commands',
      'External Network Calls for body exfil',
      'Read Outside Indexed Root',
      'Return Raw File Bodies When Disabled',
    ],
    dual_table_honesty:
      'Map RO guarantee ≠ Mode B. Do not claim Mode B is "just search." Do not claim L3 swarm-safe fleet from foundation alone.',
  };
}
