// KnoSky doctor scorecard — Mode B + L0–L3 ladder + L3 foundation (DEC-106/108/110/113).
// Honest, plain-English lines. Never claims Windows kernel lockdown when unsupported.
// Pure ESM, Node stdlib.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';
import { probeNetworkLockdownSupport, doctorLines as lockdownDoctorLines } from './net-lockdown.mjs';
import { resolveDomainRoot, loadDomain } from './domain-store.mjs';
import { closedSet, CODES } from './decision-codes.mjs';
import { verifyAuditChain } from './audit-writer.mjs';
import { DEFAULT_SWARM_QUOTAS, swarmPaths, readSwarmHeatmap } from './swarm-coordinator.mjs';
import { resolveRunMode, isEnterpriseMode, capabilityMatrix } from './enterprise-mode.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * @typedef {object} ScoreRow
 * @property {string} id
 * @property {'ok'|'warn'|'fail'|'info'} level
 * @property {string} title
 * @property {string} detail
 */

function mark(level, id, title, detail) {
  return { id, level, title, detail };
}

function emoji(level) {
  if (level === 'ok') return '🟢';
  if (level === 'warn') return '🟡';
  if (level === 'fail') return '🔴';
  return '⚪';
}

/**
 * Load SSOT artifacts from repo root.
 */
export function inspectSsot(repoRoot = ROOT) {
  const menuPath = join(repoRoot, 'ssot', 'tool-menu.json');
  const codesPath = join(repoRoot, 'ssot', 'decision-codes.json');
  const ladderPath = join(repoRoot, 'ssot', 'ladder-l0-l3.md');
  const out = {
    menuPath,
    codesPath,
    ladderPath,
    menuOk: false,
    codesOk: false,
    ladderOk: false,
    tier1: [],
    closed: [],
    errors: [],
  };
  try {
    if (!existsSync(menuPath)) throw new Error('missing tool-menu.json');
    const menu = JSON.parse(readFileSync(menuPath, 'utf8'));
    out.menuOk = true;
    out.tier1 = (menu.tiers?.tier1_governed?.tools || []).map((t) => t.name);
  } catch (e) {
    out.errors.push(String(e.message || e));
  }
  try {
    if (!existsSync(codesPath)) throw new Error('missing decision-codes.json');
    const codes = JSON.parse(readFileSync(codesPath, 'utf8'));
    out.codesOk = true;
    out.closed = codes.closed_set || [];
  } catch (e) {
    out.errors.push(String(e.message || e));
  }
  out.ladderOk = existsSync(ladderPath);
  return out;
}

/**
 * Inspect MCP server source for DEC-108 registration (static honesty).
 */
export function inspectMcpMenu(repoRoot = ROOT) {
  const serverPath = join(repoRoot, 'mcp', 'server.mjs');
  const src = existsSync(serverPath) ? readFileSync(serverPath, 'utf8') : '';
  const need = ['kc_search', 'kc_route', 'kc_bundle', 'kc_policy_check', 'createModeBDoor'];
  const missing = need.filter((t) => !src.includes(t));
  return {
    serverPath,
    present: existsSync(serverPath),
    missing,
    hasModeB: src.includes('createModeBDoor'),
    hasSecurityAudit: src.includes('kc_audit_query'),
  };
}

/**
 * Build structured doctor scorecard.
 * @param {object} [opts]
 * @param {string} [opts.domainRoot]
 * @param {string} [opts.cityPath]
 * @param {string} [opts.repoRoot]
 */
export function buildDoctorScorecard(opts = {}) {
  const repoRoot = opts.repoRoot || ROOT;
  const domainRoot = resolveDomainRoot(opts.cityPath, opts.domainRoot);
  /** @type {ScoreRow[]} */
  const rows = [];

  // --- Platform / F0.5 ---
  const lock = probeNetworkLockdownSupport();
  const plat = platform();
  if (lock.active) {
    rows.push(mark('ok', 'F0.5', 'Network lockdown', 'ACTIVE — process is sandboxed for egress.'));
  } else if (lock.supported && lock.toolAvailable) {
    rows.push(
      mark(
        'warn',
        'F0.5',
        'Network lockdown',
        'Available but NOT active for this process. External egress may still be possible until wrapped.',
      ),
    );
  } else if (plat === 'win32') {
    rows.push(
      mark(
        'warn',
        'F0.5',
        'Network lockdown (Windows)',
        'Not kernel-enforced at runtime on Windows for this CLI. Do NOT claim "no egress guaranteed on Windows". Packaging/AppContainer would be required. ' +
          (lock.unsupportedReason || lock.detail || ''),
      ),
    );
  } else {
    rows.push(
      mark(
        'fail',
        'F0.5',
        'Network lockdown',
        lock.unsupportedReason || lock.detail || 'unsupported',
      ),
    );
  }

  // --- SSOT / DEC-108 ---
  const ssot = inspectSsot(repoRoot);
  if (ssot.menuOk && ssot.codesOk && ssot.ladderOk) {
    rows.push(
      mark(
        'ok',
        'SSOT',
        'Protocol freeze files',
        `tool-menu + decision-codes + ladder present. Tier1: ${ssot.tier1.join(', ') || '(none)'}`,
      ),
    );
  } else {
    rows.push(
      mark(
        'fail',
        'SSOT',
        'Protocol freeze files',
        `Incomplete SSOT under ${join(repoRoot, 'ssot')}: ${ssot.errors.join('; ') || 'ladder missing'}`,
      ),
    );
  }

  let codesRuntimeOk = true;
  try {
    const set = closedSet();
    for (const c of ['ALLOW', 'DENY_IDENTITY', 'ADVISORY_UNAUTH', CODES.DENY_POLICY]) {
      if (!set.includes(c)) codesRuntimeOk = false;
    }
    rows.push(
      codesRuntimeOk
        ? mark('ok', 'CODES', 'Decision codes runtime', `Closed set size ${set.length}; core codes present.`)
        : mark('fail', 'CODES', 'Decision codes runtime', 'Closed set missing required codes.'),
    );
  } catch (e) {
    rows.push(mark('fail', 'CODES', 'Decision codes runtime', String(e.message || e)));
  }

  const mcp = inspectMcpMenu(repoRoot);
  if (mcp.present && mcp.missing.length === 0 && mcp.hasModeB) {
    rows.push(
      mark(
        'ok',
        'MCP',
        'Mode B front door wiring',
        'mcp/server.mjs registers Tier0+Tier1 and Mode B door. Defaults are non-authorizing until lease+policy ALLOW.',
      ),
    );
  } else if (!mcp.present) {
    rows.push(mark('fail', 'MCP', 'Mode B front door wiring', 'mcp/server.mjs missing'));
  } else {
    rows.push(
      mark(
        'fail',
        'MCP',
        'Mode B front door wiring',
        `Missing markers: ${mcp.missing.join(', ') || 'Mode B'}`,
      ),
    );
  }

  // --- Domain / Mode B readiness ---
  try {
    const domain = loadDomain(domainRoot);
    const leaseN = domain.leaseStore.size;
    const agentN = Object.keys(domain.agents || {}).length;
    const requireId = domain.policy?.require_identity !== false;
    rows.push(
      mark(
        leaseN > 0 ? 'ok' : 'warn',
        'MODEB-LEASES',
        'Local trust domain leases',
        leaseN > 0
          ? `Domain ${domainRoot}: ${agentN} agent(s), ${leaseN} lease(s). Mode B routes can bind identity.`
          : `Domain ${domainRoot}: no leases yet. Run: knosky agent-register --agent <id>. Coding profile Mode B will DENY_IDENTITY until then (or use KC_PROFILE=advisory for labeled map-only). require_identity=${requireId}`,
      ),
    );

    const audit = verifyAuditChain(domainRoot);
    if (audit.ok) {
      rows.push(
        mark(
          audit.count > 0 ? 'ok' : 'info',
          'MODEB-AUDIT',
          'Audit ledger chain',
          audit.count > 0
            ? `Hash chain OK (${audit.count} event(s)).`
            : 'No audit events yet — chain OK (empty). First Mode B call will write receipts.',
        ),
      );
    } else {
      rows.push(
        mark('fail', 'MODEB-AUDIT', 'Audit ledger chain', `Verify failed: ${audit.reason || 'unknown'} @${audit.at}`),
      );
    }
  } catch (e) {
    rows.push(mark('fail', 'MODEB-DOMAIN', 'Local trust domain', String(e.message || e)));
  }

  // --- L0–L3 ladder honesty ---
  const claimTips = [];
  claimTips.push('L0 local map: OK to claim when city is local-only and default install does not upload source.');
  claimTips.push('L1 share-safe: OK only after share-safe indexer / secret scan path you actually ran.');
  claimTips.push('L2 governed: OK only when Mode B ALLOW path has identity+policy+audit for that install.');
  claimTips.push(
    'L3 swarm: FOUNDATION present (coordinator module). Do NOT market full production “swarm-safe fleet” until remaining polish/benchmarks/red-team gates land.',
  );
  rows.push(mark('info', 'LADDER', 'L0–L3 claim ceiling', claimTips.join(' | ')));

  // --- L3 foundation ---
  try {
    const sp = swarmPaths(domainRoot);
    const heat = readSwarmHeatmap(domainRoot);
    const hasCoord = existsSync(join(repoRoot, 'core', 'swarm-coordinator.mjs'));
    if (!hasCoord) {
      rows.push(mark('fail', 'L3', 'Swarm coordinator module', 'core/swarm-coordinator.mjs missing'));
    } else {
      rows.push(
        mark(
          'ok',
          'L3-MOD',
          'Swarm coordinator module',
          `Foundation present. Default quotas: claims≤${DEFAULT_SWARM_QUOTAS.maxClaimsPerAgent}, actions/window≤${DEFAULT_SWARM_QUOTAS.maxActionsPerWindow}, antiProbe≥${DEFAULT_SWARM_QUOTAS.antiProbeDenyThreshold}. Fairness=FIFO wait when enableFifoWait.`,
        ),
      );
      if (heat.ok) {
        rows.push(
          mark(
            'ok',
            'L3-HEAT',
            'Swarm heatmap',
            `Readable at ${sp.heatmapPath}. Use: knosky swarm status`,
          ),
        );
      } else {
        rows.push(
          mark(
            'info',
            'L3-HEAT',
            'Swarm heatmap',
            `No heatmap yet under ${sp.heatmapPath}. Run knosky swarm status to write a fresh snapshot.`,
          ),
        );
      }
    }
  } catch (e) {
    rows.push(mark('warn', 'L3', 'Swarm coordinator', String(e.message || e)));
  }

  // --- Enterprise / Regulated profile (DEC-118) ---
  {
    const mode = resolveRunMode({ envMode: process.env.KC_MODE });
    const cfgCandidates = [join(domainRoot, 'config.yml'), join(domainRoot, '.knosky', 'config.yml')];
    let cfgMode = null;
    let cfgPath = null;
    try {
      for (const c of cfgCandidates) {
        if (existsSync(c)) { cfgPath = c; break; }
      }
      if (cfgPath) {
        const txt = readFileSync(cfgPath, 'utf8');
        const m = txt.match(/^mode:\s*(\w+)/m);
        if (m) cfgMode = m[1];
      }
    } catch { /* ignore */ }
    const effective = cfgMode || mode;
    if (isEnterpriseMode(effective) || isEnterpriseMode(mode)) {
      rows.push(
        mark(
          'ok',
          'ENT-MODE',
          'Enterprise / Regulated mode',
          `Profile active (mode=${effective}). Safer defaults: share-safe, fail-closed secrets, RO map honesty, security report path.`,
        ),
      );
      const secReport = [join(domainRoot, 'security-report.json'), join(domainRoot, '.knosky', 'security-report.json')].find((p) => existsSync(p));
      if (secReport) {
        rows.push(mark('ok', 'ENT-SEC', 'Security report', `Present at ${secReport}`));
      } else {
        rows.push(
          mark(
            'warn',
            'ENT-SEC',
            'Security report',
            'No security-report.json yet. Run: knosky enterprise . --no-serve  (or regulated)',
          ),
        );
      }
      const matrix = capabilityMatrix();
      rows.push(
        mark(
          'info',
          'ENT-RO',
          'Map tools read-only guarantee',
          `Allowed: ${matrix.map_tools_read_only.allowed.join(', ')}. Mode B is separate: ${matrix.mode_b_governed.tools.join(', ')}.`,
        ),
      );
    } else {
      rows.push(
        mark(
          'info',
          'ENT-MODE',
          'Enterprise / Regulated mode',
          'Not active (casual). Enable with: knosky enterprise .   Claims for regulated pilots should use enterprise profile.',
        ),
      );
    }
  }

  // --- Telemetry constitution ---
  rows.push(
    mark(
      'ok',
      'METRICS',
      'Telemetry posture',
      'Default: no always-on product telemetry. Adoption metrics = opt-in / survey / public benchmarks only (DEC-114).',
    ),
  );

  // --- Packs presence ---
  const packsRoot = join(repoRoot, 'packs');
  if (existsSync(packsRoot)) {
    rows.push(
      mark(
        'ok',
        'PACKS',
        'Consumer packs tree',
        'packs/ present (Hermes/Claude/Cursor/Codex + P1 stubs). Run pack smoke tests before release.',
      ),
    );
  } else {
    rows.push(mark('warn', 'PACKS', 'Consumer packs tree', 'packs/ missing'));
  }

  const summary = {
    ok: rows.filter((r) => r.level === 'ok').length,
    warn: rows.filter((r) => r.level === 'warn').length,
    fail: rows.filter((r) => r.level === 'fail').length,
    info: rows.filter((r) => r.level === 'info').length,
  };

  return {
    version: '1.0.0',
    platform: plat,
    domainRoot,
    repoRoot,
    lockdown: lock,
    summary,
    rows,
  };
}

/**
 * Human lines for CLI `knosky doctor`.
 * @param {object} [opts]
 * @returns {string[]}
 */
export function doctorScorecardLines(opts = {}) {
  const card = buildDoctorScorecard(opts);
  const lines = [];
  lines.push('KnoSky doctor — scorecard (Mode B · Enterprise · ladder · L3 foundation · sandbox)');
  lines.push('');
  lines.push(
    `Summary: ${card.summary.ok} ok · ${card.summary.warn} warn · ${card.summary.fail} fail · ${card.summary.info} info`,
  );
  lines.push(`Domain : ${card.domainRoot}`);
  lines.push(`OS     : ${card.platform}`);
  lines.push('');

  // Keep classic F0.5 lines for continuity
  lines.push('--- F0.5 lockdown (classic) ---');
  for (const l of lockdownDoctorLines()) lines.push(l);
  lines.push('');

  lines.push('--- Scorecard ---');
  for (const r of card.rows) {
    lines.push(`${emoji(r.level)} [${r.id}] ${r.title}`);
    lines.push(`   ${r.detail}`);
  }
  lines.push('');
  lines.push('Hints:');
  lines.push('  knosky agent-register --agent <id>     # mint Mode B lease');
  lines.push('  knosky swarm status                    # L3 heatmap snapshot');
  lines.push('  KC_PROFILE=coding|advisory|security    # MCP profile');
  lines.push('  Claims: never call Mode A “authorized”; never claim Windows no-egress if scorecard warns.');
  lines.push('  knosky enterprise . --no-serve           # Enterprise Mode + security report');
  lines.push('  knosky audit pack | audit verify <dir>   # portable audit bundle');
  return lines;
}

/** CLI exit code: 0 if no fail rows, 2 if any fail. */
export function doctorExitCode(card) {
  return card.summary.fail > 0 ? 2 : 0;
}
