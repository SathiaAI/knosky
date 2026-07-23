#!/usr/bin/env node
// KnoSky one-command launcher: index a folder -> build the city -> open it ->
// print the MCP config + first prompts -> start the local MCP server.
// Reuses the verified core/renderer/mcp scripts as child processes (no new logic to trust).
//
//   npx knosky [path]            # default: current folder
//   npx knosky . --no-open       # don't auto-open the browser
//   npx knosky . --no-serve      # build + print config, don't start the MCP server
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const argv = process.argv.slice(2);
const flags = new Set(argv.filter(a => a.startsWith('--')));
const NODE = process.execPath;
const subcommand = argv.find(a => !a.startsWith('--'));

// ---------------------------------------------------------------------------
// doctor subcommand: surface security/sandbox status for operator review (F0.5)
// Dispatched BEFORE `target` is resolved (PR #60 Architect finding): `target`
// used to be computed unconditionally first, so `knosky doctor` would resolve
// 'doctor' as a filesystem path -- harmless only because this branch exits
// before `target` is ever read. Reordered so that stays true by construction.
// ---------------------------------------------------------------------------
if (subcommand === 'agent-register') {
  // Mode B: register local agent + mint lease in .knosky domain.
  // Elevated classes require TWO operator tokens (quorum).
  // Bootstrap: --bootstrap-operator prints operator-a only; operator-b to 0600 file.
  const { loadDomain, registerAgentWithLease, resolveDomainRoot } = await import('../core/domain-store.mjs');
  const { bootstrapOperator } = await import('../core/operator-auth.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const domainRoot = resolveDomainRoot(undefined, getArgVal('--domain'));
  if (flags.has('--bootstrap-operator')) {
    if (flags.has('--allow-single-operator')) {
      console.error(JSON.stringify({
        ok: false,
        reason: 'allow_single_operator_disabled_for_elevated_guarantee',
        next_action: 'Use dual bootstrap (default). Single-op cannot elevate classes; dual is required for Rule-3 quorum. If you truly need a single identity for public/internal only domain explore later via addOperator.',
      }, null, 2));
      process.exit(2);
    }
    const boot = bootstrapOperator(domainRoot, {
      operatorId: getArgVal('--operator-id') || 'operator-a',
      operatorId2: getArgVal('--operator-id-2') || 'operator-b',
    });
    // Dual separation: only operator-a raw token on stdout.
    // operator-b is file-only (tokenFileB path + fingerprint in response — not its secret).
    console.log(JSON.stringify({
      domain: domainRoot,
      ok: boot.ok,
      mode: boot.mode,
      reason: boot.reason,
      operatorId: boot.operatorId,
      operatorToken: boot.operatorToken,
      fingerprint: boot.fingerprint,
      operatorId2: boot.operatorId2,
      fingerprint2: boot.fingerprint2,
      tokenFileB: boot.tokenFileB,
      tokenB_delivery: boot.tokenB_delivery,
      warning: boot.warning,
    }, null, 2));
    process.exit(boot.ok ? 0 : 1);
  }
  const agentId = getArgVal('--agent') || getArgVal('--id') || 'local-agent';
  const domain = loadDomain(domainRoot);
  const classes = (getArgVal('--classes') || 'public,internal').split(',').map(s => s.trim()).filter(Boolean);
  // Flag names are plain CLI text. Token values come only from argv/env (never hardcoded).
  const operatorToken = getArgVal('--operator-token') || process.env.KC_OPERATOR_TOKEN;
  const operatorToken2 = getArgVal('--operator-token-2') || process.env.KC_OPERATOR_TOKEN_2;
  const out = registerAgentWithLease(
    domain,
    { agentId, classes, role: getArgVal('--role') || 'coder' },
    { operatorToken, operatorToken2 },
  );
  if (!out.ok) {
    console.error(JSON.stringify({ domain: domainRoot, ...out }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    ok: true,
    domain: domainRoot,
    agentId: out.agentId,
    leaseId: out.leaseId,
    hint: 'Pass leaseId to kc_route / kc_policy_check / kc_bundle (Mode B). Elevated classes need --operator-token AND --operator-token-2 (quorum).',
  }, null, 2));
  process.exit(0);
}

if (subcommand === 'doctor') {
  const { doctorScorecardLines, buildDoctorScorecard, doctorExitCode } = await import('../core/doctor-scorecard.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const domain = getArgVal('--domain');
  const city = getArgVal('--city');
  const json = flags.has('--json');
  const card = buildDoctorScorecard({ domainRoot: domain, cityPath: city });
  if (json) {
    console.log(JSON.stringify(card, null, 2));
  } else {
    console.log('');
    for (const line of doctorScorecardLines({ domainRoot: domain, cityPath: city })) console.log(line);
    console.log('');
  }
  process.exit(doctorExitCode(card));
}


// ---------------------------------------------------------------------------
// enterprise | regulated — named profile + share-safe index + security report
//   knosky enterprise [path] [--no-open] [--no-serve] [--audit-pack]
//   knosky regulated  [path] ...
// ---------------------------------------------------------------------------
if (subcommand === 'enterprise' || subcommand === 'regulated') {
  const modeName = subcommand;
  const { writeEnterpriseConfigStub, capabilityMatrix } = await import('../core/enterprise-mode.mjs');
  const { buildSecurityReport, writeSecurityReportFiles, scanCityArtifactSecrets } = await import('../core/security-report.mjs');
  const { packAuditBundle } = await import('../core/audit-bundle.mjs');
  const { checkCityFreshness } = await import('../core/ro-guarantee.mjs');

  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };

  const pos = argv.filter(a => !a.startsWith('--') && a !== subcommand);
  const target = path.resolve(pos[0] || '.');
  if (!fs.existsSync(target)) { console.error('KnoSky: path not found: ' + target); process.exit(1); }

  const stub = writeEnterpriseConfigStub(target, modeName === 'regulated' ? 'regulated' : 'enterprise');
  console.log('');
  console.log('KnoSky ' + modeName + ' mode');
  console.log(stub.created ? ('  wrote ' + stub.path) : ('  ' + stub.note));

  const outDir = path.join(target, '.knosky');
  fs.mkdirSync(outDir, { recursive: true });
  const cityJson = path.join(outDir, 'city-data.json');
  const cityHtml = path.join(outDir, 'city.html');
  const run = (script, args) => spawnSync(NODE, [path.join(ROOT, script), ...args], { stdio: 'inherit' });

  console.log('');
  console.log('KnoSky -> indexing (share-safe) ' + target);
  let r = run('core/fs-indexer.mjs', ['--root', target, '--out', cityJson, '--share-safe']);
  if (r.status !== 0) {
    console.error('');
    console.error('KnoSky enterprise: indexing blocked or failed (fail-closed). Security report not written.');
    process.exit(r.status || 1);
  }

  r = run('renderer/build-rich.mjs', [cityJson, cityHtml]);
  if (r.status !== 0) { console.error(''); console.error('KnoSky: building the city failed.'); process.exit(1); }

  let cityObj = null;
  try { cityObj = JSON.parse(fs.readFileSync(cityJson, 'utf8')); } catch { cityObj = null; }
  const residual = scanCityArtifactSecrets(cityJson);
  const report = buildSecurityReport({
    root: target,
    cityPath: cityJson,
    city: cityObj,
    mode: modeName,
    shareSafe: true,
    absolutePaths: false,
    secretsResidual: residual.total,
    secretKinds: residual.kinds,
  });
  const written = writeSecurityReportFiles(outDir, report);
  console.log('');
  console.log('Security report: ' + written.jsonPath);
  console.log('Summary:        ' + written.mdPath);
  console.log('Share verdict:  ' + report.share_safe.shareable_verdict);
  console.log('Risk:           ' + report.summary.risk_level);
  console.log('Provenance:     ' + report.provenance.coverage_percent + '%');

  const fresh = checkCityFreshness({ city: cityObj, root: target });
  if (fresh.stale) {
    console.log('Freshness:      STALE — ' + (fresh.issues || []).join(', '));
    console.log('               ' + fresh.advice);
  } else {
    console.log('Freshness:      OK');
  }

  const matrixPath = path.join(outDir, 'mcp-capability-matrix.json');
  fs.writeFileSync(matrixPath, JSON.stringify(capabilityMatrix(), null, 2) + '\n');
  console.log('MCP matrix:     ' + matrixPath);

  if (flags.has('--audit-pack')) {
    const pack = packAuditBundle({ root: target, mode: modeName });
    if (pack.ok) console.log('Audit bundle:   ' + pack.bundleDir);
    else console.error('Audit pack failed: ' + (pack.reason || 'unknown'));
  }

  if (!flags.has('--no-open')) {
    const isWin = process.platform === 'win32', isMac = process.platform === 'darwin';
    const cmd = isWin ? 'cmd' : isMac ? 'open' : 'xdg-open';
    const a = isWin ? ['/c', 'start', '', cityHtml] : [cityHtml];
    try { spawn(cmd, a, { detached: true, stdio: 'ignore' }).unref(); } catch (_) {}
  }

  const mcpServer = path.join(ROOT, 'mcp', 'server.mjs');
  console.log('');
  console.log('  City:  ' + cityHtml);
  console.log('Connect (Enterprise Mode — map tools are read-only navigation):');
  console.log('  claude mcp add knosky -e KC_CITY="' + cityJson + '" -e KC_MODE="' + modeName + '" -- node "' + mcpServer + '"');
  console.log('');
  console.log('Next: knosky doctor --city "' + cityJson + '"');
  console.log('      knosky audit pack --root "' + target + '"');
  console.log('      knosky audit verify <bundleDir>');
  if (!flags.has('--no-serve')) {
    console.log('');
    console.log('Starting local MCP (Ctrl+C to stop)...');
    console.log('');
    const child = spawn(NODE, [mcpServer], {
      stdio: 'inherit',
      env: { ...process.env, KC_CITY: cityJson, KC_MODE: modeName },
    });
    child.on('exit', (code) => process.exit(code || 0));
  } else {
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
// audit pack | audit verify
//   knosky audit pack  [--root path] [--out dir]
//   knosky audit verify <bundleDir>
// ---------------------------------------------------------------------------
if (subcommand === 'audit') {
  const { packAuditBundle, verifyAuditBundle, formatVerifyHuman } = await import('../core/audit-bundle.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const action = argv.find((a, i) => i > 0 && !a.startsWith('--') && a !== 'audit') || 'pack';
  if (action === 'pack') {
    const root = path.resolve(getArgVal('--root') || '.');
    const out = getArgVal('--out');
    const pack = packAuditBundle({ root, outDir: out, mode: getArgVal('--mode') });
    console.log(JSON.stringify(pack, null, 2));
    process.exit(pack.ok ? 0 : 1);
  }
  if (action === 'verify') {
    const bundle = argv.find((a, i) => i > 0 && !a.startsWith('--') && a !== 'audit' && a !== 'verify') || getArgVal('--bundle');
    if (!bundle) {
      console.error('Usage: knosky audit verify <bundleDir>');
      process.exit(2);
    }
    const result = verifyAuditBundle(bundle);
    if (flags.has('--json')) console.log(JSON.stringify(result, null, 2));
    else for (const line of formatVerifyHuman(result)) console.log(line);
    process.exit(result.ok ? 0 : 1);
  }
  console.error('KnoSky audit: unknown action "' + action + '". Try: knosky audit pack | knosky audit verify <dir>');
  process.exit(2);
}


// ---------------------------------------------------------------------------
// adversarial | gauntlet — private multi-model synthetic gauntlet (DEC-119 Phase 2)
//   knosky adversarial run [--out dir] [--only id1,id2] [--llm]
//   knosky adversarial list
//   knosky gauntlet ...  (alias)
// ---------------------------------------------------------------------------
if (subcommand === 'adversarial' || subcommand === 'gauntlet') {
  const {
    runGauntlet,
    listScenarios,
    formatGauntletMarkdown,
  } = await import('../core/adversarial-gauntlet.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const action = argv.find((a, i) => i > 0 && !a.startsWith('--') && a !== 'adversarial' && a !== 'gauntlet') || 'run';
  if (action === 'list') {
    console.log(JSON.stringify({ scenarios: listScenarios() }, null, 2));
    process.exit(0);
  }
  if (action === 'run') {
    const onlyRaw = getArgVal('--only');
    const only = onlyRaw ? onlyRaw.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
    const outDir = getArgVal('--out');
    const llm = flags.has('--llm');
    const rollup = await runGauntlet({ outDir, only, llm });
    if (flags.has('--json')) {
      console.log(JSON.stringify(rollup, null, 2));
    } else {
      console.log(formatGauntletMarkdown(rollup));
      console.log('');
      console.log('Artifacts: ' + rollup.outDir);
      console.log(rollup.green ? 'PRIVATE GREEN' : 'NOT GREEN — fix before attack-tested claims');
    }
    process.exit(rollup.green ? 0 : 1);
  }
  console.error('KnoSky adversarial: try  knosky adversarial list | knosky adversarial run [--only id] [--llm] [--out dir]');
  process.exit(2);
}


// ---------------------------------------------------------------------------
// intel — architecture intelligence (ENT Phase 3)
//   knosky intel [path] [--prior file] [--json]
// ---------------------------------------------------------------------------
if (subcommand === 'intel') {
  const { runArchitectureIntel, formatArchitectureIntelMarkdown } = await import('../core/architecture-intel.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const pos = argv.filter(a => !a.startsWith('--') && a !== 'intel');
  const root = path.resolve(pos[0] || '.');
  const out = runArchitectureIntel({
    root,
    cityPath: getArgVal('--city'),
    priorPath: getArgVal('--prior'),
    mode: getArgVal('--mode') || 'enterprise',
  });
  if (!out.ok) {
    console.error(JSON.stringify(out, null, 2));
    process.exit(1);
  }
  if (flags.has('--json')) {
    console.log(JSON.stringify(out.report, null, 2));
  } else {
    console.log(formatArchitectureIntelMarkdown(out.report));
    console.log('');
    console.log('Wrote: ' + out.mdPath);
    console.log('       ' + out.jsonPath);
    console.log(out.prior_used ? 'Drift: prior snapshot compared' : 'Drift: no usable prior yet (next run will baseline)');
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// swarm subcommand: L3 operator heatmap / status (DEC-113 thin floor)
//   knosky swarm status [--domain <path>]
//   knosky swarm bench  [--domain <path>]
// ---------------------------------------------------------------------------
if (subcommand === 'swarm') {
  const { readSwarmHeatmap, createSwarmCoordinator } = await import('../core/swarm-coordinator.mjs');
  const { resolveDomainRoot } = await import('../core/domain-store.mjs');
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
    return undefined;
  };
  const action = argv.find((a, i) => i > 0 && !a.startsWith('--') && a !== 'swarm') || 'status';
  const domainRoot = resolveDomainRoot(getArgVal('--city'), getArgVal('--domain'));

  if (action === 'status') {
    let out = readSwarmHeatmap(domainRoot);
    if (!out.ok) {
      // Build a live snapshot so status is useful before any swarm traffic.
      const coord = createSwarmCoordinator({ domainRoot });
      const wr = coord.writeHeatmap();
      out = { ok: true, path: wr.path, domainRoot, heatmap: wr.snapshot, note: 'fresh_snapshot' };
    }
    console.log(JSON.stringify(out, null, 2));
    process.exit(out.ok ? 0 : 1);
  }

  if (action === 'bench') {
    const { runSwarmBench } = await import('../core/swarm-bench.mjs');
    const out = runSwarmBench({ domainRoot });
    console.log(JSON.stringify(out, null, 2));
    process.exit(out.ok ? 0 : 1);
  }

  console.error('KnoSky swarm: unknown action "' + action + '". Try: knosky swarm status | knosky swarm bench');
  process.exit(2);
}

// ---------------------------------------------------------------------------
// ci subcommand: generate PR-GPS advisory artifacts (advisory, never breaks builds)
// ---------------------------------------------------------------------------
if (subcommand === 'ci') {
  const { knoskyCi } = await import('../core/ci.mjs');

  // Resolve a named flag's value from argv. Supports --flag=value and --flag value.
  const getArgVal = (name) => {
    const prefix = name + '=';
    const eq = argv.find(a => a.startsWith(prefix));
    if (eq !== undefined) return eq.slice(prefix.length);
    const idx = argv.indexOf(name);
    if (idx !== -1 && idx + 1 < argv.length && !argv[idx + 1].startsWith('--')) {
      return argv[idx + 1];
    }
    return undefined;
  };

  const ciBase = getArgVal('--base');
  const ciHead = getArgVal('--head');
  const ciCity = getArgVal('--city');
  const ciFailOnSecret = flags.has('--fail-on-secret');

  const { exitCode, summaryMd, routeJson, safetyJson } = await knoskyCi({
    root: process.cwd(),
    base: ciBase,
    head: ciHead,
    cityPath: ciCity,
    failOnSecret: ciFailOnSecret,
  });

  fs.writeFileSync('knosky-pr-summary.md', summaryMd, 'utf8');
  fs.writeFileSync('knosky-pr-route.json', JSON.stringify(routeJson, null, 2) + '\n', 'utf8');
  fs.writeFileSync('knosky-safety-report.json', JSON.stringify(safetyJson, null, 2) + '\n', 'utf8');

  console.log(summaryMd);
  process.exit(exitCode);
}

// Main path (index -> build -> open -> serve): resolve the target folder only
// here, after both early-exit subcommands, so a subcommand name is never
// mistaken for a path.
const target = path.resolve(subcommand || '.');

if (!fs.existsSync(target)) { console.error('KnoSky: path not found: ' + target); process.exit(1); }

const outDir = path.join(target, '.knosky');
fs.mkdirSync(outDir, { recursive: true });
const cityJson = path.join(outDir, 'city-data.json');
const cityHtml = path.join(outDir, 'city.html');

const run = (script, args) => spawnSync(NODE, [path.join(ROOT, script), ...args], { stdio: 'inherit' });

console.log('\nKnoSky -> indexing ' + target);
let r = run('core/fs-indexer.mjs', ['--root', target, '--out', cityJson, '--share-safe']);
if (r.status !== 0) { console.error('\nKnoSky: indexing was blocked or failed (see above). Nothing was opened.'); process.exit(r.status || 1); }

r = run('renderer/build-rich.mjs', [cityJson, cityHtml]);
if (r.status !== 0) { console.error('\nKnoSky: building the city failed.'); process.exit(1); }

if (!flags.has('--no-open')) {
  const isWin = process.platform === 'win32', isMac = process.platform === 'darwin';
  const cmd = isWin ? 'cmd' : isMac ? 'open' : 'xdg-open';
  const a = isWin ? ['/c', 'start', '', cityHtml] : [cityHtml];
  try { spawn(cmd, a, { detached: true, stdio: 'ignore' }).unref(); } catch (_) {}
}

const mcpServer = path.join(ROOT, 'mcp', 'server.mjs');
const cfg = JSON.stringify({ mcpServers: { knosky: { command: 'node', args: [mcpServer], env: { KC_CITY: cityJson } } } }, null, 2);

console.log('\n  City:  ' + cityHtml);
console.log('\nConnect your AI assistant so it answers from THIS repo, with citations.');
console.log('Claude Code:');
console.log('  claude mcp add knosky -e KC_CITY="' + cityJson + '" -- node "' + mcpServer + '"');
console.log('\nClaude Desktop / Cursor / VS Code MCP config:');
console.log(cfg.split('\n').map(l => '  ' + l).join('\n'));
console.log('\nThen try one of these to see the loop (grounded, cited answers):');
console.log('  - "Using KnoSky, where does authentication live in this repo?"');
console.log('  - "Using KnoSky, what are the entry points of this project?"');
console.log('  - "Using KnoSky, which files should I read to understand billing?"');

if (flags.has('--no-serve')) {
  console.log('\n(--no-serve) Not starting the MCP server. Run it later with:');
  console.log('  KC_CITY="' + cityJson + '" node "' + mcpServer + '"\n');
  process.exit(0);
}

console.log('\nStarting the local MCP server (Ctrl+C to stop)...\n');
// F0.5: place the evaluator-facing MCP server inside the OS-level network
// lockdown when the platform supports it (core/net-lockdown.mjs).
// PR #60 Architect finding: this import must not be allowed to crash the CLI
// (or worse, silently degrade) if net-lockdown.mjs is ever missing/broken --
// explicitly caught, always warned, same fallback path as "tool not found".
let _lockdownPrefix = [];
try {
  const { wrapArgsForLockdown } = await import('../core/net-lockdown.mjs');
  _lockdownPrefix = wrapArgsForLockdown();
} catch (err) {
  console.error(
    'KnoSky: could not load the network lockdown module (' + (err?.message || err) + ') '
    + '-- MCP server will run WITHOUT the network lockdown.'
  );
}
if (_lockdownPrefix.length === 0) {
  // PR #60 QA finding: don't silently run unwrapped -- tell the operator.
  console.error(
    'KnoSky: no OS-level network sandbox available on this platform/environment '
    + '(sandbox-exec/unshare not found) -- MCP server will run WITHOUT the network '
    + 'lockdown. Run `knosky doctor` for details.'
  );
}
const mcp = _lockdownPrefix.length
  ? spawn(_lockdownPrefix[0], [..._lockdownPrefix.slice(1), NODE, mcpServer, cityJson], { stdio: 'inherit' })
  : spawn(NODE, [mcpServer, cityJson], { stdio: 'inherit' });
mcp.on('exit', c => process.exit(c || 0));
process.on('SIGINT', () => { try { mcp.kill(); } catch (_) {} process.exit(0); });