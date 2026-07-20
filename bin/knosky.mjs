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
  // Mode B bootstrap: register local agent + mint lease in .knosky domain
  // Elevated classes / secured domains require --operator-token (or KC_OPERATOR_TOKEN).
  // First operator: --bootstrap-operator (prints token once).
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
    const boot = bootstrapOperator(domainRoot, { operatorId: getArgVal('--operator-id') || 'bootstrap-operator' });
    console.log(JSON.stringify({ domain: domainRoot, ...boot }, null, 2));
    process.exit(boot.ok ? 0 : 1);
  }
  const agentId = getArgVal('--agent') || getArgVal('--id') || 'local-agent';
  const domain = loadDomain(domainRoot);
  const classes = (getArgVal('--classes') || 'public,internal').split(',').map(s => s.trim()).filter(Boolean);
  const operatorToken = getArgVal('--operator-token') || process.env.KC_OPERATOR_TOKEN;
  const out = registerAgentWithLease(
    domain,
    { agentId, classes, role: getArgVal('--role') || 'coder' },
    { operatorToken },
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
    hint: 'Pass leaseId to kc_route / kc_policy_check / kc_bundle (Mode B). Elevated classes and secured domains need operatorToken.',
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