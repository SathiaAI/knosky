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
const target = path.resolve(argv.find(a => !a.startsWith('--')) || '.');
const NODE = process.execPath;

// --verify-airgap: prove KnoSky makes zero network calls (no target needed).
if (flags.has('--verify-airgap')) {
  const v = spawnSync(NODE, [path.join(ROOT, 'test/verify-airgap.mjs')], { cwd: ROOT, stdio: 'inherit' });
  process.exit(v.status == null ? 1 : v.status);
}

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
const mcp = spawn(NODE, [mcpServer, cityJson], { stdio: 'inherit' });
mcp.on('exit', c => process.exit(c || 0));
process.on('SIGINT', () => { try { mcp.kill(); } catch (_) {} process.exit(0); });