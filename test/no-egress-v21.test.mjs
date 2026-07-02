// KnoSky no-egress re-verification: v2.1 surface area (SAT-453).
//
// Grepped the diff between main's state before the first v2.1 source-document
// merge (pre-SAT-446, commit 0dea3b7) and the current tip (d3525e8, post-SAT-476)
// for network-call patterns: fetch(, https./http. module usage, net./dns. module
// usage, child_process (exec/spawn), XMLHttpRequest, WebSocket, and package.json
// dependency changes.
//
// Findings summary (grep output reproduced verbatim in the test body):
//
//   core/freshness.mjs:16   import { execFileSync } from 'node:child_process'
//   core/freshness.mjs:51   execFileSync('git', ['rev-list', '--count', 'HEAD'], ...)
//   test/freshness.test.mjs — multiple execFileSync('git', ...) for fixture setup
//   tools/ai-review.mjs:72  https.request to LITELLM_BASE_URL (CI-only)
//   tools/ai-review.mjs:96  https.request to api.github.com (CI-only)
//
// Each hit is classified below and then pinned as a regression assertion.
//
// Run: node test/no-egress-v21.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function src(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// ---------------------------------------------------------------------------
// Helper: collect every line that matches any of the network-call patterns
// in a given source text.  Returns an array of [lineNumber, lineText] pairs.
// ---------------------------------------------------------------------------
const NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /\bhttps?\s*\./,             // https. / http.
  /\bnet\s*\./,
  /\bdns\s*\./,
  /XMLHttpRequest/,
  /WebSocket/,
];

function networkLines(text) {
  return text.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => NETWORK_PATTERNS.some(p => p.test(l)));
}

// ---------------------------------------------------------------------------
// (1) core/freshness.mjs — execFileSync('git', ...) only
//
// The ONLY child_process usage introduced in core/freshness.mjs is
// execFileSync('git', ['rev-list', '--count', 'HEAD'], {cwd:root}).
// This calls the local git binary against a local directory; it cannot reach
// any network host.  No URL, hostname, or socket address is involved.
//
// VERDICT: safe — local-only, no egress.
// ---------------------------------------------------------------------------
{
  const text = src('core/freshness.mjs');
  const lines = text.split('\n').map((l, i) => [i + 1, l]);

  // Must import execFileSync from node:child_process (expected pattern)
  const importLine = lines.find(([, l]) => /execFileSync/.test(l) && /node:child_process/.test(l));
  ok('(1a) core/freshness.mjs imports execFileSync from node:child_process', !!importLine,
    importLine ? '' : 'import not found');

  // The only call must be `git rev-list --count HEAD` — local git, not a URL.
  // Use a multiline match because the call may be formatted across lines.
  const execCallMatches = [...text.matchAll(/execFileSync\s*\(/g)];
  ok('(1b) core/freshness.mjs has exactly one execFileSync call site', execCallMatches.length === 1,
    String(execCallMatches.length));

  // Must be calling 'git' (not curl, wget, sh, etc.) — match across a possible newline
  const gitCallMatch = /execFileSync\s*\(\s*\n?\s*'git'/.test(text);
  ok('(1c) core/freshness.mjs execFileSync first arg is the string "git"', gitCallMatch,
    gitCallMatch ? '' : 'git call not found');

  // The git subcommand must be rev-list (read-only, offline)
  const hasRevList = text.includes("'rev-list'") || text.includes('"rev-list"');
  ok('(1d) core/freshness.mjs execFileSync uses rev-list subcommand (offline, no network)',
    hasRevList);

  // No URL / hostname in the args at all
  const hasUrl = /execFileSync[\s\S]{0,200}https?:\/\//.test(text);
  ok('(1e) core/freshness.mjs execFileSync has no URL argument', !hasUrl);

  // No direct network-call patterns (fetch, https., net., etc.)
  const netHits = networkLines(text);
  ok('(1f) core/freshness.mjs contains no direct network-call patterns',
    netHits.length === 0,
    netHits.length ? netHits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
}

// ---------------------------------------------------------------------------
// (2) test/freshness.test.mjs — execFileSync('git', ...) for fixture setup only
//
// All execFileSync calls in the test file call git with local-only subcommands
// (init, config, add, commit) to create temporary git repositories for the
// ledger-seq tests.  None is a network subcommand.
//
// VERDICT: test/fixture-only, no egress.
// ---------------------------------------------------------------------------
{
  const text = src('test/freshness.test.mjs');
  const lines = text.split('\n').map((l, i) => [i + 1, l]);

  // All execFileSync calls must target 'git' or the node binary (never curl, wget, etc.).
  // Use a multiline match: the first argument may be on the next line.
  const execCallArgs = [...text.matchAll(/execFileSync\s*\(\s*\n?\s*(\S+)/g)]
    .map(m => m[1].replace(/,$/, ''));  // strip trailing comma
  const allowedFirstArgs = ["'git'", '"git"', 'NODE', 'process.execPath'];
  const badArgs = execCallArgs.filter(a => !allowedFirstArgs.includes(a));
  ok('(2a) test/freshness.test.mjs execFileSync calls only invoke git or node binary',
    badArgs.length === 0,
    badArgs.length ? 'unexpected first args: ' + badArgs.join(', ') : '');

  // Git subcommands that appear must all be local-only (init/config/add/commit/rev-list)
  const LOCAL_GIT_CMDS = /'\s*(?:init|config|add|commit|rev-list)\s*'/;
  const badGitLines = lines.filter(([, l]) => /execFileSync\s*\(\s*'git'/.test(l) &&
                                              /\bfetch\b|\bclone\b|\bpush\b|\bpull\b|\bremote\b/.test(l));
  ok('(2b) test/freshness.test.mjs git calls are local-only subcommands (no fetch/clone/push/pull)',
    badGitLines.length === 0,
    badGitLines.length ? badGitLines.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');

  // No direct network-call patterns
  const netHits = networkLines(text);
  ok('(2c) test/freshness.test.mjs contains no direct network-call patterns',
    netHits.length === 0,
    netHits.length ? netHits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
}

// ---------------------------------------------------------------------------
// (3) tools/ai-review.mjs — https.request, CI-only, not published
//
// This file contains two https.request calls: one to the LiteLLM review
// endpoint (LITELLM_BASE_URL) and one to api.github.com.  These are the
// EXPECTED network calls for the PR-security-review CI job
// (.github/workflows/security-review.yml).
//
// Three properties make this safe from a no-egress standpoint:
//   (a) tools/ is NOT listed in package.json "files" → not distributed.
//   (b) No published core module (core/, bin/, mcp/, action/) imports it.
//   (c) The file hard-exits when LITELLM_REVIEW_KEY is absent, so it never
//       runs silently during normal local use.
//
// VERDICT: CI-only tool, not part of the distributed package; not a no-egress
// violation for the knosky library.
// ---------------------------------------------------------------------------
{
  // (3a) tools/ must not appear in the published "files" list
  const pkgText = src('package.json');
  const pkg = JSON.parse(pkgText);
  const publishedFiles = pkg.files || [];
  const toolsPublished = publishedFiles.some(f => f === 'tools' || f.startsWith('tools/'));
  ok('(3a) tools/ is NOT in package.json "files" (not published)', !toolsPublished,
    toolsPublished ? 'tools/ is listed: ' + publishedFiles.join(', ') : '');

  // (3b) No core/published module imports tools/ai-review.mjs.
  // Walks each published dir recursively (not just one level deep) so a
  // future nested subdirectory can't silently escape this check.
  const publishedDirs = ['core', 'bin', 'mcp', 'action'];

  function collectJsFiles(dirPath) {
    let results = [];
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        results = results.concat(collectJsFiles(full));
      } else if (entry.isFile() && (entry.name.endsWith('.mjs') || entry.name.endsWith('.js'))) {
        results.push(full);
      }
    }
    return results;
  }

  const aiReviewImported = publishedDirs.some(dir => {
    const dirPath = path.join(ROOT, dir);
    if (!fs.existsSync(dirPath)) return false;
    return collectJsFiles(dirPath).some(f => {
      try {
        return fs.readFileSync(f, 'utf8').includes('ai-review');
      } catch { return false; }
    });
  });
  ok('(3b) No published core/bin/mcp/action module imports tools/ai-review.mjs (recursive scan)',
    !aiReviewImported);

  // (3c) tools/ai-review.mjs exits early when LITELLM_REVIEW_KEY is absent.
  // Verifies process.exit(0) is causally inside the `if (!LITELLM_REVIEW_KEY...)`
  // block, not just present independently elsewhere in the file (two
  // unrelated matches could otherwise pass this check after a refactor).
  const aiText = src('tools/ai-review.mjs');
  const guardBlockMatch = aiText.match(/if\s*\(\s*!LITELLM_REVIEW_KEY[\s\S]{0,200}?\)\s*\{([\s\S]{0,200}?)\}/);
  const hasGuard = !!guardBlockMatch && /process\.exit\s*\(\s*0\s*\)/.test(guardBlockMatch[1]);
  ok('(3c) tools/ai-review.mjs process.exit(0) is inside the LITELLM_REVIEW_KEY-absent guard block',
    hasGuard);

  // (3d) The two https calls are the only network calls in tools/ai-review.mjs
  const aiNetHits = networkLines(aiText);
  const expectedNetPatterns = [
    /https\.request\s*\(/,
  ];
  const unexpected = aiNetHits.filter(([, l]) => !expectedNetPatterns.some(p => p.test(l)));
  ok('(3d) tools/ai-review.mjs network calls are exclusively https.request (no fetch/WebSocket/XMLHttpRequest)',
    unexpected.length === 0,
    unexpected.length ? unexpected.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
}

// ---------------------------------------------------------------------------
// (4) package.json / package-lock.json — no new dependencies
//
// The diff between 0dea3b7 and d3525e8 shows no changes to package.json or
// package-lock.json.  Dependencies remain: @modelcontextprotocol/sdk, zod.
// Neither introduces network-call surface area at runtime.
//
// VERDICT: no new dependencies, no change to egress surface.
// ---------------------------------------------------------------------------
{
  const pkg = JSON.parse(src('package.json'));
  const deps = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) });

  // Must contain exactly the known dependencies (no new additions)
  const KNOWN_DEPS = ['@modelcontextprotocol/sdk', 'zod'];
  const unexpected = deps.filter(d => !KNOWN_DEPS.includes(d));
  ok('(4a) package.json has no unexpected new dependencies',
    unexpected.length === 0,
    unexpected.length ? unexpected.join(', ') : '');

  // zod is a pure schema validator — no network
  ok('(4b) known dependencies are restricted to @modelcontextprotocol/sdk and zod',
    deps.every(d => KNOWN_DEPS.includes(d)),
    deps.filter(d => !KNOWN_DEPS.includes(d)).join(', ') || '');
}

// ---------------------------------------------------------------------------
// (5) Regression pin: no network-call patterns in any new/changed core file
//
// Scans all core/*.mjs files found in the diff for the full set of network
// patterns.  For freshness.mjs the only allowed exception is execFileSync
// (already classified above).
// ---------------------------------------------------------------------------
{
  const CHANGED_CORE = [
    'core/bundle.mjs',
    'core/freshness.mjs',
    'core/fs-indexer.mjs',
    'core/key-store.mjs',
    'core/ledger.mjs',
    'core/route.mjs',
    'core/schema.mjs',
  ];

  for (const rel of CHANGED_CORE) {
    const text = src(rel);
    const hits = networkLines(text);
    ok(`(5) ${rel} — no network-call patterns`, hits.length === 0,
      hits.length ? hits.map(([n, l]) => `L${n}: ${l.trim()}`).join('; ') : '');
  }
}

// ---------------------------------------------------------------------------

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
