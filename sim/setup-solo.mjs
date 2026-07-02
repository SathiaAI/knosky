// KnoSky "Solo/Startup" sim environment bootstrap (SAT-455).
//
// Clones vercel/next.js (real, large, actively-developed public monorepo) into a
// stable cache directory, then runs the KnoSky fs-indexer against it to produce a
// city.json artifact.  The result is the ground-truth index used by the SAT-438/SAT-437
// synthetic-data and adversarial red-team test suites; synthetic policy/entitlement
// files are layered on top separately (see SAT-457).
//
// Usage (standalone):
//   node sim/setup-solo.mjs [--out <path>] [--cache <dir>] [--max N]
//
// Importable:
//   import { setupSoloSim } from './sim/setup-solo.mjs';
//   const { cityPath } = await setupSoloSim({ out, cache, max });
//
// Flags:
//   --out <path>   Where to write city.json (default: sim/.cache/solo/city.json)
//   --cache <dir>  Where to shallow-clone vercel/next.js (default: sim/.cache/solo/repo)
//   --max N        File cap passed to the indexer (default: 6000)
//
// Environment variables (take precedence over flags):
//   KC_SIM_SOLO_OUT     — overrides --out
//   KC_SIM_SOLO_CACHE   — overrides --cache
//   KC_SIM_SOLO_MAX     — overrides --max
//
// The script is intentionally NOT gated on KC_RUN_SIM_TESTS; it is just a build step.
// Tests that consume the artifact gate themselves on that env var instead.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const INDEXER = path.join(REPO_ROOT, 'core', 'fs-indexer.mjs');
const NEXT_JS_URL = 'https://github.com/vercel/next.js.git';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse a single --key value pair out of process.argv.
 * Env override takes precedence; cliDefault is used when neither is present.
 * @param {string} envVar
 * @param {string} cliFlag   e.g. '--out'
 * @param {string} cliDefault
 * @returns {string}
 */
function resolveArg(envVar, cliFlag, cliDefault) {
  if (process.env[envVar]) return process.env[envVar];
  const argv = process.argv.slice(2);
  const idx = argv.indexOf(cliFlag);
  if (idx !== -1 && argv[idx + 1] && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
  return cliDefault;
}

/**
 * Ensure a shallow clone of vercel/next.js exists at `cloneDir`.
 * If the dir already contains a .git, only fetch to stay current (fast,
 * no full re-clone).  If the fetch fails (offline / rate-limited), log a
 * warning and proceed with the existing clone — stale is better than blocked.
 * @param {string} cloneDir
 */
function ensureClone(cloneDir) {
  const gitDir = path.join(cloneDir, '.git');
  if (fs.existsSync(gitDir)) {
    // Already cloned — try to fast-forward to latest main (advisory, not fatal)
    console.log('[sim-solo] existing clone found at', cloneDir, '— fetching latest …');
    const r = spawnSync('git', ['fetch', '--depth=1', 'origin', 'canary'], {
      cwd: cloneDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    });
    if (r.status !== 0) {
      console.warn('[sim-solo] fetch warning (offline/rate-limit? proceeding with cached clone):');
      console.warn(r.stderr ? r.stderr.trim().slice(0, 400) : '(no stderr)');
    } else {
      console.log('[sim-solo] fetch succeeded — resetting to origin/canary');
      spawnSync('git', ['reset', '--hard', 'origin/canary'], {
        cwd: cloneDir, encoding: 'utf8', stdio: 'inherit', timeout: 30_000,
      });
    }
    return;
  }

  console.log('[sim-solo] shallow-cloning', NEXT_JS_URL, '→', cloneDir, '…');
  fs.mkdirSync(cloneDir, { recursive: true });

  // --depth=1 --single-branch keeps it fast (typically <500 MB for next.js canary).
  // We clone canary (the mainline development branch).
  execFileSync(
    'git',
    ['clone', '--depth=1', '--single-branch', '--branch=canary', NEXT_JS_URL, cloneDir],
    { stdio: 'inherit', timeout: 600_000 },
  );
  console.log('[sim-solo] clone complete.');
}

/**
 * Run the KnoSky fs-indexer against `repoDir` and emit city.json at `outPath`.
 * Passes --share-safe --no-churn so churn (which requires full git history) is
 * skipped on a shallow clone, keeping the run fast and deterministic.
 * @param {string} repoDir
 * @param {string} outPath
 * @param {number} max
 * @returns {{ exitCode: number, stdout: string, stderr: string }}
 */
function runIndexer(repoDir, outPath, max) {
  console.log('[sim-solo] indexing', repoDir, '→', outPath, '(max:', max, ') …');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  const r = spawnSync(
    process.execPath,
    [
      INDEXER,
      '--root', repoDir,
      '--out',  outPath,
      '--max',  String(max),
      '--share-safe',
      '--no-churn',  // shallow clone has no useful history depth
    ],
    {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 600_000,       // 10 min ceiling — large monorepo, slow disk
      maxBuffer: 16 * 1024 * 1024,
    },
  );

  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);

  if (r.status !== 0) {
    throw new Error(
      `[sim-solo] indexer exited ${r.status}` +
      (r.signal ? ` (signal ${r.signal})` : '') +
      (r.stderr ? ': ' + r.stderr.trim().slice(0, 500) : ''),
    );
  }

  return { exitCode: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Set up the Solo/Startup sim environment.
 *
 * 1. Ensures a shallow clone of vercel/next.js exists (or fetches latest).
 * 2. Runs the KnoSky indexer to produce city.json.
 * 3. Returns key paths + a lightweight stats summary.
 *
 * @param {object} [opts]
 * @param {string} [opts.out]    Output path for city.json
 * @param {string} [opts.cache]  Directory for the git clone
 * @param {number} [opts.max]    File cap for the indexer (default 6000)
 * @returns {Promise<{ cityPath: string, cloneDir: string, nodeCount: number, categories: object[] }>}
 */
export async function setupSoloSim({ out, cache, max } = {}) {
  const DEFAULT_CACHE = path.join(__dirname, '.cache', 'solo');

  const cloneDir = cache
    ? path.resolve(cache)
    : path.resolve(process.env.KC_SIM_SOLO_CACHE || path.join(DEFAULT_CACHE, 'repo'));

  const cityPath = out
    ? path.resolve(out)
    : path.resolve(process.env.KC_SIM_SOLO_OUT || path.join(DEFAULT_CACHE, 'city.json'));

  const maxFiles = (() => {
    const raw = max != null ? max : parseInt(process.env.KC_SIM_SOLO_MAX || '6000', 10);
    return Number.isFinite(raw) && raw > 0 ? raw : 6000;
  })();

  ensureClone(cloneDir);
  runIndexer(cloneDir, cityPath, maxFiles);

  // Parse and summarise the output
  const city = JSON.parse(fs.readFileSync(cityPath, 'utf8'));
  const nodeCount = city.node_count ?? (city.nodes || []).length;
  const categories = city.categories || [];

  console.log('[sim-solo] ready — nodes:', nodeCount, '| categories:', categories.length);
  return { cityPath, cloneDir, nodeCount, categories };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

// Run directly: node sim/setup-solo.mjs
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const cache = resolveArg('KC_SIM_SOLO_CACHE', '--cache',
    path.join(__dirname, '.cache', 'solo', 'repo'));
  const out   = resolveArg('KC_SIM_SOLO_OUT',   '--out',
    path.join(__dirname, '.cache', 'solo', 'city.json'));
  const maxRaw = resolveArg('KC_SIM_SOLO_MAX',  '--max', '6000');
  const max   = (() => { const n = parseInt(maxRaw, 10); return Number.isFinite(n) && n > 0 ? n : 6000; })();

  const result = await setupSoloSim({ cache, out, max });
  console.log('[sim-solo] done.', JSON.stringify({ cityPath: result.cityPath, nodeCount: result.nodeCount }));
}
