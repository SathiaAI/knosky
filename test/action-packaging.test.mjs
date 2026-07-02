// KnoSky GitHub Action packaging tests (SAT-464). Run: node test/action-packaging.test.mjs
// Verifies that action.yml, action/post-comment.mjs, and package.json are wired up
// correctly for wider adoption — the CI3 pattern is packaged, not just present.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// 1. action.yml exists and defines the expected inputs
// ---------------------------------------------------------------------------
{
  const actionPath = path.join(ROOT, 'action.yml');
  ok('action.yml exists', fs.existsSync(actionPath));

  const src = fs.readFileSync(actionPath, 'utf8');
  ok('action.yml declares "base" input',          src.includes('base:'));
  ok('action.yml declares "head" input',          src.includes('head:'));
  ok('action.yml declares "github-token" input',  src.includes('github-token:'));
  ok('action.yml declares "fail-on-secret" input', src.includes('fail-on-secret:'));
  ok('action.yml uses composite runner',          src.includes("using: 'composite'"));
  ok('action.yml references action/post-comment.mjs',
    src.includes('action/post-comment.mjs'));
}

// ---------------------------------------------------------------------------
// 2. action/post-comment.mjs exists and contains the upsert marker
// ---------------------------------------------------------------------------
{
  const glue = path.join(ROOT, 'action', 'post-comment.mjs');
  ok('action/post-comment.mjs exists', fs.existsSync(glue));

  const src = fs.readFileSync(glue, 'utf8');
  ok('action/post-comment.mjs exports upsertComment logic (MARKER present)',
    src.includes('knosky-pr-gps'));
  ok('action/post-comment.mjs imports knoskyCi from core/ci.mjs',
    src.includes('ci.mjs'));
  ok('action/post-comment.mjs imports renderPrComment from core/pr-comment.mjs',
    src.includes('pr-comment.mjs'));
  // Advisory-only contract: the catch block must not re-throw (process.exitCode = 0)
  ok('action/post-comment.mjs catch block sets exitCode 0 (never rethrows)',
    src.includes('process.exitCode = 0'));
}

// ---------------------------------------------------------------------------
// 3. package.json files array includes action/ and action.yml
// ---------------------------------------------------------------------------
{
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const files = pkg.files || [];
  ok('package.json files includes "action"',     files.includes('action'));
  ok('package.json files includes "action.yml"', files.includes('action.yml'));
}

// ---------------------------------------------------------------------------
// 4. Every entry in package.json files exists on disk
// ---------------------------------------------------------------------------
{
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  for (const entry of (pkg.files || [])) {
    const full = path.join(ROOT, entry);
    ok(`files entry "${entry}" exists on disk`, fs.existsSync(full));
  }
}

// ---------------------------------------------------------------------------
// 5. README documents the GitHub Action adoption snippet
// ---------------------------------------------------------------------------
{
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  ok('README mentions PR-GPS',                              readme.includes('PR-GPS'));
  ok('README shows SathiaAI/knosky action reference',      readme.includes('SathiaAI/knosky'));
  ok('README shows base SHA input',                        readme.includes('pull_request.base.sha'));
  ok('README shows head SHA input',                        readme.includes('pull_request.head.sha'));
  ok('README states the action never blocks the build',    readme.includes('never blocks') || readme.includes('never block'));
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
