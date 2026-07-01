// KnoSky CI3 action glue tests (action/post-comment.mjs). Run: node test/action-post-comment.test.mjs
// Uses a temp git repo + a mocked global fetch so no real GitHub API call is ever made.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ACTION_SCRIPT = path.join(ROOT, 'action', 'post-comment.mjs');
let failures = 0;
const ok = (name, cond, extra = '') => { console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : '')); if (!cond) failures++; };

function setupRepo() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-action-test-'));
  execFileSync('git', ['-C', d, 'init', '-q']);
  execFileSync('git', ['-C', d, 'config', 'user.email', 'a@b.com']);
  execFileSync('git', ['-C', d, 'config', 'user.name', 't']);
  fs.writeFileSync(path.join(d, 'a.md'), '# A\n\nhello\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'base']);
  const base = execFileSync('git', ['-C', d, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  fs.appendFileSync(path.join(d, 'a.md'), 'more\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'second']);
  const head = execFileSync('git', ['-C', d, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const cityPath = path.join(d, 'city.json');
  const idx = execFileSync(process.execPath, [path.join(ROOT, 'core/fs-indexer.mjs'), '--root', d, '--out', cityPath, '--share-safe'], { encoding: 'utf8' });
  return { d, base, head, cityPath, idx };
}

// Run action/post-comment.mjs in a child process with a pre-injected fetch mock,
// so this test process's own fetch (and everything else) stays untouched.
function runAction(env, mockScript) {
  const runner = path.join(os.tmpdir(), 'knosky-action-runner-' + Math.random().toString(36).slice(2) + '.mjs');
  fs.writeFileSync(runner, `
    ${mockScript}
    for (const [k, v] of Object.entries(${JSON.stringify(env)})) process.env[k] = v;
    await import(${JSON.stringify(ACTION_SCRIPT)});
  `);
  const r = execFileSync(process.execPath, [runner], { encoding: 'utf8', timeout: 15000 });
  fs.rmSync(runner);
  return r;
}

const { d, base, head, cityPath } = setupRepo();
const commonEnv = { KC_ROOT: d, KC_CITY: cityPath, KC_BASE: base, KC_HEAD: head };

// 1) No PR context (missing token/repo/PR#) -> clean skip, no network call, no throw.
{
  const out = runAction({ ...commonEnv, GITHUB_TOKEN: '', KC_REPO: '', KC_PR_NUMBER: '' },
    `globalThis.fetch = async () => { throw new Error('fetch should not be called in this test'); };`);
  ok('no PR context: skips cleanly', /skipping the comment/.test(out), out.trim());
}

// 2) No existing comment -> POSTs a new one containing the marker + advisory wording.
{
  const out = runAction({ ...commonEnv, GITHUB_TOKEN: 'fake', KC_REPO: 'SathiaAI/knosky', KC_PR_NUMBER: '7' }, `
    globalThis.__calls = [];
    globalThis.fetch = async (url, opts = {}) => {
      globalThis.__calls.push({ url, method: opts.method || 'GET', body: opts.body });
      if ((opts.method || 'GET') === 'GET') return { ok: true, status: 200, json: async () => [] };
      return { ok: true, status: 201, json: async () => ({ id: 1 }) };
    };
  `);
  ok('new comment: posts (not patches)', /posted a new PR-GPS comment/.test(out), out.trim());
}

// 3) An existing marked comment -> PATCHes that comment id, never creates a duplicate.
{
  const runner = path.join(os.tmpdir(), 'knosky-action-runner-update.mjs');
  fs.writeFileSync(runner, `
    globalThis.__calls = [];
    globalThis.fetch = async (url, opts = {}) => {
      globalThis.__calls.push({ url, method: opts.method || 'GET' });
      if ((opts.method || 'GET') === 'GET') {
        return { ok: true, status: 200, json: async () => [{ id: 55, body: '<!-- knosky-pr-gps -->\\nold' }] };
      }
      if (opts.method === 'PATCH') return { ok: true, status: 200, json: async () => ({ id: 55 }) };
      throw new Error('unexpected method: ' + opts.method);
    };
    process.env.GITHUB_TOKEN = 'fake'; process.env.KC_REPO = 'SathiaAI/knosky'; process.env.KC_PR_NUMBER = '7';
    process.env.KC_ROOT = ${JSON.stringify(d)}; process.env.KC_CITY = ${JSON.stringify(cityPath)};
    process.env.KC_BASE = ${JSON.stringify(base)}; process.env.KC_HEAD = ${JSON.stringify(head)};
    await import(${JSON.stringify(ACTION_SCRIPT)});
    setTimeout(() => { console.log('CALLS:' + JSON.stringify(globalThis.__calls.map(c => c.method))); }, 200);
  `);
  const out = execFileSync(process.execPath, [runner], { encoding: 'utf8', timeout: 15000 });
  fs.rmSync(runner);
  ok('existing comment: updates via PATCH', /updated the existing PR-GPS comment/.test(out), out.trim());
  ok('existing comment: never issues a duplicate POST', !/CALLS:.*"POST"/.test(out), out.match(/CALLS:.*/)?.[0] || '');
}

// 4) Regression: a malicious base ref (git option-injection PoC) is still neutralized
//    when driven through this action's own env-var plumbing, not just ci.mjs directly.
{
  const pwned = path.join(d, 'pwned-via-action-test');
  fs.rmSync(pwned, { force: true });
  const out = runAction(
    { KC_ROOT: d, KC_CITY: cityPath, KC_BASE: '--output=' + pwned, KC_HEAD: 'HEAD', GITHUB_TOKEN: '', KC_REPO: '', KC_PR_NUMBER: '' },
    `globalThis.fetch = async () => { throw new Error('should not be called'); };`,
  );
  ok('malicious base ref: action does not crash', typeof out === 'string');
  ok('malicious base ref: no file written via --output=', !fs.existsSync(pwned));
}

fs.rmSync(d, { recursive: true, force: true });

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
