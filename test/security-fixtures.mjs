// KnoSky security regression fixtures. Run: node test/security-fixtures.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;
let failures = 0;
const ok = (name, cond, extra = '') => { console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : '')); if (!cond) failures++; };

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-fix-')); }
function index(dir, out, extra = []) {
  return spawnSync(NODE, [path.join(ROOT, 'core/fs-indexer.mjs'), '--root', dir, '--out', out, '--share-safe', ...extra], { encoding: 'utf8' });
}

// 1) secret in a heading + first prose line -> BLOCK (exit != 0), nothing written
{
  const d = tmp(), out = path.join(d, 'city.json');
  fs.writeFileSync(path.join(d, 'leak.md'), '# Config sk-AAAAAAAAAAAAAAAAAAAAAA\n\nghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n');
  const r = index(d, out);
  ok('secret heading/prose blocks the build', r.status !== 0 && !fs.existsSync(out), '(exit ' + r.status + ')');
  ok('block message is shown', /BLOCKED/.test(r.stderr || ''));
}

// 2) --allow-leaks overrides the block (writes output)
{
  const d = tmp(), out = path.join(d, 'city.json');
  fs.writeFileSync(path.join(d, 'leak.md'), '# Config sk-AAAAAAAAAAAAAAAAAAAAAA\n\nplain text\n');
  const r = index(d, out, ['--allow-leaks']);
  ok('--allow-leaks overrides the block', r.status === 0 && fs.existsSync(out));
}

// 3) ignored files (.env, .gitignore, .kcignore) never appear in output
{
  const d = tmp(), out = path.join(d, 'city.json');
  fs.writeFileSync(path.join(d, 'keep.md'), '# Keep me\n\nhello\n');
  fs.writeFileSync(path.join(d, '.env'), 'TOKEN=ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n');
  fs.writeFileSync(path.join(d, '.kcignore'), 'private.md\n');
  fs.writeFileSync(path.join(d, 'private.md'), '# Private\n\nsecret notes\n');
  fs.writeFileSync(path.join(d, '.gitignore'), 'ignored.md\n');
  fs.writeFileSync(path.join(d, 'ignored.md'), '# Ignored\n\nstuff\n');
  const r = index(d, out);
  const json = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  ok('build succeeds with only safe files', r.status === 0 && !!json, '(exit ' + r.status + ')');
  ok('.env not indexed', !/\.env/.test(json));
  ok('.kcignore target not indexed', !/private\.md/.test(json));
  ok('.gitignore target not indexed', !/ignored\.md/.test(json));
}

// 4) malicious markdown heading is escaped in the BUILT html (no live breakout)
{
  const d = tmp(), out = path.join(d, 'city.json'), html = path.join(d, 'city.html');
  fs.writeFileSync(path.join(d, 'x.md'), '# </script><script>alert(1)</script>\n\nbody\n');
  const r1 = index(d, out);
  const r2 = spawnSync(NODE, [path.join(ROOT, 'renderer/build-rich.mjs'), out, html], { encoding: 'utf8' });
  const page = fs.existsSync(html) ? fs.readFileSync(html, 'utf8') : '';
  ok('city builds for XSS fixture', r1.status === 0 && r2.status === 0 && !!page, '(idx ' + r1.status + ', build ' + r2.status + ')');
  ok('no raw </script> breakout from data', !page.includes('</script><script>alert(1)'));
}

// 5) embed bridge is fail-closed (static check of the shipped template)
{
  const t = fs.readFileSync(path.join(ROOT, 'renderer/city.template.html'), 'utf8');
  ok('no fail-open origin guard remains', !t.includes('if(KC_OK.length&&KC_OK.indexOf(ev.origin)===-1)return;'));
  ok('empty-allowlist disables the bridge', t.includes('if(!KC_OK.length)'));
  ok('readiness never posts to "*"', !/postMessage\(\{type:"kc:ready"\},[^)]*\|\|"\*"\)/.test(t));
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);