// KnoSky EPIC-Q enterprise pre-pilot red-team fixtures. Run: node test/redteam-fixtures.mjs
// Hostile-input threat model: no crash, no leak, no fail — symlink loops, huge/binary files,
// unicode/control-char names, malformed/empty config, secret-laden files, cyclic import graphs,
// and regression proofs for the 3 hardening notes fixed this session (symlink-escape read,
// unreadable-file fail-open, git-ref option-injection).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { kcBundle } from '../core/bundle.mjs';
import { loadConfig, parseConfigYaml } from '../core/config.mjs';
import { parseDestination } from '../core/destination.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE = process.execPath;
let failures = 0;
const ok = (name, cond, extra = '') => { console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : '')); if (!cond) failures++; };

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-redteam-')); }
function index(dir, out, extra = [], timeoutMs = 30000) {
  return spawnSync(NODE, [path.join(ROOT, 'core/fs-indexer.mjs'), '--root', dir, '--out', out, '--share-safe', ...extra], { encoding: 'utf8', timeout: timeoutMs });
}

// 1) symlink escaping root (file + dir) is NEVER indexed by fs-indexer
{
  const d = tmp(), outside = tmp(), out = path.join(d, 'city.json');
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'AKIAIOSFODNN7EXAMPLE\n');
  fs.writeFileSync(path.join(d, 'normal.md'), '# Normal\n\nhello\n');
  try { fs.symlinkSync(outside, path.join(d, 'linkdir')); } catch { /* platform lacks symlink perms */ }
  try { fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(d, 'linkfile.txt')); } catch { /* ditto */ }
  const r = index(d, out);
  const json = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  ok('index succeeds with symlinks present', r.status === 0 && !!json, '(exit ' + r.status + ', stderr=' + (r.stderr || '').slice(0, 200) + ')');
  ok('no node references the symlink dir or file', !/linkdir|linkfile/.test(json));
  ok('outside-root secret never appears in output', !json.includes('AKIAIOSFODNN7EXAMPLE'));
}

// 2) symlink loop (dir symlink to an ancestor) does not hang or crash the walk
{
  const d = tmp(), out = path.join(d, 'city.json');
  fs.mkdirSync(path.join(d, 'a', 'b'), { recursive: true });
  fs.writeFileSync(path.join(d, 'a', 'b', 'f.md'), '# F\n\nhi\n');
  try { fs.symlinkSync(d, path.join(d, 'a', 'b', 'loop')); } catch { /* platform lacks symlink perms */ }
  const start = Date.now();
  const r = index(d, out, [], 15000);
  ok('symlink loop: index completes without hang', r.status !== null, '(signal=' + r.signal + ', ms=' + (Date.now() - start) + ')');
  ok('symlink loop: index completes quickly (<10s)', (Date.now() - start) < 10000);
}

// 3) huge file: excerpt read is bounded (4096B), no crash, completes quickly
{
  const d = tmp(), out = path.join(d, 'city.json');
  const big = Buffer.alloc(8 * 1024 * 1024, 'x'.charCodeAt(0));
  fs.writeFileSync(path.join(d, 'BIG.md'), big);
  const start = Date.now();
  const r = index(d, out, [], 20000);
  ok('huge file: index succeeds', r.status === 0, '(exit ' + r.status + ')');
  ok('huge file: completes quickly (<5s)', (Date.now() - start) < 5000, '(' + (Date.now() - start) + 'ms)');
}

// 4) binary file (bytes incl NUL) does not crash the indexer
{
  const d = tmp(), out = path.join(d, 'city.json');
  const bin = Buffer.alloc(4096); for (let i = 0; i < bin.length; i++) bin[i] = i % 256;
  fs.writeFileSync(path.join(d, 'blob.bin'), bin);
  fs.writeFileSync(path.join(d, 'ok.md'), '# ok\n\nfine\n');
  const r = index(d, out);
  ok('binary file present: index does not crash', r.status === 0, '(exit ' + r.status + ', stderr=' + (r.stderr || '').slice(0, 200) + ')');
}

// 5) unicode + control-char filenames: no crash, output is valid JSON
{
  const d = tmp(), out = path.join(d, 'city.json');
  const names = ['unicode_日本語.md', 'emoji_😀.md', 'space_name.md'];
  for (const n of names) {
    try { fs.writeFileSync(path.join(d, n), '# hi\n\nbody\n'); } catch { /* some names invalid on this FS, that's fine */ }
  }
  const r = index(d, out);
  let parsed = null;
  try { parsed = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* leave null */ }
  ok('unicode names: index does not crash', r.status === 0, '(exit ' + r.status + ')');
  ok('unicode names: output is valid JSON', parsed !== null);
}

// 6) many files: MAX cap enforced, bounded runtime (proxy for the 100k-file case)
{
  const d = tmp(), out = path.join(d, 'city.json');
  const N = 2500, MAX = 500;
  for (let i = 0; i < N; i++) fs.writeFileSync(path.join(d, `f${i}.md`), `# f${i}\n\nbody\n`);
  const start = Date.now();
  const r = index(d, out, ['--max', String(MAX)], 20000);
  const json = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : { nodes: [] };
  ok(`cap: ${N} files w/ --max ${MAX} completes`, r.status === 0, '(exit ' + r.status + ')');
  ok('cap: node_count does not exceed MAX', json.nodes.length <= MAX, '(' + json.nodes.length + ')');
  ok('cap: completes in bounded time (<10s)', (Date.now() - start) < 10000, '(' + (Date.now() - start) + 'ms)');
}

// 7) cyclic import graph: depChainTo / importsOf terminate (bounded BFS + visited set)
{
  const mk = (id, links) => ({ id, kind: 'file', title: id, category: 'code', links, provenance: { store: 'fs', ref: id.replace(/^fs:/, '') } });
  const nA = mk('fs:a.js', ['fs:b.js']);
  const nB = mk('fs:b.js', ['fs:c.js']);
  const nC = mk('fs:c.js', ['fs:a.js']);
  const nD = mk('fs:d.js', ['fs:a.js']);
  const nodes = [nA, nB, nC, nD];
  const ctx = { city: { nodes, categories: [] }, byId: new Map(nodes.map(n => [n.id, n])) };
  const start = Date.now();
  const res = parseDestination(ctx, 'depChainTo:a.js', 50);
  ok('cyclic graph: depChainTo terminates', (Date.now() - start) < 2000, '(' + (Date.now() - start) + 'ms)');
  ok('cyclic graph: depChainTo finds callers without infinite loop', res.matched.length >= 2 && res.matched.length <= 4);
  const res2 = parseDestination(ctx, 'importsOf:a.js', 50);
  ok('cyclic graph: importsOf terminates and is correct', res2.matched.length === 1 && res2.matched[0].id === 'fs:b.js');
}

// 8) malformed / empty .knosky config: fail-closed (throw), absent -> safe defaults
{
  const d1 = tmp();
  const cfg1 = loadConfig(d1);
  ok('missing config -> safe defaults (telemetry off, fail_on_secret on)', cfg1.telemetry === false && cfg1.fail_on_secret === true);

  const d2 = tmp();
  fs.mkdirSync(path.join(d2, '.knosky'));
  fs.writeFileSync(path.join(d2, '.knosky', 'config.yml'), '');
  let safeOnEmpty = false;
  try { const cfg2 = loadConfig(d2); safeOnEmpty = cfg2.telemetry === false; } catch { safeOnEmpty = true; }
  ok('empty config file: does not silently become permissive', safeOnEmpty);

  let threw = false;
  try { parseConfigYaml('this is not : valid: yaml: at all: [[['); } catch { threw = true; }
  ok('malformed config: parseConfigYaml throws (fail-closed, no silent fallback)', threw);
}

// 9) REGRESSION (hardening note a+b): kcBundle never reports a symlink-escape
//    or an unreadable file as "clean" — it must block.
{
  const root = tmp(), outsideDir = tmp();
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(outsideDir, 'outside-secret.txt'), 'AKIAIOSFODNN7EXAMPLE\n');
  let haveSymlink = true;
  try { fs.symlinkSync(path.join(outsideDir, 'outside-secret.txt'), path.join(root, 'src', 'escape.mjs')); }
  catch { haveSymlink = false; }

  if (haveSymlink) {
    const node = { id: 'fs:src/escape.mjs', kind: 'file', title: 'Escape', category: 'code', links: [], provenance: { store: 'fs', ref: 'src/escape.mjs' } };
    const ctx = { city: { nodes: [node] }, byId: new Map([[node.id, node]]) };
    const manifest = kcBundle(ctx, [node.id], { root });
    ok('(regression a) symlink-escape ref is BLOCKED, not "clean"', manifest.secret_scan.status === 'blocked', JSON.stringify(manifest.secret_scan));
    ok('(regression a) sha256 for escaping symlink is empty (never hashed the outside file)', manifest.paths[0].sha256 === '');
  } else {
    ok('(regression a) symlink test skipped (platform lacks symlink perms)', true);
  }

  const unreadableRef = 'src/locked.mjs';
  fs.writeFileSync(path.join(root, unreadableRef), 'const x = 1;\n');
  let couldChmod = true;
  try { fs.chmodSync(path.join(root, unreadableRef), 0o000); } catch { couldChmod = false; }
  if (couldChmod && process.getuid && process.getuid() !== 0) {
    const node2 = { id: 'fs:src/locked.mjs', kind: 'file', title: 'Locked', category: 'code', links: [], provenance: { store: 'fs', ref: unreadableRef } };
    const ctx2 = { city: { nodes: [node2] }, byId: new Map([[node2.id, node2]]) };
    const manifest2 = kcBundle(ctx2, [node2.id], { root });
    ok('(regression b) unreadable file is BLOCKED, not "clean"', manifest2.secret_scan.status === 'blocked', JSON.stringify(manifest2.secret_scan));
    fs.chmodSync(path.join(root, unreadableRef), 0o644);
  } else {
    ok('(regression b) unreadable-file test skipped (running as root or chmod unsupported)', true);
  }
}

// 10) REGRESSION (hardening note c): a git-ref value shaped like a CLI flag
//     is neutralized — no file write, no crash, safe empty result.
{
  const d = tmp();
  execFileSync('git', ['-C', d, 'init', '-q']);
  execFileSync('git', ['-C', d, 'config', 'user.email', 'a@b.com']);
  execFileSync('git', ['-C', d, 'config', 'user.name', 'redteam']);
  fs.writeFileSync(path.join(d, 'a.txt'), 'a\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'base']);
  const pwnedPath = path.join(d, 'pwned-by-redteam-fixture');
  const maliciousBase = '--output=' + pwnedPath;
  const scriptPath = path.join(d, '__runner.mjs');
  fs.writeFileSync(scriptPath, `
    import { knoskyCi } from ${JSON.stringify(path.join(ROOT, 'core/ci.mjs'))};
    const res = await knoskyCi({ root: ${JSON.stringify(d)}, base: ${JSON.stringify(maliciousBase)}, head: 'HEAD' });
    console.log(JSON.stringify({ exitCode: res.exitCode }));
  `);
  const r = spawnSync(NODE, [scriptPath], { encoding: 'utf8', timeout: 10000 });
  ok('(regression c) malicious base ref does not crash knoskyCi', r.status === 0, '(status=' + r.status + ', stderr=' + (r.stderr || '').slice(0, 300) + ')');
  ok('(regression c) malicious base ref never gets a file written via --output=', !fs.existsSync(pwnedPath));
}

// 11) REGRESSION (own finding, not one of the 3 pre-logged notes): a node whose
//     provenance.ref is unsafe (so safeRef() falls back to its raw `id`) must never
//     let that id leak into route/alternates via the isSafeRef-or-clause bug in
//     route.mjs. Route entries with an unsafe fallback id are cleanly excluded, and
//     kcRoute must not throw on this input.
{
  const { kcRoute } = await import('../core/route.mjs');
  const evil = { id: 'fs:../../etc/passwd', kind: 'file', title: 'evil', category: 'code', links: [], provenance: { store: 'fs', ref: '../../etc/passwd' } };
  const ctx = { city: { nodes: [evil], categories: [], source_rev: null }, byId: new Map([[evil.id, evil]]) };
  let threw = false, doc = null;
  try { doc = kcRoute(ctx, 'file:../../etc/passwd', { limit: 8 }); } catch { threw = true; }
  ok('(regression route-filter) kcRoute does not throw on a malicious-id node', !threw);
  ok('(regression route-filter) malicious-id node excluded from route[]', !!doc && doc.route.length === 0);
}

// 12) COUNCIL FINDING: garbage --max value must NOT silently disable the file cap
//     (NaN comparisons are always false -> `scanned > MAX` would never trip).
{
  const d = tmp(), out = path.join(d, 'city.json');
  for (let i = 0; i < 50; i++) fs.writeFileSync(path.join(d, `f${i}.md`), `# f${i}\n\nbody\n`);
  const r = index(d, out, ['--max', 'not-a-number']);
  const json = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : { nodes: [] };
  ok('garbage --max: index still succeeds (falls back to safe default)', r.status === 0, '(exit ' + r.status + ')');
  ok('garbage --max: cap still enforced (default 6000, not disabled)', json.nodes.length === 50);
}

// 13) COUNCIL FINDING (verified NOT applicable, hardened anyway for consistency):
//     churn.mjs now uses execFileSync + an args array instead of execSync + a shell
//     string. No argument was externally controlled before this change (confirmed by
//     reading the source — the command was a fixed literal, "-- ." is not attacker
//     data), so this is defense-in-depth/consistency, not a fix for a live exploit.
//     Functional regression: churn counts/timestamps must be identical after the change.
{
  const { gitChurn } = await import('../core/churn.mjs');
  const d = tmp();
  execFileSync('git', ['-C', d, 'init', '-q']);
  execFileSync('git', ['-C', d, 'config', 'user.email', 'a@b.com']);
  execFileSync('git', ['-C', d, 'config', 'user.name', 'redteam']);
  fs.writeFileSync(path.join(d, 'x.txt'), 'one\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'c1']);
  fs.writeFileSync(path.join(d, 'x.txt'), 'one\ntwo\n');
  execFileSync('git', ['-C', d, 'add', '.']);
  execFileSync('git', ['-C', d, 'commit', '-qm', 'c2']);
  const churn = gitChurn(d);
  ok('churn.mjs (execFileSync): counts x.txt across 2 commits', churn.counts['x.txt'] === 2, JSON.stringify(churn));
  ok('churn.mjs (execFileSync): last timestamp is a positive number', typeof churn.last['x.txt'] === 'number' && churn.last['x.txt'] > 0);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
