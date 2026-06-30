// KnoSky --verify-airgap: PROVES the tool makes zero network calls.
// (A) self-check: the shim MUST trip on a forced connect (proves the test is effective).
// (B) real test: the indexer MUST make zero network calls.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const shim = new URL('./airgap-shim.mjs', import.meta.url).href; // file:// URL — required by --import
const indexer = join(process.cwd(), 'core', 'fs-indexer.mjs');
const node = process.execPath;
const hit = (s) => /AIRGAP-VIOLATION/.test(s || '');
const fail = (m) => { console.error('AIRGAP FAIL: ' + m); process.exit(1); };

const self = spawnSync(node, ['--import', shim, '-e', "const net=require('net'); try{ net.connect(80,'192.0.2.1'); }catch(e){}"], { encoding: 'utf8' });
if (!hit(self.stderr)) fail('shim did not trip on a forced connect — test not effective');

let fix;
try {
  fix = mkdtempSync(join(tmpdir(), 'knosky-airgap-'));
  for (const n of ['a.md','b.md','c.md']) writeFileSync(join(fix, n), '# ' + n + '\n\nsample\n');
  const r = spawnSync(node, ['--import', shim, indexer, '--root', fix, '--out', join(fix, 'out.json')], { encoding: 'utf8' });
  rmSync(fix, { recursive: true, force: true });
  if (hit(r.stderr) || hit(r.stdout)) { const line = ((r.stderr||'')+(r.stdout||'')).split('\n').find(hit); fail('indexer attempted a network call -> ' + (line||'').trim()); }
  console.log('AIRGAP OK: shim verified live; indexer made zero network calls.');
  process.exit(0);
} catch (e) { if (fix) try { rmSync(fix, { recursive: true, force: true }); } catch {} fail(e.message); }