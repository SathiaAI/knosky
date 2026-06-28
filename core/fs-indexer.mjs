// KC fs indexer (Phase 1b): a real local folder -> contract v2. Deterministic, $0-token.
// Pointers + projections ONLY (no file bodies). Dir-name categorizer (always-works fallback).
// Honors IGNORE_DEFAULTS + .gitignore + .kcignore. Council fixes: allowlist+scrub via contract.serializeNode.
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { SCHEMA_VERSION, IGNORE_DEFAULTS, deriveCategories, serializeNode, validateCity, setRedactTerms } from './contract.mjs';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => a.startsWith('--') ? [a.slice(2), arr[i + 1]] : []).filter(Boolean));
const ROOT = args.root && path.resolve(args.root);
const OUT = args.out || null;
const MAX = parseInt(args.max || '6000', 10);
if (!ROOT || !fs.existsSync(ROOT)) { console.log('usage: node fs-indexer.mjs --root <dir> [--out <file>] [--max N] [--redact a,b]'); process.exit(1); }
const REDACT = (args.redact || '').split(',').map(s => s.trim()).filter(Boolean);
if (REDACT.length) setRedactTerms(REDACT);
const REDACT_RX = REDACT.map(t => new RegExp('\\b' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i'));

const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|cs|swift|kt|sh|sql)$/i;
const DOC = /\.(md|markdown|mdx|txt|rst|adoc)$/i;
const TEXT_READABLE = /\.(md|markdown|mdx|txt|rst|adoc|ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|cs|swift|kt|sh|sql|json|ya?ml|toml|ini|cfg)$/i;

function gitRev(root) {
  try { return 'git:' + execSync('git rev-parse --short HEAD', { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { return 'fs:' + new Date().toISOString().slice(0, 10); }
}
// Parse .gitignore/.kcignore into conservative matchers (dir names + basenames + *.ext).
function loadIgnore(root) {
  const pats = [];
  for (const f of ['.gitignore', '.kcignore']) {
    try {
      for (let ln of fs.readFileSync(path.join(root, f), 'utf8').split(/\r?\n/)) {
        ln = ln.trim(); if (!ln || ln.startsWith('#') || ln.startsWith('!')) continue;
        ln = ln.replace(/^\/+/, '').replace(/\/+$/, '');
        if (!ln) continue;
        const rx = '(^|/)' + ln.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '(/|$)';
        pats.push(new RegExp(rx, 'i'));
      }
    } catch { /* no file */ }
  }
  return pats;
}
const REV = gitRev(ROOT);
const IGN = [...IGNORE_DEFAULTS, ...loadIgnore(ROOT)];
const ignored = (rel) => IGN.some(re => re.test(rel));

const flags = [];
let scanned = 0, capped = false, redactedPaths = 0;
const raw = []; // pre-serialize nodes

function excerptAndHeadings(fp, isDoc) {
  let txt = '';
  try { const fd = fs.openSync(fp, 'r'); const buf = Buffer.alloc(4096); const n = fs.readSync(fd, buf, 0, 4096, 0); fs.closeSync(fd); txt = buf.slice(0, n).toString('utf8'); }
  catch { return { title: null, summary: '', headings: [] }; }
  let title = null; const headings = [];
  if (isDoc) {
    const h1 = txt.match(/^#\s+(.+)$/m); if (h1) title = h1[1].trim();
    for (const m of txt.matchAll(/^#{2,3}\s+(.+)$/gm)) { headings.push(m[1].trim()); if (headings.length >= 8) break; }
  }
  // first prose line: skip frontmatter + headings/code fences
  const prose = txt.replace(/^---[\s\S]*?---/, '').split(/\r?\n/).map(s => s.trim())
    .find(s => s && !s.startsWith('#') && !s.startsWith('```') && !s.startsWith('|') && !s.startsWith('<')) || '';
  return { title, summary: prose, headings };
}

function walk(dir, depth) {
  if (capped) return;
  let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (capped) return;
    const fp = path.join(dir, e.name);
    const rel = path.relative(ROOT, fp).split(path.sep).join('/');
    if (ignored(rel)) continue;
    if (e.isDirectory()) { if (depth < 12) walk(fp, depth + 1); continue; }
    if (!e.isFile()) continue;
    if (REDACT_RX.some(re => re.test(rel))) { redactedPaths++; continue; }
    scanned++;
    if (scanned > MAX) { capped = true; flags.push(`capped at ${MAX} files`); return; }
    const parts = rel.split('/');
    const category = parts.length > 1 ? parts[0] : '(root)';
    const ext = path.extname(rel);
    const kind = DOC.test(rel) ? 'doc' : CODE.test(rel) ? 'code' : 'file';
    const readable = TEXT_READABLE.test(rel);
    const { title, summary, headings } = readable ? excerptAndHeadings(fp, DOC.test(rel)) : { title: null, summary: '', headings: [] };
    raw.push({
      id: 'fs:' + rel,
      kind,
      title: title || parts[parts.length - 1],
      summary,
      category,
      status: 'present',
      tags: ext ? [ext.slice(1)] : [],
      headings,
      links: [],
      provenance: { store: 'fs', ref: rel, source_rev: REV, fetched_at: new Date().toISOString() },
      visibility: 'internal',
    });
  }
}

walk(ROOT, 0);

// light edges: markdown relative links that resolve to an indexed node
const byRel = new Map(raw.map(n => [n.provenance.ref, n]));
for (const n of raw) {
  if (n.kind !== 'doc') continue;
  // (edges intentionally minimal in v1 fs; reserved for Phase 2 — keep links=[] unless trivially resolvable)
}

const nodes = raw.map(serializeNode);
const catIds = [...new Set(nodes.map(n => n.category))].sort();
const categories = deriveCategories(catIds);
const city = {
  schema_version: SCHEMA_VERSION,
  generated_at: new Date().toISOString(),
  source: { kind: 'fs', ref: ROOT, rev: REV },
  categories, node_count: nodes.length, nodes,
};

const res = validateCity(city);
const dist = {}; for (const n of nodes) dist[n.category] = (dist[n.category] || 0) + 1;

// leakage audit: scan emitted projections for secret-ish patterns + employer strings
const blob = JSON.stringify(nodes);
const leakHits = (blob.match(/\b(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)\b/g) || []).length
  + (blob.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).length;

console.log('--- fs index:', ROOT, '---');
console.log('rev', REV, '| scanned files:', scanned, '| nodes:', nodes.length, '| categories:', catIds.length);
console.log('byKind:', JSON.stringify(nodes.reduce((a, n) => (a[n.kind] = (a[n.kind] || 0) + 1, a), {})));
console.log('top categories:', Object.entries(dist).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k}:${v}`).join(', '));
console.log('VALID:', res.ok, res.ok ? '' : '\n - ' + res.errors.slice(0, 8).join('\n - '));
console.log('post-scrub leak hits (emails/keys, should be ~0):', leakHits);
console.log('redacted-path files skipped:', redactedPaths);
if (flags.length) console.log('flags:', flags.join('; '));
if (OUT) { fs.writeFileSync(OUT, JSON.stringify(city, null, 2) + '\n'); console.log('wrote', OUT); }
