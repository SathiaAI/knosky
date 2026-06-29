// File-level import edges (D-155): file-to-file ONLY. Import specifiers are read transiently
// and discarded after resolution; nothing but the resolved file-to-file edge is ever stored.
// No symbol names, no raw import lines, no body text. Reviewer rule: only file paths survive.
import fs from 'node:fs';
import path from 'node:path';

const PATTERNS = [
  /^\s*import\s+[^'"]*?from\s*['"]([^'"]+)['"]/,   // js/ts: import x from 'y'
  /^\s*import\s*['"]([^'"]+)['"]/,                  // js/ts: import 'y'
  /\brequire\(\s*['"]([^'"]+)['"]\s*\)/,            // js: require('y')
  /^\s*export\s+[^'"]*?from\s*['"]([^'"]+)['"]/,    // js/ts: export ... from 'y'
  /^\s*from\s+([.\w/]+)\s+import\b/,                // python: from x import
  /^\s*#include\s*["<]([^">]+)[">]/,                // c/c++: #include "y"
];

// Read up to 8KB / 150 lines, scan for import specifiers, then drop the buffer. Returns specifier strings only.
export function extractImportSpecifiers(filePath) {
  let txt = '';
  try { const fd = fs.openSync(filePath, 'r'); const buf = Buffer.alloc(8192); const n = fs.readSync(fd, buf, 0, 8192, 0); fs.closeSync(fd); txt = buf.slice(0, n).toString('utf8'); }
  catch { return []; }
  const lines = txt.split(/\r?\n/);
  txt = '';
  const specs = new Set();
  for (let i = 0; i < lines.length && i < 150; i++) {
    for (const re of PATTERNS) { const m = lines[i].match(re); if (m && m[1]) { specs.add(m[1]); break; } }
  }
  return [...specs];
}

const EXTS = ['', '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rs', '.java', '.rb', '.php', '.c', '.h', '.cpp', '.hpp', '.cs', '.kt', '.swift'];

// Resolve a relative specifier to an indexed repo file (rel path). Returns the target rel or null.
// Only relative/internal specifiers resolve; bare package names return null (external = no edge).
export function resolveSpec(fileRel, spec, relSet) {
  if (!spec || !(spec.startsWith('.') || spec.startsWith('/'))) return null;
  const baseDir = path.posix.dirname(fileRel);
  const target = path.posix.normalize(path.posix.join(spec.startsWith('/') ? '.' : baseDir, spec)).replace(/^\.\//, '');
  for (const e of EXTS) {
    if (relSet.has(target + e)) return target + e;
    const idx = path.posix.join(target, 'index' + (e || '.js'));
    if (relSet.has(idx)) return idx;
  }
  return null;
}