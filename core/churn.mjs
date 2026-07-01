// Git churn (D-155): per-file commit count (windowed) + last-commit timestamp ONLY.
// No commit messages, diffs, hunks, authors, or line-level churn retained.
// execFileSync + an args array (not execSync + a shell string) — no argument here is
// externally controlled today, but this matches the args-array-only discipline used by
// every other git invocation in this codebase (ci.mjs) and removes the shell entirely,
// so a future edit that adds a dynamic path/ref here can't reintroduce an injection class.
import { execFileSync } from 'node:child_process';

export function gitChurn(root) {
  const counts = {}, last = {};
  try {
    const out = execFileSync('git', ['log', '--since=90.days.ago', '--name-only', '--pretty=format:%ct', '--', '.'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
    let ts = 0;
    for (const raw of out.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (/^\d+$/.test(line)) { ts = parseInt(line, 10); continue; }
      const rel = line.replace(/\\/g, '/');
      counts[rel] = (counts[rel] || 0) + 1;
      if (!last[rel] || ts > last[rel]) last[rel] = ts;
    }
  } catch { /* no git / no history -> empty */ }
  return { counts, last };
}