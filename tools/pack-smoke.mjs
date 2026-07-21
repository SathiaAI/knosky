// Pack smoke matrix — SSOT ↔ packs presence & honesty (Wave 1 AR-33).
// Pure ESM. Does not install MCP hosts; checks pack content contracts.

import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const P0 = [
  { id: 'hermes', paths: ['packs/hermes/install.md', 'packs/hermes/SKILL.md'] },
  { id: 'claude-code', paths: ['packs/claude-code/install.md'] },
  { id: 'cursor', paths: ['packs/cursor/install.md', 'packs/cursor/mcp.json.example'] },
  { id: 'codex', paths: ['packs/codex/install.md'] },
];

const P1 = [
  { id: 'vscode', paths: ['packs/p1/vscode/install.md'] },
  { id: 'greptile', paths: ['packs/p1/greptile-recipe.md'] },
  { id: 'gha-pr-gps', paths: ['packs/p1/gha-pr-gps.md'] },
];

const MUST_NOT = [
  /\balways-on telemetry\b/i, // constitution breach language if claimed as on
  /\bensures zero data risk\b/i,
  /\bis swarm-safe fleet\b/i,
  /\bproduction swarm-safe\b/i,
];

/** Allow docs that *forbid* melodrama phrases. */
function hasBannedClaim(textmece) {
  // If the line is clearly forbidding the phrase, skip
  const lines = textmece.split(/\r?\n/);
  for (const line of lines) {
    if (/forbidden|never claim|do not claim|not\b|≠|unless/i.test(line)) continue;
    for (const re of MUST_NOT) {
      if (re.test(line)) return re.toString();
    }
    // Hard ban: positive swarm-safe claim without negation
    if (/\bis swarm-safe\b|\bswarm-safe by default\b/i.test(line) && !/not|never|unless|forbidden/i.test(line)) {
      return 'positive swarm-safe claim';
    }
  }
  return null;
}

/**
 * @param {string} [repoRoot]
 */
export function runPackSmoke(repoRoot = ROOT) {
  const menuPath = join(repoRoot, 'ssot', 'tool-menu.json');
  const results = [];

  if (!existsSync(menuPath)) {
    return {
      ok: false,
      total: 1,
      pass: 0,
      fail: 1,
      results: [{ id: 'ssot-menu', ok: false, detail: 'missing ssot/tool-menu.json' }],
      failed: [{ id: 'ssot-menu', ok: false, detail: 'missing ssot/tool-menu.json' }],
    };
  }

  const menu = JSON.parse(readFileSync(menuPath, 'utf8'));
  const tier0 = (menu.tiers.tier0_map.tools || []).map((t) => t.name);
  const tier1 = (menu.tiers.tier1_governed.tools || []).map((t) => t.name);
  const allTools = [...tier0, ...tier1];

  results.push({
    id: 'ssot-menu',
    ok:
      allTools.includes('kc_route') &&
      allTools.includes('kc_bundle') &&
      allTools.includes('kc_policy_check'),
    detail: `tools=${allTools.join(',')}`,
  });

  const packsReadme = join(repoRoot, 'packs', 'README.md');
  if (existsSync(packsReadme)) {
    const text = readFileSync(packsReadme, 'utf8');
    const missingTools = allTools.filter((t) => !text.includes(t));
    results.push({
      id: 'packs-readme-tools',
      ok: missingTools.length === 0,
      detail: missingTools.length ? `missing ${missingTools.join(',')}` : 'all SSOT tools listed',
    });
  } else {
    results.push({ id: 'packs-readme-tools', ok: false, detail: 'packs/README.md missing' });
  }

  for (const pack of [...P0, ...P1]) {
    const tier = P0.find((p) => p.id === pack.id) ? 'P0' : 'P1';
    for (const rel of pack.paths) {
      const abs = join(repoRoot, rel);
      if (!existsSync(abs)) {
        results.push({ id: `${tier}:${pack.id}:${rel}`, ok: false, detail: 'missing file' });
        continue;
      }
      const text = readFileSync(abs, 'utf8');
      const softOk =
        tier === 'P1' ||
        /Mode B|leaseId|agent-register|MCP|kc_route|decision_code/i.test(text);
      const bannedHit = hasBannedClaim(text);
      results.push({
        id: `${tier}:${pack.id}:${rel}`,
        ok: softOk && !bannedHit,
        detail: bannedHit
          ? `banned claim: ${bannedHit}`
          : softOk
            ? 'ok'
            : 'missing mode/lease/MCP cues',
      });
    }
  }

  const cursorEx = join(repoRoot, 'packs', 'cursor', 'mcp.json.example');
  if (existsSync(cursorEx)) {
    try {
      const j = JSON.parse(readFileSync(cursorEx, 'utf8'));
      const blob = JSON.stringify(j);
      results.push({
        id: 'P0:cursor:mcp-json',
        ok: blob.includes('server.mjs') && /KC_CITY/i.test(blob),
        detail: 'cursor mcp example points at server + KC_CITY',
      });
    } catch (e) {
      results.push({ id: 'P0:cursor:mcp-json', ok: false, detail: String(e.message || e) });
    }
  }

  const fail = results.filter((r) => !r.ok);
  return {
    ok: fail.length === 0,
    total: results.length,
    pass: results.length - fail.length,
    fail: fail.length,
    results,
    failed: fail,
  };
}

const isMain =
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMain) {
  const out = runPackSmoke();
  console.log(JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
}
