// Architecture intelligence overlays (ENT Phase 3 / FR-KS-ENT-2xx).
// Local-only, deterministic. No cloud upload. Built from city-data + optional CODEOWNERS + prior snapshot.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { findSecrets } from './contract.mjs';

/**
 * @typedef {{ id: string, label?: string, count?: number }} Category
 * @typedef {{ id: string, kind?: string, category?: string, title?: string, provenance?: { ref?: string }, churn?: { c?: number, b?: number, t?: number }, headings?: string[], summary?: string }} CityNode
 */

function sha256Text(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function loadJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Parse CODEOWNERS-ish file: "path @owner" lines (simplest useful subset).
 * @param {string} root
 * @returns {{ rules: { pattern: string, owners: string[] }[], source: string|null }}
 */
export function loadCodeowners(root) {
  const candidates = [
    path.join(root, 'CODEOWNERS'),
    path.join(root, '.github', 'CODEOWNERS'),
    path.join(root, 'docs', 'CODEOWNERS'),
  ];
  for (const fp of candidates) {
    if (!fs.existsSync(fp)) continue;
    const text = fs.readFileSync(fp, 'utf8');
    const rules = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/#.*$/, '').trim();
      if (!line) continue;
      const parts = line.split(/\s+/);
      if (parts.length < 2) continue;
      const pattern = parts[0].replace(/^\//, '');
      const owners = parts.slice(1).filter((p) => p.startsWith('@') || p.includes('/'));
      if (owners.length) rules.push({ pattern, owners });
    }
    return { rules, source: fp };
  }
  return { rules: [], source: null };
}

/**
 * Match a file path to CODEOWNERS (last match wins, GitHub style light).
 * @param {string} rel
 * @param {{ pattern: string, owners: string[] }[]} rules
 */
export function ownersForPath(rel, rules) {
  const file = String(rel || '').replace(/\\/g, '/').replace(/^\.\//, '');
  let hit = [];
  for (const r of rules) {
    const pat = r.pattern.replace(/\\/g, '/');
    if (pat === '*' || pat === '**') {
      hit = r.owners;
      continue;
    }
    // directory prefix
    if (pat.endsWith('/')) {
      if (file.startsWith(pat) || file.startsWith(pat.slice(0, -1) + '/')) hit = r.owners;
      continue;
    }
    if (file === pat || file.startsWith(pat + '/') || file.endsWith('/' + pat) || file.includes(pat.replace(/\*/g, ''))) {
      // crude glob-lite: exact or prefix when no star
      if (!pat.includes('*')) {
        if (file === pat || file.startsWith(pat.replace(/\/$/, '') + '/')) hit = r.owners;
      } else {
        const esc = pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
        if (new RegExp('^' + esc + '$').test(file)) hit = r.owners;
      }
    }
  }
  return hit;
}

function isDocNode(n) {
  const kind = String(n.kind || '').toLowerCase();
  const ref = String(n.provenance?.ref || n.id || '').toLowerCase();
  if (kind === 'doc') return true;
  return /\.(md|mdx|rst|txt|adoc)$/.test(ref) || ref.includes('/docs/') || ref.startsWith('docs/');
}

function isCodeNode(n) {
  const kind = String(n.kind || '').toLowerCase();
  if (kind === 'code') return true;
  const ref = String(n.provenance?.ref || '').toLowerCase();
  return /\.(js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|kt|cs)$/.test(ref);
}

function isTestPath(ref) {
  const r = String(ref || '').replace(/\\/g, '/').toLowerCase();
  return (
    r.includes('/test/') ||
    r.includes('/tests/') ||
    r.includes('/__tests__/') ||
    /\.(test|spec)\./.test(r) ||
    r.startsWith('test/')
  );
}

/**
 * Build per-district and portfolio architecture intelligence from a city.
 * @param {object} opts
 * @param {object} opts.city
 * @param {string} [opts.root]
 * @param {object} [opts.priorCity] previous city snapshot for drift
 * @param {string} [opts.mode]
 */
export function buildArchitectureIntel(opts = {}) {
  const city = opts.city;
  if (!city || !Array.isArray(city.nodes)) {
    return { ok: false, reason: 'missing_city_nodes' };
  }
  const root = opts.root ? path.resolve(opts.root) : null;
  const co = root ? loadCodeowners(root) : { rules: [], source: null };
  const nodes = city.nodes;
  const categories = Array.isArray(city.categories)
    ? city.categories
    : [...new Set(nodes.map((n) => n.category).filter(Boolean))].map((id, i) => ({ id, label: id, order: i }));

  /** @type {Record<string, any>} */
  const byDistrict = {};

  function ensureDistrict(id) {
    if (!byDistrict[id]) {
      byDistrict[id] = {
        id,
        label: id,
        nodes: 0,
        code: 0,
        docs: 0,
        tests: 0,
        owned: 0,
        unknown_owner: 0,
        owners: {},
        churn_sum: 0,
        churn_hot: 0,
        secretish: 0,
        refs: [],
      };
    }
    return byDistrict[id];
  }

  for (const cat of categories) {
    const d = ensureDistrict(cat.id || cat);
    d.label = cat.label || cat.id || d.id;
  }

  for (const n of nodes) {
    const cat = n.category || '(root)';
    const d = ensureDistrict(cat);
    d.nodes += 1;
    const ref = n.provenance?.ref || '';
    if (isDocNode(n)) d.docs += 1;
    if (isCodeNode(n)) d.code += 1;
    if (isTestPath(ref) || isTestPath(n.id)) d.tests += 1;

    const owners = co.rules.length ? ownersForPath(ref, co.rules) : [];
    if (owners.length) {
      d.owned += 1;
      for (const o of owners) d.owners[o] = (d.owners[o] || 0) + 1;
    } else {
      d.unknown_owner += 1;
    }

    const ch = n.churn?.c || 0;
    d.churn_sum += ch;
    if ((n.churn?.b || 0) >= 3 || ch >= 6) d.churn_hot += 1;

    // lightweight secret-ish signal on projections already scrubbed — scan title/summary/headings
    const text = [n.title, n.summary, ...(n.headings || [])].filter(Boolean).join('\n');
    const hits = findSecrets(text);
    if (hits.length) d.secretish += hits.reduce((a, h) => a + h[1], 0);

    if (d.refs.length < 5 && ref) d.refs.push(ref);
  }

  // Prior drift
  /** @type {Record<string, number>} */
  const priorCounts = {};
  if (opts.priorCity?.nodes) {
    for (const n of opts.priorCity.nodes) {
      const c = n.category || '(root)';
      priorCounts[c] = (priorCounts[c] || 0) + 1;
    }
  }

  const districts = Object.values(byDistrict).map((d) => {
    const docs_coverage =
      d.code + d.docs === 0 ? 100 : Math.round((1000 * d.docs) / Math.max(1, d.code + d.docs)) / 10;
    // pure code-heavy with no docs → lower
    const documentation_score = Math.max(0, Math.min(100, docs_coverage === 100 && d.docs === 0 ? 50 : docs_coverage));

    const ownership_score =
      d.nodes === 0 ? 100 : Math.round((1000 * d.owned) / d.nodes) / 10;

    // test adjacency: tests relative to code
    const test_adjacency =
      d.code === 0 ? 100 : Math.round((1000 * Math.min(d.tests, d.code)) / Math.max(1, d.code)) / 10;

    const avg_churn = d.nodes ? d.churn_sum / d.nodes : 0;
    const churn_score = Math.max(0, Math.min(100, 100 - Math.min(100, avg_churn * 8 + d.churn_hot * 5)));

    // freshness: use prior missing = 50 neutral; drift calc below
    let freshness_score = 70;
    const prior = priorCounts[d.id];
    let drift = null;
    if (typeof prior === 'number') {
      const delta = d.nodes - prior;
      const pct = prior === 0 ? (d.nodes > 0 ? 100 : 0) : Math.round((1000 * delta) / prior) / 10;
      drift = { prior_nodes: prior, current_nodes: d.nodes, delta_nodes: delta, delta_percent: pct };
      freshness_score = Math.max(0, Math.min(100, 90 - Math.min(40, Math.abs(pct) / 2)));
    }

    // risk: secretish + high churn + low docs + low ownership
    let risk = 10;
    risk += Math.min(40, d.secretish * 15);
    risk += Math.min(25, d.churn_hot * 4);
    risk += documentation_score < 30 ? 15 : documentation_score < 50 ? 8 : 0;
    risk += ownership_score < 40 ? 15 : ownership_score < 70 ? 8 : 0;
    risk = Math.max(0, Math.min(100, risk));
    const risk_score = Math.round(100 - risk); // higher = safer
    const risk_level = risk >= 60 ? 'elevated' : risk >= 35 ? 'watch' : 'low';

    const top_owners = Object.entries(d.owners)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([owner, count]) => ({ owner, count }));

    return {
      id: d.id,
      label: d.label,
      nodes: d.nodes,
      code: d.code,
      docs: d.docs,
      tests: d.tests,
      unknown_owner_files: d.unknown_owner,
      ownership_coverage_percent: ownership_score,
      documentation_score,
      ownership_score,
      test_adjacency_score: test_adjacency,
      churn_score,
      freshness_score,
      risk_score,
      risk_level,
      secretish_hits: d.secretish,
      churn_hot_files: d.churn_hot,
      drift,
      top_owners,
      sample_paths: d.refs,
    };
  });

  districts.sort((a, b) => a.risk_score - b.risk_score || b.nodes - a.nodes);

  // Portfolio rollup
  const totalNodes = nodes.length;
  const owned = districts.reduce((a, d) => a + (d.nodes - d.unknown_owner_files), 0);
  const portfolio = {
    node_count: totalNodes,
    district_count: districts.length,
    ownership_coverage_percent: totalNodes ? Math.round((1000 * owned) / totalNodes) / 10 : 100,
    codeowners_source: co.source,
    codeowners_rules: co.rules.length,
    elevated_risk_districts: districts.filter((d) => d.risk_level === 'elevated').map((d) => d.id),
    watch_districts: districts.filter((d) => d.risk_level === 'watch').map((d) => d.id),
    largest_drift: districts
      .filter((d) => d.drift)
      .sort((a, b) => Math.abs(b.drift.delta_percent) - Math.abs(a.drift.delta_percent))
      .slice(0, 5)
      .map((d) => ({ id: d.id, ...d.drift })),
  };

  const report = {
    schema: 'knosky.architecture_intel.v1',
    generated_at: new Date().toISOString(),
    mode: opts.mode || 'enterprise',
    local_only: true,
    source: city.source || null,
    ledger_seq: city.ledger_seq ?? null,
    city_generated_at: city.generated_at || null,
    portfolio,
    districts,
    leader_scores_legend: {
      documentation_score: 'Share of doc-like nodes vs code+doc in district (proxy)',
      ownership_score: 'CODEOWNERS coverage when present; else unknown_owner high',
      test_adjacency_score: 'Test-like paths vs code nodes (proxy)',
      churn_score: 'Higher = calmer (from city churn overlay)',
      freshness_score: 'Stable vs prior snapshot drift when prior exists',
      risk_score: 'Higher = safer (inverse of elevated risk signals)',
    },
    honesty: [
      'Scores are local deterministic proxies for pilots — not a full static-analysis product.',
      'Ownership requires CODEOWNERS (or .github/CODEOWNERS); without it unknown_owner will be high.',
      'Drift needs a prior city snapshot (city-data.prev.json or --prior).',
      'Risk districts amplify secret-like residual signals + hot churn + thin docs/ownership — not a CVE scanner.',
    ],
  };

  report.fingerprint = 'sha256:' + sha256Text(JSON.stringify({ districts: report.districts, portfolio: report.portfolio }));
  return { ok: true, report };
}

/**
 * @param {object} report
 */
export function formatArchitectureIntelMarkdown(report) {
  const lines = [
    '# KnoSky Architecture Intelligence',
    '',
    `**Generated:** ${report.generated_at}`,
    `**Nodes:** ${report.portfolio?.node_count ?? 'n/a'} · **Districts:** ${report.portfolio?.district_count ?? 'n/a'}`,
    `**Ownership coverage:** ${report.portfolio?.ownership_coverage_percent ?? 'n/a'}%` +
      (report.portfolio?.codeowners_source
        ? ` (from ${path.basename(report.portfolio.codeowners_source)})`
        : ' (no CODEOWNERS found — unknown owners expected)'),
    '',
    '## Leader view — districts by risk (lower risk_score = more attention)',
    '',
    '| District | Nodes | Docs | Own% | Tests | Churn | Risk | Level |',
    '| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |',
  ];
  for (const d of (report.districts || []).slice(0, 25)) {
    lines.push(
      `| ${d.label || d.id} | ${d.nodes} | ${d.documentation_score} | ${d.ownership_score} | ${d.test_adjacency_score} | ${d.churn_score} | ${d.risk_score} | ${d.risk_level} |`,
    );
  }
  lines.push('');
  if (report.portfolio?.largest_drift?.length) {
    lines.push('## Drift vs prior snapshot');
    lines.push('');
    for (const x of report.portfolio.largest_drift) {
      lines.push(
        `- **${x.id}**: ${x.prior_nodes} → ${x.current_nodes} (Δ ${x.delta_nodes}, ${x.delta_percent}%)`,
      );
    }
    lines.push('');
  } else {
    lines.push('## Drift');
    lines.push('');
    lines.push('_No prior snapshot — run again later or pass `--prior city-data.prev.json` for growth/shrink._');
    lines.push('');
  }
  lines.push('## Honesty');
  lines.push('');
  for (const h of report.honesty || []) lines.push(`- ${h}`);
  lines.push('');
  lines.push('_Local-only intelligence. Not uploaded. ENT Phase 3._');
  lines.push('');
  return lines.join('\n');
}

/**
 * Write intel files under outDir; optionally snapshot current city as prev for next run.
 * @param {string} outDir
 * @param {object} report
 * @param {object} [opts]
 * @param {string} [opts.cityPath]
 */
export function writeArchitectureIntelFiles(outDir, report, opts = {}) {
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'architecture-intel.json');
  const mdPath = path.join(outDir, 'architecture-intel.md');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  fs.writeFileSync(mdPath, formatArchitectureIntelMarkdown(report), 'utf8');

  // Keep prior snapshot for drift next time
  if (opts.cityPath && fs.existsSync(opts.cityPath)) {
    const prev = path.join(outDir, 'city-data.prev.json');
    try {
      // Only rotate if current city is newer/different
      fs.copyFileSync(opts.cityPath, prev);
    } catch {
      /* ignore */
    }
  }
  return { jsonPath, mdPath };
}

/**
 * Load city + optional prior and build+write intel for a project root.
 * @param {object} opts
 * @param {string} opts.root
 * @param {string} [opts.cityPath]
 * @param {string} [opts.priorPath]
 * @param {string} [opts.mode]
 */
export function runArchitectureIntel(opts = {}) {
  const root = path.resolve(opts.root || '.');
  const kn = path.join(root, '.knosky');
  const cityPath = opts.cityPath || path.join(kn, 'city-data.json');
  if (!fs.existsSync(cityPath)) {
    return {
      ok: false,
      reason: 'missing_city',
      next_action: 'Run knosky enterprise . --no-serve (or index) so .knosky/city-data.json exists.',
    };
  }
  const city = loadJson(cityPath);
  const priorPath =
    opts.priorPath ||
    (fs.existsSync(path.join(kn, 'city-data.prev.json')) ? path.join(kn, 'city-data.prev.json') : null);
  // When rotating, prior should be previous — if prev is copy of current after last write second run needs malip
  // Prefer: if prev exists and hash differs use it; if same as current, ignore
  let priorCity = priorPath && fs.existsSync(priorPath) ? loadJson(priorPath) : null;
  if (priorCity && city) {
    try {
      const a = sha256Text(JSON.stringify(priorCity.nodes?.length + priorCity.generated_at));
      const b = sha256Text(JSON.stringify(city.nodes?.length + city.generated_at));
      if (a === b) priorCity = null;
    } catch {
      /* use prior */
    }
  }

  const built = buildArchitectureIntel({
    city,
    root,
    priorCity,
    mode: opts.mode || 'enterprise',
  });
  if (!built.ok) return built;

  // Write intel first, then update prev to current for NEXT run
  const written = writeArchitectureIntelFiles(kn, built.report, {});
  try {
    fs.copyFileSync(cityPath, path.join(kn, 'city-data.prev.json'));
  } catch {
    /* ignore */
  }

  return {
    ok: true,
    report: built.report,
    ...written,
    prior_used: Boolean(priorCity),
  };
}
