// KC city-data CONTRACT v2 — the shared spine.
// Generalizes the fixed-4-district v1 → N categories. Pointers + projections ONLY (D-146); never bodies.
// Council fixes baked in: serialization ALLOWLIST at the edge + best-effort DENYLIST scrub.

export const SCHEMA_VERSION = '2.0';

// The ONLY node fields that may ever be serialized into the index. Anything else is dropped/flagged.
export const NODE_FIELD_ALLOWLIST = [
  'id', 'kind', 'title', 'summary', 'category', 'status',
  'fact_date', 'tags', 'headings', 'links', 'provenance', 'visibility', 'sensitive',
];
export const NODE_REQUIRED = ['id', 'kind', 'title', 'category', 'links', 'provenance'];
export const PROVENANCE_REQUIRED = ['store', 'ref'];
export const CATEGORY_REQUIRED = ['id', 'label', 'order'];
export const SUMMARY_MAX = 200;

// Detection patterns for the fail-closed safe-share audit (broader than the scrub list below).
export const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/g, 'aws-access-key'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, 'private-key'],
  [/\bgh[posru]_[A-Za-z0-9]{20,}\b/g, 'github-token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, 'github-pat'],
  [/\bsk-[A-Za-z0-9]{20,}\b/g, 'openai-key'],
  [/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, 'stripe-key'],
  [/\bAIza[0-9A-Za-z_\-]{35}\b/g, 'google-api-key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, 'slack-token'],
  [/\bglpat-[A-Za-z0-9_\-]{20,}\b/g, 'gitlab-pat'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, 'npm-token'],
  [/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g, 'jwt'],
];
export function findSecrets(text) {
  const s = String(text); const hits = [];
  for (const [re, kind] of SECRET_PATTERNS) { const m = s.match(re); if (m && m.length) hits.push([kind, m.length]); }
  return hits;
}

// Best-effort secret/PII denylist applied to emitted text projections. Backed by the indexer's
// fail-closed findSecrets() audit on the final artifact (defense in depth, not a single boundary).
const DENY = [
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,                 // emails
  /\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*\S+/gi,
  ...SECRET_PATTERNS.map(([re]) => re),
];
// Optional project-specific sensitive terms (e.g. an employer/customer name) → redacted too.
let EXTRA_TERMS = [];
export function setRedactTerms(terms) {
  EXTRA_TERMS = (terms || []).map(t => String(t).trim()).filter(Boolean)
    .map(t => new RegExp('\\b' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi'));
}
export function scrubText(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  for (const re of DENY) out = out.replace(re, '[REDACTED]');
  for (const re of EXTRA_TERMS) out = out.replace(re, '[REDACTED]');
  return out;
}

// Default path/dir ignores (the indexer also honors the repo's .gitignore + a user .kcignore).
export const IGNORE_DEFAULTS = [
  /(^|\/)\.git(\/|$)/, /(^|\/)node_modules(\/|$)/, /(^|\/)secrets?(\/|$)/i,
  /(^|\/)keys?(\/|$)/i, /(^|\/)\.env/i, /(^|\/)dist(\/|$)/,
];

// Serialize one node: keep ONLY allowlisted fields, scrub text, clamp summary.
export function serializeNode(n) {
  const o = {};
  for (const k of NODE_FIELD_ALLOWLIST) if (n[k] !== undefined) o[k] = n[k];
  if (typeof o.title === 'string') o.title = scrubText(o.title);
  if (typeof o.summary === 'string') o.summary = scrubText(o.summary).slice(0, SUMMARY_MAX);
  if (Array.isArray(o.headings)) o.headings = o.headings.map(scrubText);
  if (Array.isArray(o.tags)) o.tags = o.tags.map(scrubText);
  return o;
}

// Validate a city envelope against the contract. Returns { ok, errors[] }.
export function validateCity(city) {
  const errors = [];
  if (!city || typeof city !== 'object') return { ok: false, errors: ['city is not an object'] };
  if (city.schema_version !== SCHEMA_VERSION) errors.push(`schema_version != ${SCHEMA_VERSION}`);
  if (!Array.isArray(city.categories)) errors.push('missing categories[] manifest');
  if (!Array.isArray(city.nodes)) errors.push('missing nodes[]');
  const catIds = new Set((city.categories || []).map(c => c.id));
  (city.categories || []).forEach((c, i) => {
    for (const k of CATEGORY_REQUIRED) if (c[k] === undefined) errors.push(`category[${i}] missing ${k}`);
  });
  const ids = new Set();
  (city.nodes || []).forEach((n, i) => {
    for (const k of NODE_REQUIRED) if (n[k] === undefined) errors.push(`node[${i}] missing ${k}`);
    if (n.category && !catIds.has(n.category)) errors.push(`node[${i}] category '${n.category}' not in manifest`);
    if (n.id) { if (ids.has(n.id)) errors.push(`duplicate id ${n.id}`); ids.add(n.id); }
    if (n.provenance) for (const k of PROVENANCE_REQUIRED) if (n.provenance[k] === undefined) errors.push(`node[${i}] provenance missing ${k}`);
    if (typeof n.summary === 'string' && n.summary.length > SUMMARY_MAX) errors.push(`node[${i}] summary > ${SUMMARY_MAX}`);
    for (const k of Object.keys(n)) if (!NODE_FIELD_ALLOWLIST.includes(k)) errors.push(`node[${i}] non-allowlisted field '${k}'`);
  });
  if (city.node_count !== undefined && city.node_count !== (city.nodes || []).length) errors.push('node_count mismatch');
  return { ok: errors.length === 0, errors };
}

const PALETTE = ['#4f8cff', '#34c759', '#ff9f0a', '#af52de', '#ff375f', '#5ac8fa', '#ffd60a', '#bf5af2', '#30d158', '#ff6482'];

// Build a categories[] manifest from a list of category ids (stable order + palette).
export function deriveCategories(ids) {
  return ids.map((id, i) => ({
    id, label: String(id).charAt(0).toUpperCase() + String(id).slice(1),
    color: PALETTE[i % PALETTE.length], order: i,
  }));
}

// Legacy adapter: v1 (district, no categories[]) → v2 (category + categories[] manifest), via the allowlist.
export function adaptLegacy(cityV1) {
  const ids = [...new Set((cityV1.nodes || []).map(n => n.district).filter(Boolean))];
  const categories = deriveCategories(ids);
  const nodes = (cityV1.nodes || []).map(n => {
    const { district, ...rest } = n;
    return serializeNode({ ...rest, category: district });
  });
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: cityV1.generated_at || new Date().toISOString(),
    source: { kind: 'legacy', ref: cityV1.source_rev || 'unknown', rev: cityV1.source_rev || 'unknown' },
    categories, node_count: nodes.length, nodes,
  };
}
