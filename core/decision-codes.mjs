// KnoSky DEC-108 closed decision-code set (loaded from ssot/decision-codes.json).
// ESM, Node stdlib only. Fail-closed closed set — no open-string codes on the wire.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SSOT_PATH = join(HERE, '..', 'ssot', 'decision-codes.json');

let _doc;
function doc() {
  if (!_doc) {
    _doc = JSON.parse(readFileSync(SSOT_PATH, 'utf8'));
  }
  return _doc;
}

/** @returns {readonly string[]} */
export function closedSet() {
  return Object.freeze([...(doc().closed_set || [])]);
}

/** @param {string} code */
export function isKnownCode(code) {
  return closedSet().includes(code);
}

/**
 * @param {string} code
 * @returns {object|null}
 */
export function codeMeta(code) {
  const hit = (doc().codes || []).find((c) => c.code === code);
  return hit || null;
}

/**
 * Build a wire-safe decision envelope.
 * DENY* never attach restricted structures.
 *
 * @param {object} opts
 * @param {string} opts.code
 * @param {'A'|'B'} [opts.mode]
 * @param {string} [opts.receipt_id]
 * @param {string} [opts.next_action]
 * @param {string} [opts.request_id]
 * @param {object} [opts.payload] only attached when code is ALLOW or ADVISORY_UNAUTH
 */
export function envelope({
  code,
  mode,
  receipt_id,
  next_action,
  request_id,
  payload,
} = {}) {
  if (!isKnownCode(code)) {
    throw new Error(`unknown decision code: ${code}`);
  }
  const meta = codeMeta(code) || {};
  const resolvedMode = mode || (Array.isArray(meta.mode) ? meta.mode[0] : meta.mode) || 'B';
  const out = {
    decision_code: code,
    mode: resolvedMode,
    metadata_disclosed: !!meta.metadata_disclosed,
    authorizing: !!meta.authorizing,
  };
  if (request_id) out.request_id = request_id;
  if (receipt_id) out.receipt_id = receipt_id;
  if (next_action) out.next_action = next_action;
  else if (meta.client_hint) out.next_action = meta.client_hint;

  const allowPayload = code === 'ALLOW' || code === 'ADVISORY_UNAUTH';
  if (allowPayload && payload && typeof payload === 'object') {
    out.payload = payload;
  }
  return out;
}

export const CODES = Object.freeze({
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  DENY_IDENTITY: 'DENY_IDENTITY',
  DENY_POLICY: 'DENY_POLICY',
  DENY_AUDIT: 'DENY_AUDIT',
  DENY_FRESHNESS: 'DENY_FRESHNESS',
  DENY_EVIDENCE: 'DENY_EVIDENCE',
  ERROR_INVALID_INPUT: 'ERROR_INVALID_INPUT',
  ERROR_INDEX: 'ERROR_INDEX',
  ADVISORY_UNAUTH: 'ADVISORY_UNAUTH',
});
