// Operator authorization for trust-domain security-critical mutations (DEC-106/109).
// Local-only: operator tokens live under .knosky/operators.json (hashed at rest).
// Fail-closed: policy write / privileged register / foreign revoke require operator.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';

const OPS_FILE = 'operators.json';
const DEFAULT_SOLO_CLASSES = Object.freeze(['public', 'internal']);
const ELEVATED = Object.freeze(['restricted', 'confidential']);

function atomicWriteSoft(path, obj) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

export function operatorsPath(domainRoot) {
  return join(domainRoot, OPS_FILE);
}

export function hashOperatorToken(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function mintOperatorToken() {
  return `opk_${randomBytes(24).toString('hex')}`;
}

/**
 * Load operators doc (empty if missing).
 * @param {string} domainRoot
 */
export function loadOperators(domainRoot) {
  const path = operatorsPath(domainRoot);
  if (!existsSync(path)) {
    return { v: 1, operators: {}, bootstrap_complete: false, path };
  }
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    return {
      v: 1,
      operators: doc.operators || {},
      bootstrap_complete: !!doc.bootstrap_complete,
      path,
    };
  } catch {
    throw new Error(`corrupt operators file: ${path}`);
  }
}

function saveOperators(domainRoot, doc) {
  atomicWriteSoft(operatorsPath(domainRoot), {
    v: 1,
    operators: doc.operators || {},
    bootstrap_complete: !!doc.bootstrap_complete,
  });
}

export function operatorCount(domainRoot) {
  return Object.keys(loadOperators(domainRoot).operators || {}).length;
}

/**
 * Bootstrap the first operator when none exist.
 * @returns {{ ok:true, operatorId:string, operatorToken:string }
 *          |{ ok:false, reason:string }}
 */
export function bootstrapOperator(domainRoot, { operatorId = 'bootstrap-operator' } = {}) {
  mkdirSync(domainRoot, { recursive: true });
  const doc = loadOperators(domainRoot);
  if (Object.keys(doc.operators).length > 0) {
    return { ok: false, reason: 'operators_already_exist' };
  }
  const token = mintOperatorToken();
  const id = operatorId || 'bootstrap-operator';
  doc.operators[id] = {
    id,
    role: 'operator',
    token_hash: hashOperatorToken(token),
    created_at: new Date().toISOString(),
  };
  doc.bootstrap_complete = true;
  saveOperators(domainRoot, doc);
  return {
    ok: true,
    operatorId: id,
    operatorToken: token,
    warning: 'Store operatorToken offline. It is shown once and only a hash is retained.',
  };
}

/**
 * Verify operator token against domain.
 * @returns {{ ok:true, operatorId:string } | { ok:false, reason:string }}
 */
export function assertOperator(domainRoot, operatorToken) {
  if (!operatorToken || typeof operatorToken !== 'string') {
    return { ok: false, reason: 'missing_operator_token' };
  }
  const doc = loadOperators(domainRoot);
  const h = hashOperatorToken(operatorToken);
  for (const [id, rec] of Object.entries(doc.operators || {})) {
    if (rec && rec.token_hash === h) {
      if (rec.revoked) return { ok: false, reason: 'operator_revoked' };
      return { ok: true, operatorId: id };
    }
  }
  return { ok: false, reason: 'invalid_operator_token' };
}

/**
 * Classes allowed without elevated operator grant.
 */
export function sanitizeClasses(classes, { allowElevated = false } = {}) {
  const raw = Array.isArray(classes) ? classes.map(String) : DEFAULT_SOLO_CLASSES.slice();
  const out = [];
  for (const c of raw) {
    if (!c) continue;
    if (ELEVATED.includes(c) && !allowElevated) continue;
    if (['public', 'internal', 'restricted', 'confidential', 'blocked'].includes(c)) {
      if (!out.includes(c)) out.push(c);
    }
  }
  if (!out.length) return DEFAULT_SOLO_CLASSES.slice();
  return out.filter((c) => c !== 'blocked');
}

/**
 * Authorize a security-critical mutation.
 * Modes:
 *  - bootstrap: no operators yet + explicit bootstrap flag → mint operator path must be separate
 *  - operator: valid operator token
 *  - self_revoke: holder may revoke own lease only (caller checks match)
 *
 * @param {string} domainRoot
 * @param {{ operatorToken?: string, action: string }} opts
 */
export function authorizeMutation(domainRoot, opts = {}) {
  const action = opts.action || 'mutate';
  const auth = assertOperator(domainRoot, opts.operatorToken);
  if (auth.ok) {
    return { ok: true, mode: 'operator', operatorId: auth.operatorId, action };
  }
  // Allow first-run register ONLY when no operators and bootstrap requested at higher layer
  if (opts.allowEmptyBootstrap && operatorCount(domainRoot) === 0 && action === 'bootstrap_context') {
    return { ok: true, mode: 'bootstrap_pending', action };
  }
  return {
    ok: false,
    reason: auth.reason || 'operator_required',
    action,
    next_action:
      operatorCount(domainRoot) === 0
        ? 'Run: knosky agent-register --bootstrap-operator  (save the printed operatorToken)'
        : 'Pass operatorToken (KC_OPERATOR_TOKEN or --operator-token) for policy/lease admin actions',
  };
}

export { DEFAULT_SOLO_CLASSES, ELEVATED };
