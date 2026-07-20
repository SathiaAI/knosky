// Operator authorization for trust-domain security-critical mutations (DEC-106/109).
// Local-only: operator tokens under .knosky/operators.json (SHA-256 hashes at rest).
// Fail-closed. Bootstrap prefers dual-operator mint; single-operator only with
// explicit --allow-single-operator. Operator revoke needs a DIFFERENT operator
// (no unilateral self-revocation of operator status).

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
export const DEFAULT_SOLO_CLASSES = Object.freeze(['public', 'internal']);
export const ELEVATED = Object.freeze(['restricted', 'confidential']);

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
  const ops = loadOperators(domainRoot).operators || {};
  return Object.values(ops).filter((o) => o && !o.revoked).length;
}

function addOperatorRecord(doc, operatorId) {
  const token = mintOperatorToken();
  const id = operatorId || `operator-${Object.keys(doc.operators).length + 1}`;
  if (doc.operators[id] && !doc.operators[id].revoked) {
    return { ok: false, reason: 'operator_id_exists' };
  }
  doc.operators[id] = {
    id,
    role: 'operator',
    token_hash: hashOperatorToken(token),
    created_at: new Date().toISOString(),
  };
  return { ok: true, operatorId: id, operatorToken: token };
}

/**
 * Bootstrap operators when none exist.
 * Default = dual operator (2 tokens) so no single local process is sole trust root
 * without a second material secret. Single-operator requires allowSingleOperator.
 *
 * @param {string} domainRoot
 * @param {{ operatorId?: string, operatorId2?: string, allowSingleOperator?: boolean }} [opts]
 */
export function bootstrapOperator(domainRoot, opts = {}) {
  mkdirSync(domainRoot, { recursive: true });
  const doc = loadOperators(domainRoot);
  if (Object.values(doc.operators || {}).some((o) => o && !o.revoked)) {
    return { ok: false, reason: 'operators_already_exist' };
  }

  const dual = opts.allowSingleOperator !== true;
  const a = addOperatorRecord(doc, opts.operatorId || 'operator-a');
  if (!a.ok) return a;

  /** @type {any} */
  const out = {
    ok: true,
    mode: dual ? 'dual' : 'single',
    operators: [{ operatorId: a.operatorId, operatorToken: a.operatorToken }],
    warning:
      'Store operator token(s) offline. Shown once; only hashes retained on disk. Losing all tokens locks admin actions.',
  };

  if (dual) {
    const b = addOperatorRecord(doc, opts.operatorId2 || 'operator-b');
    if (!b.ok) return b;
    out.operators.push({ operatorId: b.operatorId, operatorToken: b.operatorToken });
    // Back-compat fields: first token still exposed at top level for simple CLIs
    out.operatorId = a.operatorId;
    out.operatorToken = a.operatorToken;
    out.operatorId2 = b.operatorId;
    out.operatorToken2 = b.operatorToken;
  } else {
    out.operatorId = a.operatorId;
    out.operatorToken = a.operatorToken;
    out.warning +=
      ' Single-operator mode enabled via --allow-single-operator (weaker Bootstrap).';
  }

  doc.bootstrap_complete = true;
  saveOperators(domainRoot, doc);
  return out;
}

/**
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
 * Revoke an operator. Caller must be a DIFFERENT active operator (Rule 3:
 * no unilateral self-revocation of operator status). Last operator cannot be revoked.
 *
 * @param {string} domainRoot
 * @param {{ targetOperatorId: string, callerOperatorToken: string }} opts
 */
export function revokeOperator(domainRoot, opts = {}) {
  const caller = assertOperator(domainRoot, opts.callerOperatorToken);
  if (!caller.ok) return { ok: false, reason: caller.reason };

  const targetId = opts.targetOperatorId;
  if (!targetId || typeof targetId !== 'string') {
    return { ok: false, reason: 'targetOperatorId_required' };
  }
  if (caller.operatorId === targetId) {
    return {
      ok: false,
      reason: 'cannot_self_revoke_operator',
      next_action: 'A second active operator must revoke this operator',
    };
  }

  const doc = loadOperators(domainRoot);
  const target = doc.operators[targetId];
  if (!target || target.revoked) {
    return { ok: false, reason: 'target_not_found_or_already_revoked' };
  }

  const active = Object.values(doc.operators).filter((o) => o && !o.revoked);
  if (active.length <= 1) {
    return { ok: false, reason: 'cannot_revoke_last_operator' };
  }

  target.revoked = true;
  target.revoked_at = new Date().toISOString();
  target.revoked_by = caller.operatorId;
  doc.operators[targetId] = target;
  saveOperators(domainRoot, doc);
  return { ok: true, targetOperatorId: targetId, revoked_by: caller.operatorId };
}

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
 * @param {string} domainRoot
 * @param {{ operatorToken?: string, action?: string, allowEmptyBootstrap?: boolean }} opts
 */
export function authorizeMutation(domainRoot, opts = {}) {
  const action = opts.action || 'mutate';
  const auth = assertOperator(domainRoot, opts.operatorToken);
  if (auth.ok) {
    return { ok: true, mode: 'operator', operatorId: auth.operatorId, action };
  }
  if (opts.allowEmptyBootstrap && operatorCount(domainRoot) === 0 && action === 'bootstrap_context') {
    return { ok: true, mode: 'bootstrap_pending', action };
  }
  return {
    ok: false,
    reason: auth.reason || 'operator_required',
    action,
    next_action:
      operatorCount(domainRoot) === 0
        ? 'Run: knosky agent-register --bootstrap-operator  (saves two operator tokens by default)'
        : 'Pass operatorToken (KC_OPERATOR_TOKEN or --operator-token) for policy/lease admin actions',
  };
}
