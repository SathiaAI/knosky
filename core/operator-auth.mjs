// Operator authorization for trust-domain security-critical mutations (DEC-106/109).
// Local-only: operator tokens under .knosky/operators.json (SHA-256 hashes only).
// Dual-operator default: elevated policy / class elevation needs TWO distinct operators.
// Bootstrap never prints both raw tokens in one stdout payload.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  chmodSync,
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

export function operatorTokenDir(domainRoot) {
  return join(domainRoot, 'operator-tokens');
}

export function hashOperatorToken(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function fingerprintToken(token) {
  return hashOperatorToken(token).slice(0, 12);
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
  return { ok: true, operatorId: id, operatorToken: token, fingerprint: fingerprintToken(token) };
}

function writeTokenFile(domainRoot, operatorId, token) {
  const dir = operatorTokenDir(domainRoot);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${operatorId}.token`);
  writeFileSync(path, token + '\n', { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* windows may ignore */
  }
  return path;
}

/**
 * Bootstrap operators when none exist.
 * ALWAYS creates two operators for a healthy domain.
 * allowSingleOperator is rejected for production domains; only for multi-op fail,
 * single is never enough for elevated class elevation later (quorum still needs 2).
 *
 * Token delivery (dual separation):
 * - operator-a token printed once to stdout (reveal_a)
 * - operator-b token written ONLY to a 0600 file; stdout gets path + fingerprint, not the raw second token
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

  // Dual is mandatory default. Single operator is an explicit escape hatch that
  // can ONLY mint one operator record — and elevated policy still needs TWO
  // distinct tokens (impossible with one → elevated remains blocked until second
  // operator is added via addOperator).
  const single = opts.allowSingleOperator === true;

  const a = addOperatorRecord(doc, opts.operatorId || 'operator-a');
  if (!a.ok) return a;

  /** @type {any} */
  const out = {
    ok: true,
    mode: single ? 'single' : 'dual',
    operatorId: a.operatorId,
    // Only ONE raw token on the wire for dual mode.
    operatorToken: a.operatorToken,
    fingerprint: a.fingerprint,
    warning:
      'Store operator-a token offline. Dual mode embeds operator-b only on disk at tokenFileB (0600). ' +
      'Elevated policy changes require TWO distinct operator tokens. Losing all tokens locks admin actions.',
  };

  if (!single) {
    const b = addOperatorRecord(doc, opts.operatorId2 || 'operator-b');
    if (!b.ok) return b;
    const tokenFileB = writeTokenFile(domainRoot, b.operatorId, b.operatorToken);
    out.operatorId2 = b.operatorId;
    out.fingerprint2 = b.fingerprint;
    out.tokenFileB = tokenFileB;
    // Do NOT set operatorToken2 in the bootstrap return used for stdout.
    out.tokenB_delivery =
      'operator-b raw token written only to tokenFileB — not printed alongside operator-a';
  } else {
    out.warning +=
      ' SINGLE-OPERATOR manual escape: elevated class elevation stays blocked until a second operator is added (addOperator).';
  }

  doc.bootstrap_complete = true;
  saveOperators(domainRoot, doc);
  return out;
}

/**
 * Add a second/later operator — requires an existing different operator token.
 */
export function addOperator(domainRoot, opts = {}) {
  const caller = assertOperator(domainRoot, opts.callerOperatorToken);
  if (!caller.ok) return { ok: false, reason: caller.reason };

  const doc = loadOperators(domainRoot);
  const added = addOperatorRecord(doc, opts.operatorId || `operator-${Date.now()}`);
  if (!added.ok) return added;
  saveOperators(domainRoot, doc);
  const tokenFile = writeTokenFile(domainRoot, added.operatorId, added.operatorToken);
  return {
    ok: true,
    operatorId: added.operatorId,
    fingerprint: added.fingerprint,
    tokenFile,
    // Raw token returned only to caller over this API so CLI can choose delivery
    operatorToken: added.operatorToken,
    added_by: caller.operatorId,
  };
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
 * Require TWO distinct valid operators (quorum for elevated / policy class elevation).
 * @param {string} domainRoot
 * @param {string} [tokenA]
 * @param {string} [tokenB]
 */
export function assertOperatorQuorum(domainRoot, tokenA, tokenB) {
  const a = assertOperator(domainRoot, tokenA);
  if (!a.ok) return { ok: false, reason: a.reason || 'operator_a_invalid', need: 2 };
  const b = assertOperator(domainRoot, tokenB);
  if (!b.ok) {
    return {
      ok: false,
      reason: b.reason || 'operator_b_invalid',
      need: 2,
      next_action: 'Provide a second distinct operator token (--operator-token-2 / KC_OPERATOR_TOKEN_2)',
    };
  }
  if (a.operatorId === b.operatorId) {
    return {
      ok: false,
      reason: 'operator_tokens_not_distinct',
      need: 2,
      next_action: 'Quorum requires two different operators',
    };
  }
  return { ok: true, operatorIds: [a.operatorId, b.operatorId] };
}

/**
 * Revoke an operator. Caller must be a DIFFERENT active operator.
 * Last operator cannot be revoked.
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
        ? 'Run: knosky agent-register --bootstrap-operator (dual operators; elevated needs both tokens)'
        : 'Pass operatorToken / KC_OPERATOR_TOKEN for admin actions; elevated needs a second token too',
  };
}
