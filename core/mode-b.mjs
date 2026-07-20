// KnoSky Mode B evaluator (DEC-106/108).
// identity → policy lattice → audit receipt → ALLOW subgraph | DENY_* / ADVISORY_UNAUTH

import { evaluate, DENY, ALLOW, NOT_APPLICABLE } from './policy-lattice.mjs';
import { resolveLeaseIdentity } from './local-ipc-identity.mjs';
import { writeDecisionReceipt } from './audit-writer.mjs';
import { CODES, envelope } from './decision-codes.mjs';
import {
  loadDomain,
  policyRulesFromDomain,
  inferRouteClass,
  resolveDomainRoot,
} from './domain-store.mjs';
import { kcRoute } from './route.mjs';
import { kcBundle } from './bundle.mjs';
import { loadClass, DEFAULT_CLASS } from './district-classification.mjs';

/**
 * @typedef {object} ModeBRequest
 * @property {'route'|'bundle'|'policy_check'} tool
 * @property {string} [destination]
 * @property {string[]} [nodeIds]
 * @property {string} [leaseId]
 * @property {string|null} [agentId] payload claim — never trusted alone
 * @property {boolean} [advisory] force Mode A
 * @property {number} [limit]
 * @property {string} [root] repo root for bundle secret scan
 */

/**
 * Create a Mode B front-door bound to a city ctx + domain.
 * @param {object} opts
 * @param {object} opts.cityCtx  from retrieve.load
 * @param {string} opts.cityPath
 * @param {string} [opts.domainRoot]
 * @param {'coding'|'security'|'advisory'} [opts.profile]
 */
export function createModeBDoor(opts) {
  const cityCtx = opts.cityCtx;
  // Normalize byId so route/filter code never assumes Map vs plain object.
  if (cityCtx && cityCtx.byId && typeof cityCtx.byId.get !== 'function') {
    cityCtx.byId = new Map(Object.entries(cityCtx.byId));
  }
  const cityPath = opts.cityPath;
  const domainRoot = resolveDomainRoot(cityPath, opts.domainRoot);
  const domain = loadDomain(domainRoot);
  const profile = opts.profile || process.env.KC_PROFILE || 'coding';

  function bindIdentity(req) {
    // Advisory path may skip identity
    if (req.advisory || profile === 'advisory') {
      return { ok: true, advisory: true, agentId: null, lease: null };
    }
    const requireId = domain.policy.require_identity !== false;
    if (!requireId) {
      return { ok: true, advisory: false, agentId: req.agentId || 'anonymous-local', lease: null };
    }
    if (!req.leaseId) {
      return { ok: false, code: CODES.DENY_IDENTITY, hint: 'Provide leaseId from knosky agent register (or set KC_MODE=advisory).' };
    }
    const resolved = resolveLeaseIdentity(domain.leaseStore, req.leaseId, req.agentId ?? null);
    if (!resolved.ok) {
      return {
        ok: false,
        code: CODES.DENY_IDENTITY,
        hint: `Identity bind failed (${resolved.reason}). Register agent + lease in domain.`,
      };
    }
    return { ok: true, advisory: false, agentId: resolved.agentId, lease: resolved.lease };
  }

  function decidePolicy(agentId, className, tool) {
    const rules = policyRulesFromDomain(domain.policy);
    const subject = { agentId, class: className, tool };
    const { decision, reasons } = evaluate(rules, subject);
    if (decision === DENY) {
      return { ok: false, code: CODES.DENY_POLICY, reasons };
    }
    if (decision === NOT_APPLICABLE && domain.policy.require_identity !== false) {
      // No allow found — fail closed when identity required
      return { ok: false, code: CODES.DENY_POLICY, reasons: reasons.concat(['no_allow_rule']) };
    }
    return { ok: true, decision, reasons };
  }

  function receipt(decision_code, agentId, tool, destination, meta) {
    const wr = writeDecisionReceipt({
      domainRoot,
      decision_code,
      agent_id: agentId,
      tool,
      destination,
      mode: decision_code === CODES.ADVISORY_UNAUTH ? 'A' : 'B',
      meta,
    });
    if (!wr.ok) {
      return { ok: false, code: CODES.DENY_AUDIT, hint: wr.reason };
    }
    return { ok: true, receipt_id: wr.receipt_id, ledger_seq: wr.ledger_seq };
  }

  function filterRouteByPolicy(routeDoc, agentId) {
    // Drop waypoints whose node class is denied for agent
    const rules = policyRulesFromDomain(domain.policy);
    const getNodeById = (id) => {
      if (!id || !cityCtx?.byId) return null;
      if (typeof cityCtx.byId.get === 'function') return cityCtx.byId.get(id) || null;
      return cityCtx.byId[id] || null;
    };
    const filterList = (arr) => {
      if (!Array.isArray(arr)) return [];
      return arr.filter((e) => {
        const id = e.id || (e.path ? `fs:${e.path}` : null);
        let cls = DEFAULT_CLASS;
        const node = getNodeById(id);
        if (node) cls = loadClass(node);
        const { decision } = evaluate(rules, { agentId, class: cls, tool: 'route' });
        return decision !== DENY;
      });
    };
    return {
      ...routeDoc,
      route: filterList(routeDoc.route),
      alternates: filterList(routeDoc.alternates),
      tests: filterList(routeDoc.tests),
      docs: filterList(routeDoc.docs),
      authorized: true,
      mode: 'B',
    };
  }

  /**
   * @param {ModeBRequest} req
   */
  function handle(req) {
    const request_id = `req_${Date.now().toString(36)}`;
    try {
      if (!cityCtx) {
        return envelope({
          code: CODES.ERROR_INDEX,
          mode: 'B',
          request_id,
          next_action: 'Set KC_CITY to a valid city-data.json',
        });
      }

      const tool = req.tool || 'route';
      const identity = bindIdentity(req);

      // Mode A advisory
      if (identity.advisory || req.advisory === true || profile === 'advisory') {
        if (tool === 'policy_check') {
          return envelope({
            code: CODES.ADVISORY_UNAUTH,
            mode: 'A',
            request_id,
            payload: { note: 'policy_check in advisory mode does not authorize', decision: 'ADVISORY' },
          });
        }
        if (tool === 'route') {
          if (!req.destination || typeof req.destination !== 'string') {
            return envelope({ code: CODES.ERROR_INVALID_INPUT, mode: 'A', request_id });
          }
          const doc = kcRoute(cityCtx, String(req.destination).slice(0, 400), {
            limit: req.limit ? Math.min(Math.max(1, req.limit), 20) : 8,
          });
          const labeled = {
            ...doc,
            authorized: false,
            mode: 'A',
            advisory: true,
            caveats: [...(doc.caveats || []), 'ADVISORY_UNAUTH: not policy-certified; verify before acting'],
          };
          // optional receipt for advisory trail
          const rc = receipt(CODES.ADVISORY_UNAUTH, null, tool, req.destination, { advisory: true });
          return envelope({
            code: CODES.ADVISORY_UNAUTH,
            mode: 'A',
            request_id,
            receipt_id: rc.ok ? rc.receipt_id : undefined,
            payload: labeled,
          });
        }
        if (tool === 'bundle') {
          return envelope({
            code: CODES.ADVISORY_UNAUTH,
            mode: 'A',
            request_id,
            next_action: 'Bundle under Mode B requires identity; switch profile=coding with leaseId',
          });
        }
      }

      if (!identity.ok) {
        return envelope({
          code: identity.code || CODES.DENY_IDENTITY,
          mode: 'B',
          request_id,
          next_action: identity.hint,
        });
      }

      const agentId = identity.agentId;

      // Build structural artifact first (metadata), then authorize
      let raw = null;
      let destination = req.destination || null;
      let className = DEFAULT_CLASS;

      if (tool === 'route' || tool === 'policy_check') {
        if (!req.destination || typeof req.destination !== 'string') {
          return envelope({ code: CODES.ERROR_INVALID_INPUT, mode: 'B', request_id });
        }
        raw = kcRoute(cityCtx, String(req.destination).slice(0, 400), {
          limit: req.limit ? Math.min(Math.max(1, req.limit), 20) : 8,
        });
        className = inferRouteClass(cityCtx, raw);
      } else if (tool === 'bundle') {
        const ids = Array.isArray(req.nodeIds) ? req.nodeIds : [];
        if (!ids.length && req.destination) {
          const r = kcRoute(cityCtx, String(req.destination).slice(0, 400), { limit: 8 });
          raw = r;
          const idsFromRoute = (r.route || []).map((e) => e.id).filter(Boolean);
          req = { ...req, nodeIds: idsFromRoute };
        }
        className = raw ? inferRouteClass(cityCtx, raw) : DEFAULT_CLASS;
      } else {
        return envelope({ code: CODES.ERROR_INVALID_INPUT, mode: 'B', request_id });
      }

      const pol = decidePolicy(agentId, className, tool);
      if (!pol.ok) {
        const rc = receipt(pol.code, agentId, tool, destination, { reasons: pol.reasons, class: className });
        return envelope({
          code: pol.code,
          mode: 'B',
          request_id,
          receipt_id: rc.ok ? rc.receipt_id : undefined,
          next_action: rc.ok
            ? 'Adjust agent class allowlist in .knosky/policy.json or pick another destination'
            : `Audit write failed: ${rc.hint}`,
        });
      }

      // Audit BEFORE allow payload (DEC-106)
      const rc = receipt(CODES.ALLOW, agentId, tool, destination, { class: className });
      if (!rc.ok) {
        return envelope({
          code: CODES.DENY_AUDIT,
          mode: 'B',
          request_id,
          next_action: rc.hint,
        });
      }

      if (tool === 'policy_check') {
        return envelope({
          code: CODES.ALLOW,
          mode: 'B',
          request_id,
          receipt_id: rc.receipt_id,
          payload: {
            would_allow: true,
            class: className,
            agent_id: agentId,
            reasons: pol.reasons,
          },
        });
      }

      if (tool === 'route') {
        const authorized = filterRouteByPolicy(raw, agentId);
        authorized.receipt_id = rc.receipt_id;
        authorized.agent_id = agentId;
        return envelope({
          code: CODES.ALLOW,
          mode: 'B',
          request_id,
          receipt_id: rc.receipt_id,
          payload: authorized,
        });
      }

      if (tool === 'bundle') {
        const ids = Array.isArray(req.nodeIds) ? req.nodeIds : [];
        if (!ids.length) {
          return envelope({ code: CODES.ERROR_INVALID_INPUT, mode: 'B', request_id, receipt_id: rc.receipt_id });
        }
        try {
          const manifest = kcBundle(cityCtx, ids, {
            root: req.root || null,
            expiry: req.expiry ?? null,
          });
          if (manifest.secret_scan && manifest.secret_scan.status === 'blocked') {
            return envelope({
              code: CODES.DENY_EVIDENCE,
              mode: 'B',
              request_id,
              receipt_id: rc.receipt_id,
              next_action: 'Bundle blocked by fail-closed secret scan',
            });
          }
          return envelope({
            code: CODES.ALLOW,
            mode: 'B',
            request_id,
            receipt_id: rc.receipt_id,
            payload: { ...manifest, authorized: true, agent_id: agentId },
          });
        } catch (err) {
          return envelope({
            code: CODES.ERROR_INVALID_INPUT,
            mode: 'B',
            request_id,
            next_action: err && err.message ? err.message : String(err),
          });
        }
      }

      return envelope({ code: CODES.ERROR_INVALID_INPUT, mode: 'B', request_id });
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      // Do not mask security-path failures as "bad input"
      const securityish =
        /audit|ledger|hwm|policy|identity|lease|operator|deny|fsync|permission|EPERM|ENOSPC/i.test(
          msg,
        );
      return envelope({
        code: securityish ? CODES.DENY_AUDIT : CODES.ERROR_INVALID_INPUT,
        mode: 'B',
        request_id,
        next_action: securityish
          ? `Security path error (fail-closed): ${msg.slice(0, 200)}`
          : msg.slice(0, 200),
      });
    }
  }

  return {
    domainRoot,
    domain,
    profile,
    handle,
  };
}
