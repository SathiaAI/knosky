// Local trust domain state for Mode B + early L3 identity (DEC-109/106).
// Loads/creates .knosky agents, leases, and optional policy rules.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  openSync,
  fsyncSync,
  closeSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DENY, ALLOW, NOT_APPLICABLE } from './policy-lattice.mjs';
import { DEFAULT_CLASS, loadClass, CLASS_BLOCKED, CLASS_RESTRICTED, CLASS_CONFIDENTIAL } from './district-classification.mjs';
import {
  assertOperator,
  assertOperatorQuorum,
  operatorCount,
  sanitizeClasses,
  ELEVATED,
} from './operator-auth.mjs';

/**
 * Resolve domain root (.knosky dir) from city path or explicit env.
 * @param {string} [cityPath]
 * @param {string} [explicitDomain]
 */
export function resolveDomainRoot(cityPath, explicitDomain) {
  if (explicitDomain) return explicitDomain;
  if (process.env.KC_DOMAIN) return process.env.KC_DOMAIN;
  if (cityPath) {
    // city often lives at <repo>/.knosky/city-data.json
    const d = dirname(cityPath);
    if (d.endsWith('.knosky') || d.replace(/\\/g, '/').endsWith('/.knosky')) return d;
    return join(d, '.knosky');
  }
  return join(process.cwd(), '.knosky');
}

function atomicWrite(path, obj) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', 'utf8');
  try {
    const fd = openSync(tmp, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    /* ignore */
  }
  renameSync(tmp, path);
}

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`corrupt domain file: ${path}`);
  }
}

/**
 * @param {string} domainRoot
 */
export function ensureDomainLayout(domainRoot) {
  mkdirSync(domainRoot, { recursive: true });
  mkdirSync(join(domainRoot, 'audit'), { recursive: true });
  const agentsPath = join(domainRoot, 'agents.json');
  const leasesPath = join(domainRoot, 'leases.json');
  const policyPath = join(domainRoot, 'policy.json');

  if (!existsSync(agentsPath)) {
    atomicWrite(agentsPath, {
      v: 1,
      agents: {
        // bootstrapped solo agent for local Meta — encoded as optional
      },
    });
  }
  if (!existsSync(leasesPath)) {
    atomicWrite(leasesPath, { v: 1, leases: {} });
  }
  if (!existsSync(policyPath)) {
    // Default: Team-ish open for public/internal, deny restricted+ without allowlist
    atomicWrite(policyPath, {
      v: 1,
      profile: 'team',
      require_identity: true,
      default_class_effect: {
        public: 'ALLOW',
        internal: 'ALLOW',
        restricted: 'DENY',
        confidential: 'DENY',
        blocked: 'DENY',
      },
      // agentId -> allowed classes
      agent_class_allow: {},
    });
  }
  return { agentsPath, leasesPath, policyPath };
}

/**
 * Load domain into memory structures.
 * @param {string} domainRoot
 */
export function loadDomain(domainRoot) {
  const paths = ensureDomainLayout(domainRoot);
  const agentsDoc = readJson(paths.agentsPath, { v: 1, agents: {} });
  const leasesDoc = readJson(paths.leasesPath, { v: 1, leases: {} });
  const policy = readJson(paths.policyPath, { v: 1, require_identity: true });

  /** @type {Map<string, any>} */
  const leaseStore = new Map();
  for (const [leaseId, rec] of Object.entries(leasesDoc.leases || {})) {
    leaseStore.set(leaseId, { leaseId, ...rec });
  }

  return {
    domainRoot,
    paths,
    agents: agentsDoc.agents || {},
    leaseStore,
    leasesDoc,
    policy,
    saveLeases() {
      const leases = {};
      for (const [id, rec] of leaseStore.entries()) {
        const { leaseId, ...rest } = rec;
        leases[id] = rest;
      }
      atomicWrite(paths.leasesPath, { v: 1, leases });
    },
    saveAgents() {
      atomicWrite(paths.agentsPath, { v: 1, agents: this.agents });
    },
  };
}

/**
 * Register an agent and mint an active lease (local trust domain).
 *
 * Authorization (Rule 3 — security-critical policy mutation):
 * - Elevated classes (restricted/confidential) require **two distinct operators**
 *   (operatorToken + operatorToken2). Single-op cannot unilaterally elevate.
 * - Once any operator exists: plain public/internal join still needs **one**
 *   operator token (domain is secured).
 * - Open first-run solo (no operators): only public/internal may self-register.
 *
 * @param {ReturnType<typeof loadDomain>} domain
 * @param {{ agentId: string, role?: string, classes?: string[] }} agent
 * @param {{ operatorToken?: string, operatorToken2?: string }} [opts]
 * @returns {{ ok:true, agentId:string, leaseId:string }
 *          |{ ok:false, reason:string, next_action?:string }}
 */
export function registerAgentWithLease(domain, agent, opts = {}) {
  const agentId = agent?.agentId;
  if (!agentId || typeof agentId !== 'string') {
    return { ok: false, reason: 'agentId_required' };
  }

  const requested = Array.isArray(agent.classes) ? agent.classes.map(String) : ['public', 'internal'];
  const elevatedWanted = requested.some((c) => ELEVATED.includes(c));
  const secured = operatorCount(domain.domainRoot) > 0;
  const token = opts.operatorToken || process.env.KC_OPERATOR_TOKEN;
  const token2 = opts.operatorToken2 || process.env.KC_OPERATOR_TOKEN_2;
  let allowElevated = false;

  if (elevatedWanted) {
    // Quorum of 2 distinct operators — single bootstrap token cannot elevate.
    const q = assertOperatorQuorum(domain.domainRoot, token, token2);
    if (!q.ok) {
      return {
        ok: false,
        reason: q.reason || 'operator_quorum_required_for_elevated_classes',
        next_action:
          q.next_action ||
          'Elevated classes require two distinct operator tokens (--operator-token and --operator-token-2)',
      };
    }
    allowElevated = true;
  } else if (secured) {
    const auth = assertOperator(domain.domainRoot, token);
    if (!auth.ok) {
      return {
        ok: false,
        reason: 'operator_required_domain_secured',
        next_action:
          auth.reason === 'missing_operator_token'
            ? 'Pass operatorToken / KC_OPERATOR_TOKEN (bootstrap via knosky agent-register --bootstrap-operator)'
            : `Operator auth failed: ${auth.reason}`,
      };
    }
  }

  const classes = sanitizeClasses(requested, { allowElevated });
  if (elevatedWanted && !allowElevated) {
    return {
      ok: false,
      reason: 'operator_quorum_required_for_elevated_classes',
      next_action: 'Elevated district classes require two distinct operator tokens',
    };
  }

  domain.agents[agentId] = {
    agentId,
    role: agent.role || 'coder',
    classes,
    created_at: new Date().toISOString(),
  };
  domain.saveAgents();

  if (!domain.policy.agent_class_allow) domain.policy.agent_class_allow = {};
  domain.policy.agent_class_allow[agentId] = classes;
  try {
    atomicWrite(domain.paths.policyPath, domain.policy);
  } catch (err) {
    return { ok: false, reason: `policy_persist_failed: ${err.message || err}` };
  }

  const leaseId = `lease_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const rec = {
    leaseId,
    agentId,
    status: 'active',
    created_at: new Date().toISOString(),
    expires_at: null,
  };
  domain.leaseStore.set(leaseId, rec);
  domain.saveLeases();
  return { ok: true, agentId, leaseId };
}

/**
 * Build lattice rule functions from domain policy for a subject.
 * Subject: { agentId, node?, class?, tool }
 */
export function policyRulesFromDomain(policy) {
  const requireId = policy.require_identity !== false;
  const effects = policy.default_class_effect || {};
  const allowMap = policy.agent_class_allow || {};

  return [
    // identity present?
    (subject) => {
      if (!requireId) return NOT_APPLICABLE;
      if (!subject || !subject.agentId) return DENY;
      return ALLOW;
    },
    // class effect — DENY is sticky for elevated classes; non-elevated allowlist may only grant
    // classes that default is not DENY OR agent was listed AND class is public|internal.
    (subject) => {
      const cls = subject?.class || DEFAULT_CLASS;
      const eff = effects[cls];
      if (eff === 'DENY') {
        // agent_class_allow must NOT override DENY for restricted/confidential without those classes
        // already granted at registration time via quorum. At evaluation, listed classes can pass
        // only if the allowlist includes that exact class (set only under quorum at register time).
        const allowed = subject?.agentId ? allowMap[subject.agentId] : null;
        if (Array.isArray(allowed) && allowed.includes(cls) && !ELEVATED.includes(cls)) {
          return ALLOW;
        }
        if (Array.isArray(allowed) && allowed.includes(cls) && ELEVATED.includes(cls)) {
          // Elevated classes listed at register time (quorum-minted) may ALLOW
          return ALLOW;
        }
        return DENY;
      }
      if (eff === 'ALLOW') return ALLOW;
      return NOT_APPLICABLE;
    },
    // per-agent allowlist can expand public/internal when default is N/A
    (subject) => {
      if (!subject?.agentId) return NOT_APPLICABLE;
      const allowed = allowMap[subject.agentId];
      if (!Array.isArray(allowed)) return NOT_APPLICABLE;
      const cls = subject.class || DEFAULT_CLASS;
      if (allowed.includes(cls)) return ALLOW;
      return NOT_APPLICABLE;
    },
    // blocked class always deny
    (subject) => {
      const cls = subject?.class || DEFAULT_CLASS;
      if (cls === CLASS_BLOCKED) return DENY;
      return NOT_APPLICABLE;
    },
  ];
}

/**
 * Infer a representative class for a route payload (best/most open among hits).
 * Unclassified nodes default to `internal` for Team profile routing (policy can still deny),
 * so greenfield indexes without district_class metadata remain usable under Mode B.
 */
export function inferRouteClass(cityCtx, routeDoc) {
  try {
    const entries = [].concat(routeDoc?.route || [], routeDoc?.alternates || []);
    if (!entries.length) return CLASS_INTERNAL_FALLBACK();

    let best = CLASS_BLOCKED;
    let saw = false;
    for (const e of entries) {
      const id = e.id || (e.path ? `fs:${e.path}` : null);
      if (!id || !cityCtx?.byId) continue;
      const node = typeof cityCtx.byId.get === 'function' ? cityCtx.byId.get(id) : cityCtx.byId[id];
      if (!node) continue;
      saw = true;
      const cls = loadClass(node);
      // prefer least restrictive for "representative open class" of the destination set
      if (rank(cls) < rank(best)) best = cls;
    }
    if (!saw) return CLASS_INTERNAL_FALLBACK();
    // If everything unresolved stays blocked, treat as internal for team usability
    if (best === CLASS_BLOCKED) return CLASS_INTERNAL_FALLBACK();
    return best;
  } catch {
    return CLASS_INTERNAL_FALLBACK();
  }
}

function CLASS_INTERNAL_FALLBACK() {
  return 'internal';
}

function rank(cls) {
  const order = ['public', 'internal', 'restricted', 'confidential', 'blocked'];
  const i = order.indexOf(cls);
  return i < 0 ? 99 : i;
}

export { CLASS_RESTRICTED, CLASS_CONFIDENTIAL, DEFAULT_CLASS };
