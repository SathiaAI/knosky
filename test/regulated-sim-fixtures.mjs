// KnoSky "Regulated-Sim" environment (SAT-456).
// Real multi-repo set: kubernetes/kubernetes, kubernetes/client-go,
// kubernetes/kubectl, kubernetes/apimachinery — 4 repos, genuine cross-repo
// dependency graph, multiple SIGs / owners simulating overlapping-team messiness.
// Synthetically-authored adversarial policy / entitlement / classification data
// is layered on top: overlapping ownership, deliberately stale/conflicting rules,
// and a deprecated signing-key stub still present in the index (simulating a
// key that should have been rotated but is still detectable in repo history).
//
// Run:     node test/regulated-sim-fixtures.mjs
// Feeds:   SAT-448 (cross-repo graph rendering), SAT-437 (red-team suite)
// Exports: REGULATED_SIM_CTX — the city context consumed by both downstreams.

import { validateCity, SCHEMA_VERSION } from '../core/contract.mjs';
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';
import { parseDestination } from '../core/destination.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Regulated-Sim city definition
// ---------------------------------------------------------------------------
//
// Node-id convention: <repo-slug>:<path>  (store: 'git', ref: relative path)
// Cross-repo dependency edges use the same id scheme so the graph is navigable.
//
// Adversarial policy overlays are attached as extra metadata fields that feed
// SAT-437 (red-team) checks below; they are NOT stored in the serialized index
// (the contract allowlist drops them before any index write).
// ---------------------------------------------------------------------------

const REPOS = {
  KUBERNETES:   'kubernetes/kubernetes',
  CLIENT_GO:    'kubernetes/client-go',
  KUBECTL:      'kubernetes/kubectl',
  APIMACHINERY: 'kubernetes/apimachinery',
};

// categories mirror Kubernetes SIG groupings — simulating overlapping-team messiness
const CATEGORIES = [
  { id: 'api-machinery', label: 'API Machinery', color: '#4f8cff', order: 0 },
  { id: 'cli',          label: 'CLI',            color: '#34c759', order: 1 },
  { id: 'client',       label: 'Client',         color: '#ff9f0a', order: 2 },
  { id: 'storage',      label: 'Storage',        color: '#af52de', order: 3 },
  { id: 'policy',       label: 'Policy',         color: '#ff375f', order: 4 },
  { id: 'sig-auth',     label: 'SIG Auth',       color: '#5ac8fa', order: 5 },
];

//
// ── Helper to build a node literal ──────────────────────────────────────────
//
function node(id, { kind = 'file', title, summary, category, headings = [], tags = [],
                    links = [], churn = null, status, sensitive = false, repo }) {
  return {
    id,
    kind,
    title,
    summary: summary ? summary.slice(0, 200) : '',
    category,
    headings,
    tags,
    links,
    churn,
    ...(status ? { status } : {}),
    sensitive,
    provenance: {
      store: 'git',
      ref: id.replace(/^[^:]+:/, ''),        // strip the "repo:" prefix → path
      source_rev: repo === REPOS.KUBERNETES   ? 'k8s-v1.30.0'
                : repo === REPOS.CLIENT_GO    ? 'cg-v0.30.0'
                : repo === REPOS.KUBECTL      ? 'kc-v1.30.0'
                : /* APIMACHINERY */            'am-v0.30.0',
      repo,
    },
  };
}

const nodes = [
  // ── kubernetes/apimachinery ───────────────────────────────────────────────
  node('am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go', {
    kind: 'file', category: 'api-machinery',
    title: 'apimachinery/meta',
    summary: 'Core REST meta helpers used by all Kubernetes clients and the API server.',
    headings: ['ObjectMeta', 'TypeMeta', 'Accessor'],
    tags: ['apimachinery', 'meta', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go',
      'am:staging/src/k8s.io/apimachinery/pkg/types/uid.go',
    ],
    repo: REPOS.APIMACHINERY,
  }),

  node('am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go', {
    kind: 'file', category: 'api-machinery',
    title: 'apimachinery/runtime interfaces',
    summary: 'Object, Encoder, Decoder contracts — the serialization contract every codec must satisfy.',
    headings: ['Object', 'Encoder', 'Decoder', 'Serializer'],
    tags: ['apimachinery', 'runtime', 'sig-api-machinery'],
    links: [],
    repo: REPOS.APIMACHINERY,
  }),

  node('am:staging/src/k8s.io/apimachinery/pkg/types/uid.go', {
    kind: 'file', category: 'api-machinery',
    title: 'apimachinery/types/uid',
    summary: 'UID type alias. Referenced across kubernetes, client-go, and kubectl.',
    headings: ['UID'],
    tags: ['apimachinery', 'types'],
    links: [],
    repo: REPOS.APIMACHINERY,
  }),

  // ── kubernetes/client-go ─────────────────────────────────────────────────
  node('cg:tools/cache/controller.go', {
    kind: 'file', category: 'client',
    title: 'client-go/cache/controller',
    summary: 'List-Watch controller driving the Kubernetes informer pattern.',
    headings: ['Controller', 'NewInformer', 'processLoop'],
    tags: ['client-go', 'cache', 'informer', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',    // cross-repo
      'cg:tools/cache/store.go',
      'cg:rest/client.go',
    ],
    churn: { c: 18, b: 0.92 }, // high-churn: frequently touched across releases
    repo: REPOS.CLIENT_GO,
  }),

  node('cg:tools/cache/store.go', {
    kind: 'file', category: 'client',
    title: 'client-go/cache/store',
    summary: 'Thread-safe in-memory object store with indexers.',
    headings: ['Store', 'ThreadSafeStore', 'Indexer'],
    tags: ['client-go', 'cache', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go', // cross-repo
    ],
    repo: REPOS.CLIENT_GO,
  }),

  node('cg:rest/client.go', {
    kind: 'file', category: 'client',
    title: 'client-go/rest/client',
    summary: 'RESTClient wraps http.Client with Kubernetes-specific verb methods.',
    headings: ['RESTClient', 'Do', 'Get', 'Post', 'Delete'],
    tags: ['client-go', 'rest', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/types/uid.go',   // cross-repo
    ],
    repo: REPOS.CLIENT_GO,
  }),

  // ── kubernetes/kubectl ───────────────────────────────────────────────────
  node('kc:pkg/cmd/get/get.go', {
    kind: 'file', category: 'cli',
    title: 'kubectl/cmd/get',
    summary: 'Implements `kubectl get` — list and describe Kubernetes resources.',
    headings: ['NewCmdGet', 'RunGet', 'transformRequests'],
    tags: ['kubectl', 'cli', 'sig-cli'],
    links: [
      'cg:tools/cache/controller.go',                          // cross-repo
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go', // cross-repo
      'kc:pkg/cmd/util/factory.go',
    ],
    churn: { c: 31, b: 0.97 }, // highest-churn file — CLI surface area changes frequently
    repo: REPOS.KUBECTL,
  }),

  node('kc:pkg/cmd/util/factory.go', {
    kind: 'file', category: 'cli',
    title: 'kubectl/util/factory',
    summary: 'Factory builds kubectl command dependencies: client, discovery, rest mapper.',
    headings: ['Factory', 'NewFactory', 'ToRESTMapper'],
    tags: ['kubectl', 'cli', 'sig-cli'],
    links: [
      'cg:rest/client.go',   // cross-repo
    ],
    repo: REPOS.KUBECTL,
  }),

  node('kc:pkg/cmd/apply/apply.go', {
    kind: 'file', category: 'cli',
    title: 'kubectl/cmd/apply',
    summary: 'Implements `kubectl apply` — server-side / client-side apply with 3-way merge.',
    headings: ['NewCmdApply', 'RunApply', 'serverSideApply'],
    tags: ['kubectl', 'cli', 'sig-cli', 'sig-api-machinery'],
    links: [
      'kc:pkg/cmd/util/factory.go',
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go', // cross-repo
    ],
    repo: REPOS.KUBECTL,
  }),

  // ── kubernetes/kubernetes (api-server, storage, auth) ────────────────────
  node('k8s:staging/src/k8s.io/apiserver/pkg/registry/rest/rest.go', {
    kind: 'file', category: 'storage',
    title: 'apiserver/registry/rest',
    summary: 'REST storage interfaces — Create, Update, Delete, Get, List, Watch contracts.',
    headings: ['Storage', 'Creater', 'Updater', 'Getter', 'Lister', 'Watcher'],
    tags: ['kubernetes', 'apiserver', 'storage', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go', // cross-repo
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',      // cross-repo
    ],
    repo: REPOS.KUBERNETES,
  }),

  node('k8s:plugin/pkg/auth/authorizer/rbac/rbac.go', {
    kind: 'file', category: 'sig-auth',
    title: 'kubernetes/auth/rbac',
    summary: 'RBAC authorizer: evaluates policy rules against request attributes.',
    headings: ['RBACAuthorizer', 'Authorize', 'RulesAllow'],
    tags: ['kubernetes', 'rbac', 'sig-auth', 'sig-api-machinery'],
    links: [
      'k8s:staging/src/k8s.io/apiserver/pkg/registry/rest/rest.go',
    ],
    churn: { c: 9, b: 0.78 },
    repo: REPOS.KUBERNETES,
  }),

  // ── Policy / classification nodes (SAT-437 adversarial layer) ────────────
  // These represent synthetically-authored entitlement + policy data.
  // - OWNER-CONFLICT: two nodes claim ownership of the same path (overlapping SIG ownership)
  // - STALE-POLICY: policy last updated 2022, references a signing key (deprecated)
  // - DEPRECATED-KEY: signing key stub still present — should trigger red-team detection

  node('policy:ownership/sig-api-machinery.yaml', {
    kind: 'file', category: 'policy',
    title: 'SIG API-Machinery ownership rules',
    summary: 'OWNERS file: SIG-API-Machinery claims apimachinery/*, client-go/tools/cache, apiserver/registry.',
    headings: ['approvers', 'reviewers', 'labels'],
    tags: ['policy', 'ownership', 'sig-api-machinery', 'owners'],
    // intentionally overlaps with sig-cli.yaml below — adversarial conflict
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',
      'cg:tools/cache/controller.go',
    ],
    status: 'active',
    repo: REPOS.KUBERNETES,
  }),

  node('policy:ownership/sig-cli.yaml', {
    kind: 'file', category: 'policy',
    title: 'SIG CLI ownership rules',
    summary: 'OWNERS file: SIG-CLI claims kubectl/*, client-go (ALL files) — overlaps SIG-API-Machinery claim on client-go.',
    headings: ['approvers', 'reviewers', 'labels'],
    tags: ['policy', 'ownership', 'sig-cli', 'owners'],
    // ADVERSARIAL: also claims client-go, creating an ownership conflict
    links: [
      'kc:pkg/cmd/get/get.go',
      'kc:pkg/cmd/apply/apply.go',
      'cg:rest/client.go',               // <-- conflicting claim vs sig-api-machinery
      'cg:tools/cache/controller.go',    // <-- conflicting claim
    ],
    status: 'active',
    repo: REPOS.KUBECTL,
  }),

  node('policy:classification/data-sensitivity.yaml', {
    kind: 'file', category: 'policy',
    title: 'Data sensitivity classification (STALE)',
    // deliberately stale — last-reviewed 2022, references a key-id no longer valid
    summary: 'Classifies API-server response bodies as RESTRICTED. Last reviewed 2022-01-15. References signing key KID-2021-DEPRECATED.',
    headings: ['classification', 'signing-key', 'last-reviewed'],
    tags: ['policy', 'classification', 'stale', 'sig-auth'],
    links: [
      'k8s:plugin/pkg/auth/authorizer/rbac/rbac.go',
      'policy:signing/deprecated-key-stub.pem',   // points to deprecated key
    ],
    status: 'stale',          // deliberate status marker for red-team detection
    sensitive: true,
    repo: REPOS.KUBERNETES,
  }),

  // DEPRECATED SIGNING KEY STUB — still present in index history, never rotated.
  // Content is a deliberately fake/non-functional PEM stub (no real key material).
  // The title string matches the SECRET_PATTERNS prefix test (begins with -----BEGIN)
  // so the contract's scrubText() will redact it — this is intentional: the test
  // below asserts that the *raw* node title carries the red-team signal BEFORE
  // serialization, and the SERIALIZED title is scrubbed (defense-in-depth check).
  node('policy:signing/deprecated-key-stub.pem', {
    kind: 'file', category: 'sig-auth',
    title: '-----BEGIN RSA PRIVATE KEY----- (DEPRECATED KID-2021 — stub, non-functional)',
    summary: 'DEPRECATED signing key KID-2021. Should have been rotated 2023-01-01. Still present in index.',
    headings: ['KID-2021-DEPRECATED', 'rotation-due'],
    tags: ['signing-key', 'deprecated', 'sig-auth', 'red-team-target'],
    links: [],
    status: 'deprecated',
    sensitive: true,
    repo: REPOS.KUBERNETES,
  }),
];

// Build byId map
const byId = new Map(nodes.map(n => [n.id, n]));

// Canonical city envelope (schema_version 2.0 contract)
export const REGULATED_SIM_CTX = {
  city: {
    schema_version: SCHEMA_VERSION,
    generated_at: '2026-07-02T00:00:00.000Z',
    source: { kind: 'git', ref: 'regulated-sim', rev: 'sat-456' },
    categories: CATEGORIES,
    node_count: nodes.length,
    nodes,
  },
  byId,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// (1) City envelope structure is valid under contract v2
{
  const result = validateCity(REGULATED_SIM_CTX.city);
  ok('(1) regulated-sim city passes validateCity', result.ok === true, JSON.stringify(result.errors));
  ok('(1) schema_version is 2.0', REGULATED_SIM_CTX.city.schema_version === '2.0');
  ok('(1) node_count matches nodes.length', REGULATED_SIM_CTX.city.node_count === nodes.length);
  ok('(1) all 6 SIG categories present', REGULATED_SIM_CTX.city.categories.length === 6);
}

// (2) Multi-repo: cross-repo edges exist in the graph
{
  // client-go controller imports apimachinery meta (cross-repo)
  const cacheCtrl = byId.get('cg:tools/cache/controller.go');
  ok('(2) cg/cache/controller exists', cacheCtrl !== undefined);
  const hasCrossRepoEdge = (cacheCtrl?.links || []).includes(
    'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',
  );
  ok('(2) client-go->apimachinery cross-repo edge present', hasCrossRepoEdge);

  // kubectl get imports both client-go and apimachinery
  const kubectlGet = byId.get('kc:pkg/cmd/get/get.go');
  ok('(2) kubectl/get exists', kubectlGet !== undefined);
  const linksClientGo = (kubectlGet?.links || []).some(l => l.startsWith('cg:'));
  const linksApimachinery = (kubectlGet?.links || []).some(l => l.startsWith('am:'));
  ok('(2) kubectl/get has cross-repo edge to client-go', linksClientGo);
  ok('(2) kubectl/get has cross-repo edge to apimachinery', linksApimachinery);
}

// (3) Cross-repo depChainTo: kubernetes/apimachinery types/uid is imported
//     transitively by kubectl through client-go
{
  const { matched, matchStrength } = parseDestination(
    REGULATED_SIM_CTX,
    'depChainTo:am:staging/src/k8s.io/apimachinery/pkg/types/uid.go',
    20,
  );
  const ids = matched.map(n => n.id);
  // Direct importer: cg/rest/client.go (imports uid)
  ok('(3) depChainTo uid: cg/rest/client.go is a caller', ids.includes('cg:rest/client.go'), ids.join('\n'));
  // Transitive caller: kubectl/factory imports cg/rest  →  chain includes factory
  ok('(3) depChainTo uid: kc/util/factory.go is a transitive caller', ids.includes('kc:pkg/cmd/util/factory.go'), ids.join('\n'));
  ok('(3) depChainTo: matchStrength is chain', matchStrength === 'chain');
}

// (4) Route doc for kubectl/cmd/get is valid and includes cross-repo nodes
{
  const doc = kcRoute(REGULATED_SIM_CTX, 'file:kc:pkg/cmd/get/get.go');
  const result = validateRouteDoc(doc);
  ok('(4) route doc for kubectl/get passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  ok('(4) route has non-empty entries', doc.route.length > 0);
  ok('(4) advisory is true', doc.advisory === true);
  // The route path for cross-repo nodes uses the node's provenance.ref (path within repo)
  const routePaths = doc.route.map(e => e.path);
  ok('(4) kubectl/get itself appears in route', routePaths.some(p => p.includes('get.go')), routePaths.join(', '));
  // High-churn file should generate a churn caveat
  const hasChurnCaveat = doc.caveats.some(c => c.includes('recently changed'));
  ok('(4) high-churn (kubectl/get) generates recently-changed caveat', hasChurnCaveat, JSON.stringify(doc.caveats));
}

// (5) Adversarial overlap: both SIG ownership policies link to the same client-go
//     nodes — detect that 2 policy nodes claim overlapping jurisdiction
{
  const { matched } = parseDestination(
    REGULATED_SIM_CTX,
    'depChainTo:cg:tools/cache/controller.go',
    20,
  );
  const policyCallers = matched.filter(n => n.category === 'policy');
  ok('(5) both SIG policy files are callers of cg/cache/controller (overlap detected)',
    policyCallers.length >= 2,
    policyCallers.map(n => n.id).join(', '));
}

// (6) Stale/conflicting policy node is detectable by status field
{
  const stalePolicy = nodes.find(n => n.status === 'stale');
  ok('(6) stale policy node exists with status=stale', stalePolicy !== undefined, stalePolicy?.id);
  ok('(6) stale policy is sensitive', stalePolicy?.sensitive === true);
  ok('(6) stale policy references deprecated key via links',
    (stalePolicy?.links || []).includes('policy:signing/deprecated-key-stub.pem'),
    JSON.stringify(stalePolicy?.links));
}

// (7) Deprecated signing key stub is present and carries red-team signals
{
  const depKey = byId.get('policy:signing/deprecated-key-stub.pem');
  ok('(7) deprecated key stub node exists', depKey !== undefined);
  ok('(7) key stub status is deprecated', depKey?.status === 'deprecated');
  ok('(7) key stub is tagged as red-team-target', (depKey?.tags || []).includes('red-team-target'));
  ok('(7) key stub title contains private-key marker (pre-scrub signal)',
    typeof depKey?.title === 'string' && depKey.title.includes('-----BEGIN RSA PRIVATE KEY-----'));
}

// (8) Contract serialization scrubs the deprecated key title
//     serializeNode() is in contract.mjs; we import it inline here to verify
//     defense-in-depth: the adversarial title is scrubbed before any index write.
{
  const { serializeNode } = await import('../core/contract.mjs');
  const depKey = byId.get('policy:signing/deprecated-key-stub.pem');
  const serialized = serializeNode(depKey);
  ok('(8) serializeNode scrubs private-key pattern from title',
    !serialized.title.includes('-----BEGIN RSA PRIVATE KEY-----'),
    JSON.stringify(serialized.title));
  ok('(8) serialized title is [REDACTED]', serialized.title.includes('[REDACTED]'));
  // sensitive field must survive the allowlist (it is in NODE_FIELD_ALLOWLIST)
  ok('(8) sensitive flag survives serializeNode', serialized.sensitive === true);
}

// (9) Multi-repo isolation: district and node-id namespace separate repos cleanly.
//
// The `folder:` destination matches provenance.ref (intra-repo path), so it is
// not the right tool for cross-repo isolation — that is for SAT-448 rendering.
// Here we validate that:
//   (a) all `cli` category nodes belong to REPOS.KUBECTL
//   (b) all `api-machinery` category nodes belong to either apimachinery or client-go or k8s/*
//   (c) the full graph spans all 4 repos (provenance.repo values are all distinct)
{
  const { matched: cliNodes } = parseDestination(REGULATED_SIM_CTX, 'district:cli', 20);
  const allCli = cliNodes.every(n => n.provenance?.repo === REPOS.KUBECTL);
  ok('(9a) district:cli returns only kubectl-repo nodes', allCli && cliNodes.length > 0,
    cliNodes.map(n => n.id).join(', '));

  const repos = new Set(nodes.map(n => n.provenance?.repo).filter(Boolean));
  ok('(9b) all 4 repos appear in the graph', repos.size === 4,
    [...repos].join(', '));

  // Every node id must start with a known repo-code prefix — no bare paths
  const validPrefixes = ['am:', 'cg:', 'kc:', 'k8s:', 'policy:'];
  const badIds = nodes.filter(n => !validPrefixes.some(p => n.id.startsWith(p)));
  ok('(9c) all node ids carry a repo-code prefix', badIds.length === 0,
    badIds.map(n => n.id).join(', '));
}

// (10) District routing finds all policy nodes
{
  const doc = kcRoute(REGULATED_SIM_CTX, 'district:policy');
  const result = validateRouteDoc(doc);
  ok('(10) district:policy route passes validateRouteDoc', result.ok === true, JSON.stringify(result.errors));
  const policyRoutes = doc.route.filter(e => e.path.startsWith('ownership/') || e.path.startsWith('classification/'));
  ok('(10) district:policy route includes policy nodes', policyRoutes.length >= 2,
    doc.route.map(e => e.path).join(', '));
}

// (11) No absolute or ".." paths in any route/alternates doc produced from this ctx
{
  const destinations = [
    'file:kc:pkg/cmd/apply/apply.go',
    'file:k8s:plugin/pkg/auth/authorizer/rbac/rbac.go',
    'district:sig-auth',
    'rbac authorization kubernetes',
  ];
  for (const dest of destinations) {
    const doc = kcRoute(REGULATED_SIM_CTX, dest);
    const allEntries = [...(doc.route || []), ...(doc.alternates || [])];
    const badPath = allEntries.find(e => {
      const p = e.path || '';
      return p.startsWith('/') || /^[A-Za-z]:[\\\/]/.test(p) || p.split(/[/\\]/).some(s => s === '..');
    });
    ok(`(11) no absolute or ".." paths in route for "${dest}"`, badPath === undefined,
      badPath ? JSON.stringify(badPath) : '');
  }
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
