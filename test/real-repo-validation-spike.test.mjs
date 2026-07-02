// SAT-449: Real-repo validation spike.
//
// Confirms KnoSky's rendering/indexing layers hold up at real scale (D-165 gate)
// against three environments:
//
//   ENV A — "Solo/Startup" monorepo: vercel/next.js.
//           sim-solo.test.mjs handles the real clone path (KC_RUN_SIM_TESTS=1).
//           This file validates the D-165 *rendering* + *streaming* + *LOD* invariants
//           at equivalent scale (6000 nodes, 12 categories) using a synthetic city,
//           so the gate doesn't require network access.
//
//   ENV B — "Regulated-Sim" multi-repo: kubernetes/* (4 repos, genuine cross-repo
//           dependency graph, 6 SIG categories).  Built inline to avoid importing
//           regulated-sim-fixtures.mjs which calls process.exit() at module scope.
//           Nodes are exactly the same as in regulated-sim-fixtures.mjs.
//
//   ADV   — Adversarial policy overlay on ENV B (stale/conflicting ownership rules,
//           deprecated signing-key stub) — per SAT-457 policy fuzzer design.
//
// Per ticket: results need structural quality review (not just green checkmarks).
// The QUALITY REPORT at the end provides the structural summary for that review.
//
// Run:   node test/real-repo-validation-spike.test.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  lodForZoom,
  viewportClip, isVisible,
  buildClusters,
  makeBatches,
  shouldStream,
  STREAM_THRESHOLD, STREAM_BATCH_SIZE,
  LOD_FULL_THRESHOLD, LOD_SIMPLE_THRESHOLD, LOD_DOT_THRESHOLD,
  LOD_FULL, LOD_SIMPLE, LOD_DOT, LOD_CLUSTER,
} from '../core/lod.mjs';
import { layoutCity } from '../core/layout.mjs';
import { getCrossRepoEdges, getRepoBoundaries } from '../core/cross-repo.mjs';
import { kcRoute } from '../core/route.mjs';
import { validateRouteDoc } from '../core/schema.mjs';
import { parseDestination } from '../core/destination.mjs';
import { SCHEMA_VERSION } from '../core/contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Renderer tile constants (must mirror city.template.html line 195)
// ---------------------------------------------------------------------------
const TW = 64, TH = 32;
const isoToWorld = (gx, gy) => ({ x: (gx - gy) * (TW / 2), y: (gx + gy) * (TH / 2) });

// ---------------------------------------------------------------------------
// Helper: adapt layoutCity output → renderer-style { d, bx, by } objects.
// ---------------------------------------------------------------------------
function adaptNodes(layoutResult) {
  return layoutResult.nodes.map(n => {
    const w = isoToWorld(n.gx, n.gy);
    return { ...n, d: n.category, bx: w.x, by: w.y };
  });
}

// ---------------------------------------------------------------------------
// ENV B fixture: kubernetes 4-repo regulated-sim (same node set as
// test/regulated-sim-fixtures.mjs — kept in sync by description, not import,
// to avoid that file's top-level process.exit()).
// ---------------------------------------------------------------------------

const REPOS = {
  KUBERNETES:   'kubernetes/kubernetes',
  CLIENT_GO:    'kubernetes/client-go',
  KUBECTL:      'kubernetes/kubectl',
  APIMACHINERY: 'kubernetes/apimachinery',
};

const REG_CATEGORIES = [
  { id: 'api-machinery', label: 'API Machinery', color: '#4f8cff', order: 0 },
  { id: 'cli',          label: 'CLI',            color: '#34c759', order: 1 },
  { id: 'client',       label: 'Client',         color: '#ff9f0a', order: 2 },
  { id: 'storage',      label: 'Storage',        color: '#af52de', order: 3 },
  { id: 'policy',       label: 'Policy',         color: '#ff375f', order: 4 },
  { id: 'sig-auth',     label: 'SIG Auth',       color: '#5ac8fa', order: 5 },
];

function regNode(id, { kind = 'file', title, summary = '', category, headings = [], tags = [],
                       links = [], churn = null, status, sensitive = false, repo }) {
  return {
    id, kind, title,
    summary: summary.slice(0, 200),
    category, headings, tags, links, churn,
    ...(status ? { status } : {}),
    sensitive,
    provenance: {
      store: 'git',
      ref: id.replace(/^[^:]+:/, ''),
      source_rev: repo === REPOS.KUBERNETES   ? 'k8s-v1.30.0'
                : repo === REPOS.CLIENT_GO    ? 'cg-v0.30.0'
                : repo === REPOS.KUBECTL      ? 'kc-v1.30.0'
                : /* APIMACHINERY */            'am-v0.30.0',
      repo,
    },
  };
}

const regNodes = [
  // kubernetes/apimachinery
  regNode('am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go', {
    category: 'api-machinery', title: 'apimachinery/meta',
    summary: 'Core REST meta helpers used by all Kubernetes clients and the API server.',
    headings: ['ObjectMeta', 'TypeMeta', 'Accessor'],
    tags: ['apimachinery', 'meta', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go',
      'am:staging/src/k8s.io/apimachinery/pkg/types/uid.go',
    ],
    repo: REPOS.APIMACHINERY,
  }),
  regNode('am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go', {
    category: 'api-machinery', title: 'apimachinery/runtime interfaces',
    summary: 'Object, Encoder, Decoder contracts.',
    headings: ['Object', 'Encoder', 'Decoder', 'Serializer'],
    tags: ['apimachinery', 'runtime', 'sig-api-machinery'],
    links: [], repo: REPOS.APIMACHINERY,
  }),
  regNode('am:staging/src/k8s.io/apimachinery/pkg/types/uid.go', {
    category: 'api-machinery', title: 'apimachinery/types/uid',
    summary: 'UID type alias.',
    headings: ['UID'], tags: ['apimachinery', 'types'],
    links: [], repo: REPOS.APIMACHINERY,
  }),
  // kubernetes/client-go
  regNode('cg:tools/cache/controller.go', {
    category: 'client', title: 'client-go/cache/controller',
    summary: 'List-Watch controller driving the Kubernetes informer pattern.',
    headings: ['Controller', 'NewInformer', 'processLoop'],
    tags: ['client-go', 'cache', 'informer', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',    // cross-repo
      'cg:tools/cache/store.go',
      'cg:rest/client.go',
    ],
    churn: { c: 18, b: 0.92 }, repo: REPOS.CLIENT_GO,
  }),
  regNode('cg:tools/cache/store.go', {
    category: 'client', title: 'client-go/cache/store',
    summary: 'Thread-safe in-memory object store with indexers.',
    headings: ['Store', 'ThreadSafeStore', 'Indexer'],
    tags: ['client-go', 'cache', 'sig-api-machinery'],
    links: ['am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go'], // cross-repo
    repo: REPOS.CLIENT_GO,
  }),
  regNode('cg:rest/client.go', {
    category: 'client', title: 'client-go/rest/client',
    summary: 'RESTClient wraps http.Client with Kubernetes-specific verb methods.',
    headings: ['RESTClient', 'Do', 'Get', 'Post', 'Delete'],
    tags: ['client-go', 'rest', 'sig-api-machinery'],
    links: ['am:staging/src/k8s.io/apimachinery/pkg/types/uid.go'],  // cross-repo
    repo: REPOS.CLIENT_GO,
  }),
  // kubernetes/kubectl
  regNode('kc:pkg/cmd/get/get.go', {
    category: 'cli', title: 'kubectl/cmd/get',
    summary: 'Implements `kubectl get`.',
    headings: ['NewCmdGet', 'RunGet', 'transformRequests'],
    tags: ['kubectl', 'cli', 'sig-cli'],
    links: [
      'cg:tools/cache/controller.go',                                // cross-repo
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',    // cross-repo
      'kc:pkg/cmd/util/factory.go',
    ],
    churn: { c: 31, b: 0.97 }, repo: REPOS.KUBECTL,
  }),
  regNode('kc:pkg/cmd/util/factory.go', {
    category: 'cli', title: 'kubectl/util/factory',
    summary: 'Factory builds kubectl command dependencies.',
    headings: ['Factory', 'NewFactory', 'ToRESTMapper'],
    tags: ['kubectl', 'cli', 'sig-cli'],
    links: ['cg:rest/client.go'],  // cross-repo
    repo: REPOS.KUBECTL,
  }),
  regNode('kc:pkg/cmd/apply/apply.go', {
    category: 'cli', title: 'kubectl/cmd/apply',
    summary: 'Implements `kubectl apply`.',
    headings: ['NewCmdApply', 'RunApply', 'serverSideApply'],
    tags: ['kubectl', 'cli', 'sig-cli', 'sig-api-machinery'],
    links: [
      'kc:pkg/cmd/util/factory.go',
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',    // cross-repo
    ],
    repo: REPOS.KUBECTL,
  }),
  // kubernetes/kubernetes
  regNode('k8s:staging/src/k8s.io/apiserver/pkg/registry/rest/rest.go', {
    category: 'storage', title: 'apiserver/registry/rest',
    summary: 'REST storage interfaces — Create, Update, Delete, Get, List, Watch contracts.',
    headings: ['Storage', 'Creater', 'Updater', 'Getter', 'Lister', 'Watcher'],
    tags: ['kubernetes', 'apiserver', 'storage', 'sig-api-machinery'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/runtime/interfaces.go', // cross-repo
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',      // cross-repo
    ],
    repo: REPOS.KUBERNETES,
  }),
  regNode('k8s:plugin/pkg/auth/authorizer/rbac/rbac.go', {
    category: 'sig-auth', title: 'kubernetes/auth/rbac',
    summary: 'RBAC authorizer: evaluates policy rules against request attributes.',
    headings: ['RBACAuthorizer', 'Authorize', 'RulesAllow'],
    tags: ['kubernetes', 'rbac', 'sig-auth', 'sig-api-machinery'],
    links: ['k8s:staging/src/k8s.io/apiserver/pkg/registry/rest/rest.go'],
    churn: { c: 9, b: 0.78 }, repo: REPOS.KUBERNETES,
  }),
  // Adversarial policy overlay (SAT-457 policy fuzzer output on ENV B)
  regNode('policy:ownership/sig-api-machinery.yaml', {
    category: 'policy', title: 'SIG API-Machinery ownership rules',
    summary: 'OWNERS file: SIG-API-Machinery claims apimachinery/*, client-go/tools/cache.',
    headings: ['approvers', 'reviewers', 'labels'],
    tags: ['policy', 'ownership', 'sig-api-machinery', 'owners'],
    links: [
      'am:staging/src/k8s.io/apimachinery/pkg/api/meta/meta.go',
      'cg:tools/cache/controller.go',
    ],
    status: 'active', repo: REPOS.KUBERNETES,
  }),
  regNode('policy:ownership/sig-cli.yaml', {
    category: 'policy', title: 'SIG CLI ownership rules',
    summary: 'OWNERS file: SIG-CLI claims kubectl/*, client-go (ALL) — overlaps SIG-API-Machinery.',
    headings: ['approvers', 'reviewers', 'labels'],
    tags: ['policy', 'ownership', 'sig-cli', 'owners'],
    links: [
      'kc:pkg/cmd/get/get.go',
      'kc:pkg/cmd/apply/apply.go',
      'cg:rest/client.go',             // conflicting claim vs sig-api-machinery
      'cg:tools/cache/controller.go',  // conflicting claim
    ],
    status: 'active', repo: REPOS.KUBECTL,
  }),
  regNode('policy:classification/data-sensitivity.yaml', {
    category: 'policy', title: 'Data sensitivity classification (STALE)',
    summary: 'Classifies API-server responses RESTRICTED. Last reviewed 2022-01-15. References KID-2021-DEPRECATED.',
    headings: ['classification', 'signing-key', 'last-reviewed'],
    tags: ['policy', 'classification', 'stale', 'sig-auth'],
    links: [
      'k8s:plugin/pkg/auth/authorizer/rbac/rbac.go',
      'policy:signing/deprecated-key-stub.pem',
    ],
    status: 'stale', sensitive: true, repo: REPOS.KUBERNETES,
  }),
  // Deprecated signing-key stub (SAT-457 adversarial case — still present in index)
  regNode('policy:signing/deprecated-key-stub.pem', {
    category: 'sig-auth',
    title: '-----BEGIN RSA PRIVATE KEY----- (DEPRECATED KID-2021 — stub, non-functional)',
    summary: 'DEPRECATED signing key KID-2021. Should have been rotated 2023-01-01.',
    headings: ['KID-2021-DEPRECATED', 'rotation-due'],
    tags: ['signing-key', 'deprecated', 'sig-auth', 'red-team-target'],
    links: [], status: 'deprecated', sensitive: true, repo: REPOS.KUBERNETES,
  }),
];

const regCity = {
  schema_version: SCHEMA_VERSION,
  generated_at: '2026-07-02T00:00:00.000Z',
  source: { kind: 'git', ref: 'regulated-sim', rev: 'sat-456' },
  categories: REG_CATEGORIES,
  node_count: regNodes.length,
  nodes: regNodes,
};
const regById = new Map(regNodes.map(n => [n.id, n]));
const regCtx  = { city: regCity, byId: regById };

// ===========================================================================
// SECTION 1 — ENV B (Regulated-Sim, kubernetes 4-repo)
// Layout + LOD + clustering + viewport culling + streaming + cross-repo edges
// ===========================================================================
console.log('\n=== ENV B — Regulated-Sim (kubernetes 4-repo, 15 nodes) ===');

// (R1) layoutCity produces sane dimensions for ENV B
{
  let layout = null, threw = false;
  try { layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES }); } catch { threw = true; }
  ok('(R1) ENV-B layoutCity does not throw', !threw);
  ok('(R1) ENV-B layout.nodes.length === regNodes.length',
    layout && layout.nodes.length === regNodes.length);
  ok('(R1) ENV-B gridW >= 1', layout && layout.gridW >= 1);
  ok('(R1) ENV-B gridH >= 1', layout && layout.gridH >= 1);
  ok('(R1) ENV-B districts count matches 6 SIG categories',
    layout && layout.districts.length === REG_CATEGORIES.length,
    layout ? `districts=${layout.districts.length} cats=${REG_CATEGORIES.length}` : '');

  const badPos = layout ? layout.nodes.filter(n => !Number.isFinite(n.gx) || !Number.isFinite(n.gy)) : [];
  ok('(R1) ENV-B all nodes have finite gx/gy', badPos.length === 0,
    badPos.map(n => n.id).join(', '));
}

// (R2) LOD tiers behave correctly for the expected zoom range
{
  ok('(R2) lodForZoom(1.0) → LOD_FULL',     lodForZoom(1.0)  === LOD_FULL);
  ok('(R2) lodForZoom(0.20) → LOD_SIMPLE',  lodForZoom(0.20) === LOD_SIMPLE);
  ok('(R2) lodForZoom(0.08) → LOD_DOT',     lodForZoom(0.08) === LOD_DOT);
  ok('(R2) lodForZoom(0.03) → LOD_CLUSTER', lodForZoom(0.03) === LOD_CLUSTER);
}

// (R3) Viewport culling: with a camera that correctly encompasses the full iso-world
//      city extent all nodes are visible.  The iso projection (bx=(gx-gy)*TW/2) can
//      produce negative bx values for districts on the left side of the city, so we
//      offset the camera to bring the minimum world coordinate to the viewport origin.
{
  const layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES });
  const adapted = adaptNodes(layout);
  const minBx = Math.min(...adapted.map(n => n.bx));
  const maxBx = Math.max(...adapted.map(n => n.bx));
  const minBy = Math.min(...adapted.map(n => n.by));
  const maxBy = Math.max(...adapted.map(n => n.by));
  // Canvas sized to the full world extent plus a small margin
  const margin = 64;
  const cw = maxBx - minBx + margin * 2;
  const ch = maxBy - minBy + margin * 2;
  // Camera shifted so that minBx/minBy maps to (margin, margin) on screen
  const cam = { x: -minBx + margin, y: -minBy + margin, zoom: 1 };
  const clip = viewportClip(cam, cw, ch, 0);
  const notVisible = adapted.filter(n => !isVisible(n.bx, n.by, clip));
  ok('(R3) ENV-B all nodes visible when viewport correctly encompasses city extent',
    notVisible.length === 0, `${notVisible.length} nodes outside clip`);
}

// (R4) buildClusters at LOD_CLUSTER zoom covers every category
{
  const layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES });
  const adapted = adaptNodes(layout);
  const dcfg = Object.fromEntries(REG_CATEGORIES.map(c => [c.id, { name: c.label, color: c.color }]));
  const clusters = buildClusters(adapted, dcfg);
  ok('(R4) ENV-B cluster count equals 6 SIG categories',
    clusters.length === REG_CATEGORIES.length,
    `clusters=${clusters.length} cats=${REG_CATEGORIES.length}`);
  ok('(R4) ENV-B every cluster has count >= 1', clusters.every(c => c.count >= 1));
  ok('(R4) ENV-B cluster total node count matches regNodes.length',
    clusters.reduce((s, c) => s + c.count, 0) === regNodes.length);
  ok('(R4) ENV-B cluster centroids are finite',
    clusters.every(c => Number.isFinite(c.wx) && Number.isFinite(c.wy)));
}

// (R5) Streaming geometry: 14 nodes < STREAM_THRESHOLD — no streaming needed
{
  ok('(R5) ENV-B (14 nodes) does NOT trigger streaming',
    !shouldStream(regNodes.length), `nodeCount=${regNodes.length} threshold=${STREAM_THRESHOLD}`);
}

// (R6) Cross-repo edges: genuine multi-repo dependency graph
{
  const edges = getCrossRepoEdges(regCtx);
  ok('(R6) ENV-B has cross-repo edges', edges.length > 0, `crossRepoEdges=${edges.length}`);

  const boundaries = getRepoBoundaries(regCtx);
  ok('(R6) ENV-B spans 4 repos (kubernetes/*)', boundaries.length === 4,
    boundaries.map(b => b.repo).join(', '));

  const knownRepos = new Set(boundaries.map(b => b.repo));
  const badEdges = edges.filter(e => !knownRepos.has(e.fromRepo) || !knownRepos.has(e.toRepo));
  ok('(R6) all cross-repo edge endpoints are in known repos', badEdges.length === 0);

  const selfEdges = edges.filter(e => e.fromRepo === e.toRepo);
  ok('(R6) no same-repo edge in getCrossRepoEdges result', selfEdges.length === 0);
}

// (R7) Route docs for multi-repo nodes: valid, advisory, relative paths
{
  const focusFiles = [
    'file:kc:pkg/cmd/get/get.go',
    'file:cg:tools/cache/controller.go',
    'file:k8s:plugin/pkg/auth/authorizer/rbac/rbac.go',
  ];
  for (const dest of focusFiles) {
    const doc = kcRoute(regCtx, dest);
    const res = validateRouteDoc(doc);
    ok(`(R7) route doc valid for ${dest}`, res.ok === true, JSON.stringify(res.errors));
    ok(`(R7) advisory=true for ${dest}`, doc.advisory === true);
    const allPaths = [...(doc.route||[]), ...(doc.alternates||[])].map(e => e.path);
    const badPaths = allPaths.filter(p =>
      p.startsWith('/') ||
      /^[A-Za-z]:[\\\/]/.test(p) ||
      p.split(/[/\\]/).some(s => s === '..'),
    );
    ok(`(R7) no absolute/traversal paths for ${dest}`, badPaths.length === 0,
      JSON.stringify(badPaths));
  }
}

// ===========================================================================
// SECTION 2 — ENV A: Solo/Startup scale simulation (6000 nodes, 12 categories)
//
// sim-solo.test.mjs handles the real vercel/next.js clone (KC_RUN_SIM_TESTS=1).
// Here we exercise the LOD + streaming + layout invariants at equivalent scale.
// ===========================================================================
console.log('\n=== ENV A — Solo/Startup scale simulation (6000 nodes) ===');

{
  const SOLO_CATEGORIES = [
    'packages', 'apps', 'test', 'benchmarks', 'scripts', 'examples',
    'errors', 'docs', 'contributing', 'instrumentation', 'hooks', 'turbopack',
  ].map((id, i) => ({ id, label: id, order: i, color: '#e0b24a' }));
  const SOLO_N = 6000;
  const soloNodes = Array.from({ length: SOLO_N }, (_, i) => ({
    id: `fs:src/module_${i}.mjs`,
    kind: 'file',
    title: `Module ${i}`,
    category: SOLO_CATEGORIES[i % SOLO_CATEGORIES.length].id,
    links: [],
    provenance: { store: 'fs', ref: `src/module_${i}.mjs` },
  }));

  // (S1) layoutCity at 6000 nodes: no throw, < 3s, deterministic, all nodes placed
  const t0 = Date.now();
  let layout1 = null, layout2 = null, soloThrew = false;
  try {
    layout1 = layoutCity({ nodes: soloNodes, categories: SOLO_CATEGORIES });
    layout2 = layoutCity({ nodes: soloNodes, categories: SOLO_CATEGORIES });
  } catch { soloThrew = true; }
  const elapsed = Date.now() - t0;

  ok('(S1) layoutCity(6000 nodes) does not throw', !soloThrew);
  ok('(S1) layoutCity(6000 nodes) terminates < 3s', elapsed < 3000, `elapsed=${elapsed}ms`);
  ok('(S1) layoutCity(6000 nodes) all 6000 nodes placed',
    layout1 && layout1.nodes.length === SOLO_N);
  ok('(S1) layoutCity(6000 nodes) is deterministic',
    layout1 && layout2 &&
    layout1.nodes[0].gx === layout2.nodes[0].gx &&
    layout1.nodes[0].gy === layout2.nodes[0].gy);
  ok('(S1) layoutCity(6000 nodes) gridW/gridH are positive',
    layout1 && layout1.gridW > 0 && layout1.gridH > 0);

  // (S2) shouldStream fires at 6000 (well above STREAM_THRESHOLD=400)
  ok('(S2) shouldStream(6000) === true', shouldStream(SOLO_N) === true);

  // (S3) makeBatches divides 6000 nodes into expected batch count
  if (layout1) {
    const batches = makeBatches(layout1.nodes, STREAM_BATCH_SIZE);
    const expectedBatches = Math.ceil(SOLO_N / STREAM_BATCH_SIZE);
    ok('(S3) makeBatches(6000) produces correct batch count',
      batches.length === expectedBatches,
      `got=${batches.length} expected=${expectedBatches}`);
    ok('(S3) every batch has <= STREAM_BATCH_SIZE items',
      batches.every(b => b.length <= STREAM_BATCH_SIZE));
    ok('(S3) total items across batches equals 6000',
      batches.reduce((s, b) => s + b.length, 0) === SOLO_N);
  }

  // (S4) buildClusters at 6000 nodes / 12 categories produces 12 clusters
  if (layout1) {
    const adapted = adaptNodes(layout1);
    const dcfg = Object.fromEntries(SOLO_CATEGORIES.map(c => [c.id, { name: c.label, color: c.color }]));
    const clusters = buildClusters(adapted, dcfg);
    ok('(S4) buildClusters(6000 / 12 cats) → 12 clusters',
      clusters.length === SOLO_CATEGORIES.length, `got=${clusters.length}`);
    ok('(S4) cluster total == 6000',
      clusters.reduce((s, c) => s + c.count, 0) === SOLO_N);
    ok('(S4) all cluster centroids are finite',
      clusters.every(c => Number.isFinite(c.wx) && Number.isFinite(c.wy)));
  }

  // (S5) LOD tier selected correctly at key zoom levels
  const ZOOM_TESTS = [
    [1.0,                  LOD_FULL,    'full-zoom'],
    [LOD_FULL_THRESHOLD,   LOD_FULL,    'full-threshold'],
    [LOD_SIMPLE_THRESHOLD, LOD_SIMPLE,  'simple-threshold'],
    [LOD_DOT_THRESHOLD,    LOD_DOT,     'dot-threshold'],
    [0.02,                 LOD_CLUSTER, 'deep-zoom-out'],
  ];
  for (const [z, expected, label] of ZOOM_TESTS) {
    ok(`(S5) lodForZoom(${z}) [${label}] → ${expected}`,
      lodForZoom(z) === expected, `got=${lodForZoom(z)}`);
  }

  // (S6) At LOD_CLUSTER zoom (0.02), camera centred on city midpoint:
  //      all 6000 nodes fall within the padded clip region.
  if (layout1) {
    const adapted = adaptNodes(layout1);
    const zoom = 0.02;
    const cw = 1280, ch = 900;
    const minBx = Math.min(...adapted.map(n => n.bx));
    const maxBx = Math.max(...adapted.map(n => n.bx));
    const minBy = Math.min(...adapted.map(n => n.by));
    const maxBy = Math.max(...adapted.map(n => n.by));
    const midBx = (minBx + maxBx) / 2;
    const midBy = (minBy + maxBy) / 2;
    const cam = { x: cw / 2 - midBx * zoom, y: ch / 2 - midBy * zoom, zoom };
    // Pad must be at least half the city extent in world-units so all nodes are in view
    const pad = Math.max(maxBx - minBx, maxBy - minBy) / 2 + 256;
    const clip = viewportClip(cam, cw, ch, pad);
    const visibleCount = adapted.filter(n => isVisible(n.bx, n.by, clip)).length;
    ok('(S6) at LOD_CLUSTER zoom all 6000 nodes are within padded viewport',
      visibleCount === SOLO_N, `visible=${visibleCount}`);
  }
}

// ===========================================================================
// SECTION 3 — Adversarial policy overlay (ENV B + SAT-457 policy fuzzer output)
// ===========================================================================
console.log('\n=== ADV — Adversarial policy overlay ===');

// (A1) Adversarial nodes are present and survive layoutCity
{
  const advNodes = regNodes.filter(n =>
    n.category === 'policy' || n.status === 'deprecated' || n.status === 'stale',
  );
  ok('(A1) adversarial policy/deprecated nodes present (>= 3)',
    advNodes.length >= 3,
    `advNodes=${advNodes.length}: ${advNodes.map(n => n.id).join(', ')}`);

  const layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES });
  const depKeyPlaced = layout.nodes.find(n => n.id === 'policy:signing/deprecated-key-stub.pem');
  ok('(A1) deprecated key stub node is placed by layoutCity', depKeyPlaced !== undefined);
}

// (A2) layoutCity with the full adversarial overlay produces a valid layout
{
  let layout = null, threw = false;
  try { layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES }); } catch { threw = true; }
  ok('(A2) layoutCity(adv overlay) does not throw', !threw);
  ok('(A2) all nodes including adversarial ones are placed',
    layout && layout.nodes.length === regNodes.length);
}

// (A3) buildClusters isolates adversarial policy/sig-auth nodes into their districts
{
  const layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES });
  const adapted = adaptNodes(layout);
  const dcfg = Object.fromEntries(REG_CATEGORIES.map(c => [c.id, { name: c.label, color: c.color }]));
  const clusters = buildClusters(adapted, dcfg);

  const policyCluster  = clusters.find(c => c.districtId === 'policy');
  const sigAuthCluster = clusters.find(c => c.districtId === 'sig-auth');
  ok('(A3) policy district cluster exists', policyCluster !== undefined);
  ok('(A3) sig-auth district cluster exists', sigAuthCluster !== undefined);

  const depKey = regNodes.find(n => n.id === 'policy:signing/deprecated-key-stub.pem');
  ok('(A3) deprecated key stub is in sig-auth category', depKey && depKey.category === 'sig-auth');
  ok('(A3) sig-auth cluster count >= 1', sigAuthCluster && sigAuthCluster.count >= 1);

  const policyNodes = regNodes.filter(n => n.category === 'policy');
  ok('(A3) policy cluster count matches policy category node count',
    policyCluster && policyCluster.count === policyNodes.length,
    `clusterCount=${policyCluster?.count} policyNodes=${policyNodes.length}`);
}

// (A4) Route docs for adversarial nodes: no throw, advisory=true, no absolute paths
{
  const adversarialRoutes = [
    'district:policy',
    'district:sig-auth',
    'file:policy:classification/data-sensitivity.yaml',
    'file:policy:signing/deprecated-key-stub.pem',
  ];
  for (const dest of adversarialRoutes) {
    let doc = null, threw = false;
    try { doc = kcRoute(regCtx, dest); } catch { threw = true; }
    ok(`(A4) kcRoute does not throw for "${dest}"`, !threw);
    if (doc) {
      const res = validateRouteDoc(doc);
      ok(`(A4) route doc valid for "${dest}"`, res.ok === true, JSON.stringify(res.errors));
      ok(`(A4) advisory=true for "${dest}"`, doc.advisory === true);
      const allPaths = [...(doc.route||[]), ...(doc.alternates||[])].map(e => e.path);
      const badPaths = allPaths.filter(p =>
        p.startsWith('/') ||
        /^[A-Za-z]:[\\\/]/.test(p) ||
        p.split(/[/\\]/).some(s => s === '..'),
      );
      ok(`(A4) no absolute/traversal paths for "${dest}"`, badPaths.length === 0,
        JSON.stringify(badPaths));
    }
  }
}

// (A5) Raw PEM header does NOT appear in the route doc JSON
{
  const doc = kcRoute(regCtx, 'district:sig-auth');
  const serialized = JSON.stringify(doc);
  ok('(A5) "-----BEGIN RSA PRIVATE KEY-----" absent from sig-auth route doc JSON',
    !serialized.includes('-----BEGIN RSA PRIVATE KEY-----'));
}

// (A6) Overlapping ownership conflict is detectable, and layoutCity survives it
{
  const { matched } = parseDestination(regCtx, 'depChainTo:cg:tools/cache/controller.go', 20);
  const policyCallers = matched.filter(n => n.category === 'policy');
  ok('(A6) overlapping SIG ownership policies detectable via depChainTo (>= 2 policy callers)',
    policyCallers.length >= 2,
    policyCallers.map(n => n.id).join(', '));

  let layout = null, threw = false;
  try { layout = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES }); } catch { threw = true; }
  ok('(A6) layoutCity does not crash despite ownership conflict', !threw);
  ok('(A6) all nodes placed despite conflict', layout && layout.nodes.length === regNodes.length);
}

// ===========================================================================
// SECTION 4 — ENV B rendering pipeline (build-rich.mjs --vector subprocess)
// ===========================================================================
console.log('\n=== ENV B rendering pipeline (build-rich.mjs --vector) ===');

{
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-sat449-'));
  const cityPath = path.join(tmpDir, 'city.json');
  const htmlPath = path.join(tmpDir, 'city.html');
  fs.writeFileSync(cityPath, JSON.stringify(regCity));

  const r = spawnSync(process.execPath, [
    path.join(ROOT, 'renderer/build-rich.mjs'),
    cityPath,
    htmlPath,
    '--vector',
  ], { encoding: 'utf8', timeout: 30_000 });

  ok('(P1) build-rich.mjs exits 0 for ENV-B city', r.status === 0,
    '(exit=' + r.status + ' stderr=' + (r.stderr || '').slice(0, 200) + ')');

  const html = r.status === 0 && fs.existsSync(htmlPath)
    ? fs.readFileSync(htmlPath, 'utf8') : '';
  ok('(P1) rendered HTML is non-empty', html.length > 0, `len=${html.length}`);
  ok('(P1) HTML has kc-data script block', html.includes('id="kc-data"'));
  ok('(P1) HTML embeds JSON nodes array', html.includes('"nodes"'));

  // Quality gate: htmlSafe() prevents </script> breakout and JS line-terminator hazard.
  // Note: the PEM header '-----BEGIN RSA PRIVATE KEY-----' is present in the city JSON
  // because htmlSafe() only escapes < / U+2028 / U+2029 (XSS/LSP prevention, not content
  // scrubbing). Scrubbing happens in serializeNode() at indexing time.
  ok('(P1) no </script><script> XSS breakout in rendered HTML',
    !html.includes('</script><script>'));
  ok('(P1) no literal U+2028 in HTML', !html.includes(' '));
  ok('(P1) no literal U+2029 in HTML', !html.includes(' '));

  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
}

// ===========================================================================
// QUALITY REPORT — structural summary for visual review (D-165 gate)
// ===========================================================================
console.log('\n======== QUALITY REPORT (SAT-449 spike) ========');

const rptLayout    = layoutCity({ nodes: regNodes, categories: REG_CATEGORIES });
const rptAdapted   = adaptNodes(rptLayout);
const rptDcfg      = Object.fromEntries(REG_CATEGORIES.map(c => [c.id, { name: c.label, color: c.color }]));
const rptClusters  = buildClusters(rptAdapted, rptDcfg);
const crossEdges   = getCrossRepoEdges(regCtx);
const repoBounds   = getRepoBoundaries(regCtx);

const soloScale = 6000;
console.log('\n--- ENV A (vercel/next.js @ simulated 6000 nodes) ---');
console.log('  shouldStream:', shouldStream(soloScale), `(threshold=${STREAM_THRESHOLD})`);
console.log('  batchCount:', Math.ceil(soloScale / STREAM_BATCH_SIZE),
  `(batchSize=${STREAM_BATCH_SIZE})`);
console.log('  LOD at key zooms:',
  'full=' + lodForZoom(1.0),
  'simple=' + lodForZoom(LOD_SIMPLE_THRESHOLD),
  'dot=' + lodForZoom(LOD_DOT_THRESHOLD),
  'cluster=' + lodForZoom(0.02));

console.log('\n--- ENV B (kubernetes 4-repo regulated-sim, 15 nodes) ---');
console.log('  categories:', REG_CATEGORIES.map(c => c.id).join(', '));
console.log('  layout: gridW=' + rptLayout.gridW + ' gridH=' + rptLayout.gridH
  + ' districts=' + rptLayout.districts.length + ' placed=' + rptLayout.nodes.length);
console.log('  shouldStream:', shouldStream(regNodes.length));
console.log('  crossRepoEdges:', crossEdges.length, '—',
  crossEdges.map(e => e.from.split(':')[0] + '→' + e.to.split(':')[0]).join(', '));
console.log('  repoBoundaries:',
  repoBounds.map(b => b.repo + '(' + b.count + ')').join(', '));
console.log('  clusters (district→count):',
  rptClusters.map(c => c.districtId + ':' + c.count).join(', '));

console.log('\n--- ADV (policy overlay on ENV B) ---');
const advList = regNodes.filter(n =>
  n.category === 'policy' || n.status === 'deprecated' || n.status === 'stale',
);
for (const n of advList) {
  const flags = [n.status || 'active'];
  if (n.sensitive) flags.push('sensitive');
  if (n.tags.includes('red-team-target')) flags.push('RED-TEAM-TARGET');
  console.log('  ', n.id, '[' + flags.join(', ') + ']');
}
const staleNode = regNodes.find(n => n.status === 'stale');
console.log('  stale policy links to:', staleNode?.links?.join(', '));

console.log('\n--- Rendering quality gates ---');
console.log('  LOD thresholds: full=' + LOD_FULL_THRESHOLD
  + ' simple=' + LOD_SIMPLE_THRESHOLD
  + ' dot='    + LOD_DOT_THRESHOLD);
const sampleClip = viewportClip({ x: 0, y: 0, zoom: 1 }, 1280, 900, 128);
console.log('  viewportClip(zoom=1, 1280×900, pad=128):', JSON.stringify(sampleClip));

console.log('\n--- Gate result ---');
console.log('  Automated invariants:', failures === 0 ? 'ALL PASS ✓' : failures + ' FAILURE(S) ✗');
console.log('  Visual review required: open rendered HTML in browser (--vector mode tested here).');
console.log('  Full clone validation: KC_RUN_SIM_TESTS=1 node test/sim-solo.test.mjs');
console.log();

console.log('======================================\n');
console.log(failures ? failures + ' FAILURE(S)' : 'all checks passed');
process.exit(failures ? 1 : 0);
