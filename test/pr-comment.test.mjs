// KnoSky PR-comment renderer tests. Run: node test/pr-comment.test.mjs
import { renderPrComment } from '../core/pr-comment.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const routeJson = {
  knosky_protocol: '1.0',
  artifact_type: 'pr-route',
  advisory: true,
  generated_at: new Date().toISOString(),
  base: 'main',
  head: 'feature/foo',
  routes: [
    {
      file: 'core/route.mjs',
      route: {
        knosky_protocol: '1.0',
        artifact_type: 'route',
        advisory: true,
        destination: 'file:core/route.mjs',
        route: [
          { path: 'core/route.mjs', reason: 'entry point' },
          { path: 'core/retrieve.mjs', reason: 'data access' },
          { path: 'core/schema.mjs', reason: 'validation' },
          { path: 'core/destination.mjs', reason: 'parsing' },
          { path: 'test/route.test.mjs', reason: 'tests' },
        ],
        alternates: [],
        caveats: [
          'recently changed — route cache may be stale',
          'coverage: 3 of 5 files indexed',
        ],
        confidence: 0.82,
        tests: ['test/route.test.mjs'],
        docs: ['core/CONTRACT.md'],
      },
    },
  ],
};

const safetyJson = {
  knosky_protocol: '1.0',
  artifact_type: 'safety-report',
  advisory: true,
  generated_at: new Date().toISOString(),
  absolute_paths: false,
  secrets_found: 0,
  redaction: 'metadata-only; no file bodies; no absolute paths',
};

// ---------------------------------------------------------------------------
// (a) Rendered comment contains the word "advisory"
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  ok('(a) comment contains "advisory"', comment.toLowerCase().includes('advisory'));
}

// ---------------------------------------------------------------------------
// (b) Forbidden denylist — NONE of these must appear (case-insensitive)
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  const denylist = [
    /\bCI gate\b/i,
    /\bblocks? the build\b/i,
    /\bgate(s|d)? the build\b/i,
    /\blearns?\b/i,
    /\bunderstands? your code\b/i,
    /\bzero data risk\b/i,
    /\bofficial standard\b/i,
    /\bair-?gap guarantee\b/i,
  ];
  for (const pattern of denylist) {
    ok(
      `(b) denylist: no match for ${pattern}`,
      !pattern.test(comment),
      pattern.test(comment) ? `  FOUND: "${comment.match(pattern)[0]}"` : '',
    );
  }
}

// ---------------------------------------------------------------------------
// (c) Includes at least one route waypoint + a confidence %
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  // A waypoint appears as a backtick-wrapped path
  const hasWaypoint = /`core\/route\.mjs`/.test(comment);
  // Confidence formatted as NN%
  const hasConfidence = /\b\d+%/.test(comment);
  ok('(c) includes at least one route waypoint', hasWaypoint);
  ok('(c) includes a confidence %', hasConfidence);
}

// ---------------------------------------------------------------------------
// (d) Includes the "Suggested" prompt block
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  ok('(d) contains "Suggested" heading', comment.includes('Suggested'));
  ok('(d) contains "Advisory only — verify before acting"', comment.includes('Advisory only — verify before acting'));
}

// ---------------------------------------------------------------------------
// (e) Empty changeset — renders without throwing
// ---------------------------------------------------------------------------
{
  let threw = false;
  let comment = '';
  try {
    comment = renderPrComment({
      routeJson: { knosky_protocol: '1.0', artifact_type: 'pr-route', advisory: true, routes: [] },
      safetyJson: { secrets_found: 0 },
    });
  } catch (err) {
    threw = true;
  }
  ok('(e) empty routes: no throw', !threw);
  ok('(e) empty routes: still contains "advisory"', !threw && comment.toLowerCase().includes('advisory'));
  ok('(e) empty routes: mentions no changed files', !threw && /no changed files/i.test(comment));
}

// ---------------------------------------------------------------------------
// (f) Footer contains required safety language
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  ok('(f) footer: "reads metadata only"', comment.includes('reads metadata only'));
  ok('(f) footer: "never uploads your code"', comment.includes('never uploads your code'));
  ok('(f) footer: "network-silent (verify with --verify-airgap)"', comment.includes('network-silent (verify with --verify-airgap)'));
  ok('(f) footer: "open protocol / reference implementation"', comment.includes('open protocol / reference implementation'));
}

// ---------------------------------------------------------------------------
// (g) secrets_found is surfaced in the footer
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson: { secrets_found: 3 } });
  ok('(g) secrets_found=3 appears in comment', comment.includes('3'));
}

// ---------------------------------------------------------------------------
// (h) Freshness/coverage caveats appear when present
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  ok('(h) freshness caveat rendered', comment.includes('recently changed'));
  ok('(h) coverage caveat rendered', comment.includes('coverage:'));
}

// ---------------------------------------------------------------------------
// (i) Related tests and docs appear when present on the route doc
// ---------------------------------------------------------------------------
{
  const comment = renderPrComment({ routeJson, safetyJson });
  ok('(i) related tests rendered', comment.includes('test/route.test.mjs'));
  ok('(i) related docs rendered', comment.includes('core/CONTRACT.md'));
}

// ---------------------------------------------------------------------------
// (j) tests/docs as {path} objects — render path, no [object Object]
// ---------------------------------------------------------------------------
{
  const objRouteJson = {
    knosky_protocol: '1.0',
    artifact_type: 'pr-route',
    advisory: true,
    routes: [
      {
        file: 'core/example.mjs',
        route: {
          knosky_protocol: '1.0',
          artifact_type: 'route',
          advisory: true,
          destination: 'file:core/example.mjs',
          route: [],
          alternates: [],
          caveats: [],
          confidence: 0.9,
          tests: [{ path: 'test/x.test.js', id: 'test-x' }],
          docs: [{ path: 'docs/x.md', id: 'doc-x' }],
        },
      },
    ],
  };
  const comment = renderPrComment({ routeJson: objRouteJson, safetyJson });
  ok('(j) object-form test path rendered', comment.includes('test/x.test.js'));
  ok('(j) object-form doc path rendered', comment.includes('docs/x.md'));
  ok('(j) no [object Object] in comment', !comment.includes('[object Object]'));
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
