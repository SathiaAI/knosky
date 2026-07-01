// KnoSky protocol artifact schema tests. Run: node test/schema.test.mjs
import {
  PROTOCOL_VERSION,
  makeRouteDoc,
  validateRouteDoc,
  makeIntentManifest,
  validateIntentManifest,
} from '../core/schema.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// (a) makeRouteDoc output passes validateRouteDoc
// ---------------------------------------------------------------------------
{
  const doc = makeRouteDoc({ destination: 'src/core/index.mjs' });
  const result = validateRouteDoc(doc);
  ok('makeRouteDoc output is valid', result.ok === true, JSON.stringify(result.errors));
  ok('makeRouteDoc sets knosky_protocol', doc.knosky_protocol === PROTOCOL_VERSION);
  ok('makeRouteDoc sets artifact_type', doc.artifact_type === 'route');
  ok('makeRouteDoc sets advisory true', doc.advisory === true);
  ok('makeRouteDoc generated_at is ISO string', typeof doc.generated_at === 'string' && doc.generated_at.length > 0);
  ok('makeRouteDoc default route is []', Array.isArray(doc.route) && doc.route.length === 0);
  ok('makeRouteDoc default confidence is 0', doc.confidence === 0);
  ok('makeRouteDoc default source_rev is null', doc.source_rev === null);
}

// (a cont.) makeRouteDoc with explicit fields
{
  const doc = makeRouteDoc({
    destination: 'src/app.mjs',
    route: ['src/a.mjs', 'src/b.mjs'],
    alternates: [{ path: 'src/c.mjs' }],
    caveats: ['experimental'],
    confidence: 0.9,
    source_rev: 'abc123',
  });
  const result = validateRouteDoc(doc);
  ok('makeRouteDoc with all fields is valid', result.ok === true, JSON.stringify(result.errors));
  ok('makeRouteDoc stores source_rev', doc.source_rev === 'abc123');
  ok('makeRouteDoc stores confidence', doc.confidence === 0.9);
}

// ---------------------------------------------------------------------------
// (a) makeIntentManifest output passes validateIntentManifest
// ---------------------------------------------------------------------------
{
  const doc = makeIntentManifest({
    paths: [{ path: 'src/index.mjs', sha256: 'deadbeef' }],
    secret_scan: { status: 'clean' },
  });
  const result = validateIntentManifest(doc);
  ok('makeIntentManifest output is valid', result.ok === true, JSON.stringify(result.errors));
  ok('makeIntentManifest sets knosky_protocol', doc.knosky_protocol === PROTOCOL_VERSION);
  ok('makeIntentManifest sets artifact_type', doc.artifact_type === 'intent-manifest');
  ok('makeIntentManifest sets advisory true', doc.advisory === true);
  ok('makeIntentManifest generated_at is ISO string', typeof doc.generated_at === 'string' && doc.generated_at.length > 0);
  ok('makeIntentManifest default edges is []', Array.isArray(doc.edges) && doc.edges.length === 0);
  ok('makeIntentManifest default expiry is null', doc.expiry === null);
}

// (a cont.) makeIntentManifest with status "blocked" also valid
{
  const doc = makeIntentManifest({
    secret_scan: { status: 'blocked', detail: 'credential found' },
  });
  const result = validateIntentManifest(doc);
  ok('makeIntentManifest with blocked secret_scan is valid', result.ok === true, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (b) A route with an absolute path in route[] fails
// ---------------------------------------------------------------------------
{
  const doc = makeRouteDoc({
    destination: 'dst',
    route: ['/etc/passwd'],
  });
  const result = validateRouteDoc(doc);
  ok('absolute path in route[] fails validation', result.ok === false, JSON.stringify(result.errors));
  ok('absolute path error mentions route[0]', result.errors.some(e => e.includes('route[0]')), JSON.stringify(result.errors));
}

// (b cont.) Windows drive path in alternates[] also fails
{
  const doc = makeRouteDoc({
    destination: 'dst',
    alternates: ['C:\\Users\\admin\\secret.txt'],
  });
  const result = validateRouteDoc(doc);
  ok('Windows absolute path in alternates[] fails', result.ok === false, JSON.stringify(result.errors));
}

// (b cont.) Object entry with absolute path in route[] fails
{
  const doc = makeRouteDoc({
    destination: 'dst',
    route: [{ path: '/absolute/path.mjs', label: 'x' }],
  });
  const result = validateRouteDoc(doc);
  ok('absolute path via object .path in route[] fails', result.ok === false, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (c) A route with ".." in route[] fails
// ---------------------------------------------------------------------------
{
  const doc = makeRouteDoc({
    destination: 'dst',
    route: ['../outside/file.mjs'],
  });
  const result = validateRouteDoc(doc);
  ok('".." path segment in route[] fails validation', result.ok === false, JSON.stringify(result.errors));
  ok('".." error mentions route[0]', result.errors.some(e => e.includes('route[0]')), JSON.stringify(result.errors));
}

// (c cont.) ".." embedded deeper
{
  const doc = makeRouteDoc({
    destination: 'dst',
    route: ['src/foo/../bar.mjs'],
  });
  const result = validateRouteDoc(doc);
  ok('embedded ".." segment in route[] fails', result.ok === false, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (d) confidence 1.5 fails
// ---------------------------------------------------------------------------
{
  const doc = makeRouteDoc({ destination: 'dst', confidence: 1.5 });
  const result = validateRouteDoc(doc);
  ok('confidence 1.5 fails validation', result.ok === false, JSON.stringify(result.errors));
  ok('confidence error text mentions confidence', result.errors.some(e => e.includes('confidence')), JSON.stringify(result.errors));
}

// (d cont.) confidence -0.1 also fails
{
  const doc = makeRouteDoc({ destination: 'dst', confidence: -0.1 });
  const result = validateRouteDoc(doc);
  ok('confidence -0.1 fails validation', result.ok === false, JSON.stringify(result.errors));
}

// (d cont.) confidence exactly 0 and 1 pass
{
  ok('confidence 0 passes', validateRouteDoc(makeRouteDoc({ destination: 'x', confidence: 0 })).ok === true);
  ok('confidence 1 passes', validateRouteDoc(makeRouteDoc({ destination: 'x', confidence: 1 })).ok === true);
}

// ---------------------------------------------------------------------------
// (e) Wrong artifact_type fails
// ---------------------------------------------------------------------------
{
  const doc = { ...makeRouteDoc({ destination: 'dst' }), artifact_type: 'intent-manifest' };
  const result = validateRouteDoc(doc);
  ok('wrong artifact_type fails validateRouteDoc', result.ok === false, JSON.stringify(result.errors));
}

{
  const doc = { ...makeIntentManifest({ secret_scan: { status: 'clean' } }), artifact_type: 'route' };
  const result = validateIntentManifest(doc);
  ok('wrong artifact_type fails validateIntentManifest', result.ok === false, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (f) Intent-manifest missing secret_scan.status fails
// ---------------------------------------------------------------------------
{
  const doc = makeIntentManifest({ secret_scan: { status: 'clean' } });
  const badDoc = { ...doc, secret_scan: { detail: 'something' } }; // status missing
  const result = validateIntentManifest(badDoc);
  ok('manifest missing secret_scan.status fails', result.ok === false, JSON.stringify(result.errors));
  ok('error mentions secret_scan.status', result.errors.some(e => e.includes('secret_scan.status')), JSON.stringify(result.errors));
}

// (f cont.) secret_scan entirely absent
{
  const doc = makeIntentManifest({ secret_scan: { status: 'clean' } });
  const badDoc = { ...doc, secret_scan: undefined };
  const result = validateIntentManifest(badDoc);
  ok('manifest with secret_scan undefined fails', result.ok === false, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (g) A manifest path with "../" fails
// ---------------------------------------------------------------------------
{
  const doc = makeIntentManifest({
    paths: [{ path: '../etc/shadow', sha256: 'aabbcc' }],
    secret_scan: { status: 'clean' },
  });
  const result = validateIntentManifest(doc);
  ok('manifest path with "../" fails validation', result.ok === false, JSON.stringify(result.errors));
  ok('error mentions paths[0]', result.errors.some(e => e.includes('paths[0]')), JSON.stringify(result.errors));
}

// (g cont.) absolute path in manifest paths[] also fails
{
  const doc = makeIntentManifest({
    paths: [{ path: '/var/secret', sha256: 'aabbcc' }],
    secret_scan: { status: 'clean' },
  });
  const result = validateIntentManifest(doc);
  ok('absolute path in manifest paths[] fails', result.ok === false, JSON.stringify(result.errors));
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
