// KnoSky LOD / clustering / virtualization / streaming tests. Run: node test/lod.test.mjs
import {
  LOD_FULL, LOD_SIMPLE, LOD_DOT, LOD_CLUSTER,
  LOD_FULL_THRESHOLD, LOD_SIMPLE_THRESHOLD, LOD_DOT_THRESHOLD,
  lodForZoom,
  viewportClip, isVisible,
  buildClusters,
  STREAM_THRESHOLD, STREAM_BATCH_SIZE, makeBatches, shouldStream,
} from '../core/lod.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

// ---------------------------------------------------------------------------
// LOD tier constants are defined and correctly ordered
// ---------------------------------------------------------------------------
ok('LOD constant values are unique integers', new Set([LOD_FULL,LOD_SIMPLE,LOD_DOT,LOD_CLUSTER]).size === 4);
ok('LOD_FULL=0 LOD_SIMPLE=1 LOD_DOT=2 LOD_CLUSTER=3',
   LOD_FULL === 0 && LOD_SIMPLE === 1 && LOD_DOT === 2 && LOD_CLUSTER === 3);
ok('zoom thresholds decrease in order',
   LOD_FULL_THRESHOLD > LOD_SIMPLE_THRESHOLD && LOD_SIMPLE_THRESHOLD > LOD_DOT_THRESHOLD && LOD_DOT_THRESHOLD > 0);

// ---------------------------------------------------------------------------
// lodForZoom
// ---------------------------------------------------------------------------
ok('lodForZoom(1.0)  → LOD_FULL',    lodForZoom(1.0)                        === LOD_FULL);
ok('lodForZoom at LOD_FULL_THRESHOLD → LOD_FULL', lodForZoom(LOD_FULL_THRESHOLD) === LOD_FULL);
ok('lodForZoom(0.20) → LOD_SIMPLE',  lodForZoom(0.20)                       === LOD_SIMPLE);
ok('lodForZoom at LOD_SIMPLE_THRESHOLD → LOD_SIMPLE', lodForZoom(LOD_SIMPLE_THRESHOLD) === LOD_SIMPLE);
ok('lodForZoom(0.08) → LOD_DOT',     lodForZoom(0.08)                       === LOD_DOT);
ok('lodForZoom at LOD_DOT_THRESHOLD → LOD_DOT', lodForZoom(LOD_DOT_THRESHOLD) === LOD_DOT);
ok('lodForZoom(0.03) → LOD_CLUSTER', lodForZoom(0.03)                       === LOD_CLUSTER);
ok('lodForZoom(0)    → LOD_CLUSTER', lodForZoom(0)                           === LOD_CLUSTER);

// ---------------------------------------------------------------------------
// viewportClip
// ---------------------------------------------------------------------------
{
  const cam = { x: 0, y: 0, zoom: 1 };
  const clip = viewportClip(cam, 800, 600, 0);
  ok('clip.wx0 === 0 when cam at origin no pad', clip.wx0 === 0);
  ok('clip.wy0 === 0 when cam at origin no pad', clip.wy0 === 0);
  ok('clip.wx1 === 800 when cam at origin no pad', clip.wx1 === 800);
  ok('clip.wy1 === 600 when cam at origin no pad', clip.wy1 === 600);
}
{
  const cam = { x: 100, y: 50, zoom: 2 };
  const clip = viewportClip(cam, 800, 600, 0);
  // worldX = (screenX - 100) / 2
  ok('clip with offset cam wx0', Math.abs(clip.wx0 - (-50)) < 0.001);
  ok('clip with offset cam wy0', Math.abs(clip.wy0 - (-25)) < 0.001);
  ok('clip with offset cam wx1', Math.abs(clip.wx1 - 350) < 0.001);
  ok('clip with offset cam wy1', Math.abs(clip.wy1 - 275) < 0.001);
}
{
  const cam = { x: 0, y: 0, zoom: 1 };
  const clip = viewportClip(cam, 800, 600, 128);
  ok('pad extends wx0 by -128', clip.wx0 === -128);
  ok('pad extends wy0 by -128', clip.wy0 === -128);
  ok('pad extends wx1 by +128', clip.wx1 === 928);
  ok('pad extends wy1 by +128', clip.wy1 === 728);
}

// ---------------------------------------------------------------------------
// isVisible
// ---------------------------------------------------------------------------
{
  const clip = { wx0: 0, wy0: 0, wx1: 800, wy1: 600 };
  ok('isVisible inside rect', isVisible(400, 300, clip) === true);
  ok('isVisible on left edge', isVisible(0, 300, clip) === true);
  ok('isVisible on right edge', isVisible(800, 300, clip) === true);
  ok('isVisible above viewport', isVisible(400, -1, clip) === false);
  ok('isVisible below viewport', isVisible(400, 601, clip) === false);
  ok('isVisible left of viewport', isVisible(-1, 300, clip) === false);
  ok('isVisible right of viewport', isVisible(801, 300, clip) === false);
}

// ---------------------------------------------------------------------------
// buildClusters
// ---------------------------------------------------------------------------
{
  const nodes = [
    { d: 'code', bx: 0, by: 0 },
    { d: 'code', bx: 100, by: 100 },
    { d: 'docs', bx: 200, by: 400 },
  ];
  const dcfg = {
    code: { name: 'Code', color: '#e0b24a' },
    docs: { name: 'Docs', color: '#5cc1e6' },
  };
  const clusters = buildClusters(nodes, dcfg);
  ok('buildClusters returns one cluster per district', clusters.length === 2);
  const code = clusters.find(c => c.districtId === 'code');
  const docs = clusters.find(c => c.districtId === 'docs');
  ok('code cluster exists', !!code);
  ok('docs cluster exists', !!docs);
  ok('code cluster count = 2', code.count === 2);
  ok('docs cluster count = 1', docs.count === 1);
  ok('code cluster centroid wx', code.wx === 50);
  ok('code cluster centroid wy', code.wy === 50);
  ok('docs cluster centroid wx', docs.wx === 200);
  ok('docs cluster centroid wy', docs.wy === 400);
  ok('cluster has label', code.label === 'Code');
  ok('cluster has color', code.color === '#e0b24a');
}
{
  // Unknown district falls back to id and default colour
  const nodes = [{ d: 'mystery', bx: 10, by: 20 }];
  const clusters = buildClusters(nodes, {});
  ok('unknown district produces cluster', clusters.length === 1);
  ok('unknown district label = id', clusters[0].label === 'mystery');
  ok('unknown district color is a string', typeof clusters[0].color === 'string');
}
{
  // Empty nodes → empty clusters
  const clusters = buildClusters([], {});
  ok('empty nodes → empty clusters', clusters.length === 0);
}

// ---------------------------------------------------------------------------
// makeBatches
// ---------------------------------------------------------------------------
{
  const arr = Array.from({ length: 250 }, (_, i) => i);
  const batches = makeBatches(arr, 80);
  ok('makeBatches splits 250 → 4 batches of 80/80/80/10',
     batches.length === 4 &&
     batches[0].length === 80 && batches[1].length === 80 &&
     batches[2].length === 80 && batches[3].length === 10);
  ok('makeBatches first item of batch 2 = 80', batches[1][0] === 80);
  ok('makeBatches last item = 249', batches[3][9] === 249);
}
{
  // Exact multiple
  const arr = Array.from({ length: 160 }, (_, i) => i);
  const batches = makeBatches(arr, 80);
  ok('makeBatches exact multiple → 2 batches of 80', batches.length === 2 && batches[1].length === 80);
}
{
  // Single item
  const batches = makeBatches([42]);
  ok('makeBatches single item → 1 batch of 1', batches.length === 1 && batches[0][0] === 42);
}
{
  // Empty array
  const batches = makeBatches([]);
  ok('makeBatches empty → empty array', batches.length === 0);
}
{
  // Uses default STREAM_BATCH_SIZE when size omitted
  const arr = Array.from({ length: STREAM_BATCH_SIZE + 1 }, (_, i) => i);
  const batches = makeBatches(arr);
  ok('makeBatches default size → 2 batches', batches.length === 2);
}
{
  // TypeError on non-array
  let threw = false;
  try { makeBatches('string', 10); } catch (e) { threw = e instanceof TypeError; }
  ok('makeBatches throws TypeError for non-array', threw);
}
{
  // RangeError on bad size
  let threw = false;
  try { makeBatches([1,2,3], 0); } catch (e) { threw = e instanceof RangeError; }
  ok('makeBatches throws RangeError for size=0', threw);
}

// ---------------------------------------------------------------------------
// shouldStream
// ---------------------------------------------------------------------------
ok('shouldStream at threshold', shouldStream(STREAM_THRESHOLD) === true);
ok('shouldStream above threshold', shouldStream(STREAM_THRESHOLD + 1) === true);
ok('shouldStream below threshold', shouldStream(STREAM_THRESHOLD - 1) === false);
ok('shouldStream(0) = false', shouldStream(0) === false);
ok('STREAM_THRESHOLD is a positive integer', Number.isInteger(STREAM_THRESHOLD) && STREAM_THRESHOLD > 0);
ok('STREAM_BATCH_SIZE is a positive integer', Number.isInteger(STREAM_BATCH_SIZE) && STREAM_BATCH_SIZE > 0);

// ---------------------------------------------------------------------------
console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
