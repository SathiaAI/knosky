// core/lod.mjs — Level-of-detail, viewport culling, clustering, and streaming
// utilities for large single-repo city graphs (SAT-447).
//
// All functions are pure (no side-effects, no DOM/canvas imports) so they can
// be used both in the Node.js test harness and inlined into the browser renderer.

// ---------------------------------------------------------------------------
// LOD tier constants
// Each tier drives rendering fidelity in city.template.html.
//   FULL   — full-detail buildings, cars, trees, props, shadows, connections
//   SIMPLE — buildings only (no cars / trees / props / shadows)
//   DOT    — each building renders as a coloured dot (very-far-out zoom)
//   CLUSTER— entire district collapses to a single cluster badge
// ---------------------------------------------------------------------------
export const LOD_FULL    = 0;  // zoom >= LOD_FULL_THRESHOLD
export const LOD_SIMPLE  = 1;  // zoom >= LOD_SIMPLE_THRESHOLD
export const LOD_DOT     = 2;  // zoom >= LOD_DOT_THRESHOLD
export const LOD_CLUSTER = 3;  // zoom <  LOD_DOT_THRESHOLD

// Zoom boundary constants (cam.zoom scale, matching renderer defaults)
export const LOD_FULL_THRESHOLD    = 0.35;  // below → drop cars/trees/props/shadows
export const LOD_SIMPLE_THRESHOLD  = 0.12;  // below → dots only
export const LOD_DOT_THRESHOLD     = 0.06;  // below → cluster badges

/**
 * Map a camera zoom value to an LOD tier.
 * @param {number} zoom
 * @returns {0|1|2|3}
 */
export function lodForZoom(zoom) {
  if (zoom >= LOD_FULL_THRESHOLD)   return LOD_FULL;
  if (zoom >= LOD_SIMPLE_THRESHOLD) return LOD_SIMPLE;
  if (zoom >= LOD_DOT_THRESHOLD)    return LOD_DOT;
  return LOD_CLUSTER;
}

// ---------------------------------------------------------------------------
// Viewport culling
// Works in canvas/screen-space: test an iso-world point against a padded
// screen rectangle.  Call once per draw to compute the clip region, then
// call isVisible() per object.
//
// cam  = { x, y, zoom }       (renderer camera object)
// cw   = canvas CSS width
// ch   = canvas CSS height
// pad  = extra margin in world-units so objects at the edge aren't clipped
//         (default: 2 tile-widths, 64px each → 128)
// ---------------------------------------------------------------------------

/**
 * Compute an axis-aligned world-space clip rect for the current camera view.
 * Returns { wx0, wy0, wx1, wy1 } in *world* coordinates (pre-camera transform).
 * @param {{ x: number, y: number, zoom: number }} cam
 * @param {number} cw  canvas CSS width
 * @param {number} ch  canvas CSS height
 * @param {number} [pad=128]  extra padding around the edges in world units
 * @returns {{ wx0: number, wy0: number, wx1: number, wy1: number }}
 */
export function viewportClip(cam, cw, ch, pad = 128) {
  // Screen corners → world coords: worldX = (screenX - cam.x) / cam.zoom
  const wx0 = (0 - cam.x) / cam.zoom - pad;
  const wy0 = (0 - cam.y) / cam.zoom - pad;
  const wx1 = (cw - cam.x) / cam.zoom + pad;
  const wy1 = (ch - cam.y) / cam.zoom + pad;
  return { wx0, wy0, wx1, wy1 };
}

/**
 * Return true if the iso-world point (wx, wy) is inside the clip rect.
 * @param {number} wx
 * @param {number} wy
 * @param {{ wx0: number, wy0: number, wx1: number, wy1: number }} clip
 * @returns {boolean}
 */
export function isVisible(wx, wy, clip) {
  return wx >= clip.wx0 && wx <= clip.wx1 && wy >= clip.wy0 && wy <= clip.wy1;
}

// ---------------------------------------------------------------------------
// Clustering
// Group city nodes by their district and compute a single representative
// "cluster badge" position + count.  The badge sits at the
// district centroid in world-space.
// ---------------------------------------------------------------------------

/**
 * Build an array of cluster descriptors from the current NODES array.
 * Each cluster has: { districtId, label, color, count, wx, wy }
 *
 * @param {Array<{ d: string, bx: number, by: number }>} nodes  renderer-adapted nodes (with bx/by world pos)
 * @param {{ [id: string]: { name: string, color: string } }} dcfg  DCFG district config
 * @returns {Array<{ districtId: string, label: string, color: string, count: number, wx: number, wy: number }>}
 */
export function buildClusters(nodes, dcfg) {
  const acc = {};
  for (const n of nodes) {
    const k = n.d;
    if (!acc[k]) acc[k] = { sumX: 0, sumY: 0, count: 0 };
    acc[k].sumX += n.bx;
    acc[k].sumY += n.by;
    acc[k].count++;
  }
  return Object.keys(acc).map(k => {
    const a = acc[k];
    const cfg = dcfg[k] || { name: k, color: '#7c83a3' };
    return {
      districtId: k,
      label: cfg.name,
      color: cfg.color,
      count: a.count,
      wx: a.sumX / a.count,
      wy: a.sumY / a.count,
    };
  });
}

// ---------------------------------------------------------------------------
// Streaming geometry build
// For large repos (node count >= STREAM_THRESHOLD) instead of building the
// entire OBJ array synchronously during ingest, the renderer schedules small
// batches of geometry across animation frames.  This function splits a nodes
// array into fixed-size batches.
// ---------------------------------------------------------------------------

/** Minimum node count before streaming geometry build is preferred. */
export const STREAM_THRESHOLD = 400;

/** Nodes processed per animation-frame batch. */
export const STREAM_BATCH_SIZE = 80;

/**
 * Split an array into batches of `size`.
 * @template T
 * @param {T[]} items
 * @param {number} [size=STREAM_BATCH_SIZE]
 * @returns {T[][]}
 */
export function makeBatches(items, size = STREAM_BATCH_SIZE) {
  if (!Array.isArray(items)) throw new TypeError('items must be an array');
  if (!Number.isInteger(size) || size < 1) throw new RangeError('size must be a positive integer');
  const batches = [];
  for (let i = 0; i < items.length; i += size) {
    batches.push(items.slice(i, i + size));
  }
  return batches;
}

/**
 * Return true when the node count warrants streaming geometry build.
 * @param {number} nodeCount
 * @returns {boolean}
 */
export function shouldStream(nodeCount) {
  return nodeCount >= STREAM_THRESHOLD;
}
