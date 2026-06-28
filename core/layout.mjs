// Deterministic N-category city layout (Phase 2b). Implements locked D3:
// stable order (category manifest order), each district a square sized to hold its nodes,
// districts shelf-packed into a roughly square city. Recompute is deterministic (same data -> same layout).
export function layoutCity(city, opts = {}) {
  const PAD = opts.pad ?? 1;   // building-cells of padding inside a district
  const GAP = opts.gap ?? 2;   // building-cells between districts

  const cats = (city.categories || []).slice().sort((a, b) => a.order - b.order);
  const byCat = new Map(cats.map(c => [c.id, []]));
  for (const n of city.nodes || []) {
    if (!byCat.has(n.category)) byCat.set(n.category, []);   // tolerate uncategorized
    byCat.get(n.category).push(n);
  }
  // ensure any extra categories (not in manifest) still get a district, appended in id order
  const extra = [...byCat.keys()].filter(id => !cats.find(c => c.id === id)).sort();
  const order = [...cats.map(c => ({ id: c.id, label: c.label, color: c.color })),
                 ...extra.map(id => ({ id, label: id, color: '#888' }))];

  const districts = order.map((c, i) => {
    const nodes = byCat.get(c.id) || [];
    const side = Math.max(1, Math.ceil(Math.sqrt(nodes.length || 1)));
    return { id: c.id, label: c.label, color: c.color, idx: i, nodes, side, w: side + PAD * 2, h: side + PAD * 2 };
  });

  const totalArea = districts.reduce((a, d) => a + d.w * d.h, 0);
  const rowTarget = Math.max(Math.max(...districts.map(d => d.w)), Math.ceil(Math.sqrt(totalArea)));

  const placed = [];
  let x = 0, y = 0, rowH = 0;
  for (const d of districts) {
    if (x > 0 && x + d.w > rowTarget) { x = 0; y += rowH + GAP; rowH = 0; }
    d.x = x; d.y = y; rowH = Math.max(rowH, d.h);
    d.nodes.forEach((n, i) => {
      placed.push({
        id: n.id, title: n.title, category: n.category, kind: n.kind,
        gx: d.x + PAD + (i % d.side),
        gy: d.y + PAD + Math.floor(i / d.side),
        ref: n.provenance ? n.provenance.ref : null,
      });
    });
    x += d.w + GAP;
  }
  const gridW = Math.max(1, ...placed.map(p => p.gx + 1), ...districts.map(d => d.x + d.w));
  const gridH = Math.max(1, ...placed.map(p => p.gy + 1), ...districts.map(d => d.y + d.h));
  return { districts, nodes: placed, gridW, gridH };
}
