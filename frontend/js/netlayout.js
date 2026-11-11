// Layout math for the Network view. Pure functions only (unit-tested in Node).
//
// Projection: 2:1 isometric. World x runs down-right, y runs down-left, z up.
//   iso(x, y, z) = [x - y, (x + y) / 2 - z]

export const SLAB_Z = 12; // slab thickness; devices stand on top of it
export const TOP_INTERNET = 8;

export function iso(x, y, z = 0) {
  return [x - y, (x + y) / 2 - z];
}

/** Slab size and screen offset for a panel of W×H pixels. */
export function slabGeometry(W, H) {
  const raw = Math.max(150, Math.min(0.29 * W, H - 150));
  const S = Math.floor(raw / 24) * 24;       // whole grid cells, so the slab sits on the floor grid
  const ox = S + 24;                         // screen x of the world origin (slab's top corner)
  const oy = Math.max(120, H - S - 40);      // screen y of the slab's top surface; room for the incident card
  const wy = oy + SLAB_Z;                    // screen y of the world origin on the floor (z = 0)
  return { S, ox, oy, wy, rightEdge: 24 + 2 * S };
}

/** Screen point → world point on the plane z (inverse of iso + offset). */
export function worldAt(sx, sy, geom, z = SLAB_Z) {
  const a = sx - geom.ox;                    // x - y
  const b = 2 * (sy - geom.wy + z);          // x + y
  return { x: (a + b) / 2, y: (b - a) / 2, z };
}

export function screenAt(p, geom) {
  const [sx, sy] = iso(p.x, p.y, p.z);
  return [sx + geom.ox, sy + geom.wy];
}

/** Fraction of the slab top's screen bounding box → world point on the slab top. */
export function slabPoint(fx, fy, geom) {
  return worldAt(24 + fx * 2 * geom.S, geom.oy + fy * geom.S, geom);
}

// Two screen-horizontal rows parallel to the Mac-to-router line (one behind it,
// one in front), about 0.46·S apart so labels never touch.
// Busiest first: middle back, middle front, then the sides.
export const LAN_SLOTS = [
  [0.5, 0.25],
  [0.5, 0.75],
  [0.27, 0.25],
  [0.73, 0.75],
  [0.73, 0.25],
  [0.27, 0.75],
];
export const SELF_SLOT = [0.15, 0.5];
export const GATEWAY_SLOT = [0.86, 0.5];

/** Edge look from throughput. */
export function edgeStyle(bps) {
  const b = Math.max(0, bps || 0);
  const width = clamp(1 + (3 * (Math.log10(Math.max(b, 1)) - 4)) / 3, 1, 4);
  if (b < 1000) return { width, idle: true, gap: 0, dur: 0 };
  const t = clamp((Math.log10(b) - 3) / 4, 0, 1); // 1 KB/s → 0, 10 MB/s → 1
  const gap = Math.round(64 - 48 * t);
  const speed = 40 + 200 * t;
  const dur = Math.round(((3 + gap) / speed) * 100) / 100;
  return {
    width: Math.round(width * 10) / 10,
    idle: false,
    gap,
    dur,
    hot: b > 1e6,
  };
}

export function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

/** L-shaped path along the grid from world point a to world point b. */
export function gridPath(a, b, geom) {
  const c1 = { x: b.x, y: a.y, z: a.z };
  const c2 = { x: a.x, y: b.y, z: a.z };
  const mid = geom.S / 2;
  const d1 = Math.hypot(c1.x - mid, c1.y - mid);
  const d2 = Math.hypot(c2.x - mid, c2.y - mid);
  const corner = d1 <= d2 ? c1 : c2;
  const pts = [a, corner, b].map((p) => screenAt(p, geom));
  return `M${f(pts[0][0])} ${f(pts[0][1])}L${f(pts[1][0])} ${f(pts[1][1])}L${f(pts[2][0])} ${f(pts[2][1])}`;
}

/** Curve through the air: control points at 50% of the horizontal distance. */
export function airPath(from, to) {
  const dx = to[0] - from[0];
  return `M${f(from[0])} ${f(from[1])}C${f(from[0] + dx / 2)} ${f(from[1])} ${f(to[0] - dx / 2)} ${f(to[1])} ${f(to[0])} ${f(to[1])}`;
}

export function f(n) {
  return Math.round(n * 10) / 10;
}

/** Holds a ranking steady: a new order only applies after it has held for `hold` seconds. */
export class RankHold {
  constructor(hold = 3) {
    this.hold = hold;
    this.current = [];
    this.pending = null;
    this.since = 0;
  }

  update(next, now) {
    const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
    // Membership follows `next` at once: leavers drop out, newcomers join at the end.
    const wanted = new Set(next);
    const cur = this.current.filter((ip) => wanted.has(ip));
    for (const ip of next) if (!cur.includes(ip)) cur.push(ip);
    this.current = cur;
    // Reordering only applies once the new order has held for `hold` seconds.
    if (same(next, cur)) {
      this.pending = null;
    } else if (!this.pending || !same(next, this.pending)) {
      this.pending = next.slice();
      this.since = now;
    } else if (now - this.since >= this.hold) {
      this.current = next.slice();
      this.pending = null;
    }
    return this.current;
  }
}

/** Internet column rows: y centres around the router line. */
export function columnRows(n, H, centerY) {
  if (!n) return [];
  const sp = clamp((H - 72) / n, 40, 72);
  let y0 = centerY - ((n - 1) * sp) / 2;
  const top = 64;
  const bottom = H - 28;
  if (y0 < top) y0 = top;
  if (y0 + (n - 1) * sp > bottom) y0 = Math.max(top, bottom - (n - 1) * sp);
  const spacing = n > 1 ? Math.min(sp, (bottom - y0) / (n - 1)) : sp;
  return Array.from({ length: n }, (_, i) => y0 + i * spacing);
}

/**
 * Sankey-style ribbons for the Flows tab.
 * rows: [{key, share}] in display order. Returns ribbon geometry per row.
 */
export function ribbons(rows, W, H, opts = {}) {
  const top = opts.top ?? 44;
  const bottom = opts.bottom ?? H - 72;
  const x0 = opts.x0 ?? 64;
  const x1 = opts.x1 ?? Math.max(x0 + 160, W - 300);
  const n = rows.length;
  if (!n) return { bar: { x: x0 - 8, y: top, h: 0 }, items: [] };
  const rowGap = 2;
  const rowH = clamp((bottom - top) / n, 22, 44);
  const total = rows.reduce((s, r) => s + Math.max(0, r.share), 0) || 1;
  const usable = Math.max(
    40,
    Math.min(bottom - top, n * rowH) - rowGap * (n - 1),
  );
  const thick = rows.map((r) =>
    Math.max(2, (Math.max(0, r.share) / total) * usable),
  );
  const sumThick = thick.reduce((a, b) => a + b, 0) + rowGap * (n - 1);
  const scale =
    sumThick > usable + rowGap * (n - 1)
      ? (usable + rowGap * (n - 1)) / sumThick
      : 1;
  let a = top;
  const items = rows.map((r, i) => {
    const t = thick[i] * scale;                    // thickness at the Mac (left)
    const tr = Math.min(t, Math.max(2, rowH - 8));   // tapers to fit its row (right)
    const rowCenter = top + rowH * i + rowH / 2;
    const b1 = rowCenter - tr / 2;
    const a1 = a;
    a += t + rowGap * scale;
    const xm = (x0 + x1) / 2;
    const path =
      `M${f(x0)} ${f(a1)}C${f(xm)} ${f(a1)} ${f(xm)} ${f(b1)} ${f(x1)} ${f(b1)}` +
      `L${f(x1)} ${f(b1 + tr)}C${f(xm)} ${f(b1 + tr)} ${f(xm)} ${f(a1 + t)} ${f(x0)} ${f(a1 + t)}Z`;
    const topLine = `M${f(x0)} ${f(a1)}C${f(xm)} ${f(a1)} ${f(xm)} ${f(b1)} ${f(x1)} ${f(b1)}`;
    const botLine = `M${f(x0)} ${f(a1 + t)}C${f(xm)} ${f(a1 + t)} ${f(xm)} ${f(b1 + tr)} ${f(x1)} ${f(b1 + tr)}`;
    const mid = `M${f(x0)} ${f(a1 + t / 2)}C${f(xm)} ${f(a1 + t / 2)} ${f(xm)} ${f(b1 + tr / 2)} ${f(x1)} ${f(b1 + tr / 2)}`;
    return {
      key: r.key,
      path,
      topLine,
      botLine,
      mid,
      thickness: t,
      rowY: rowCenter,
      midPoint: [xm, (a1 + t / 2 + b1 + tr / 2) / 2],
    };
  });
  return {
    bar: { x: x0 - 8, y: top, h: a - top - rowGap * scale },
    items,
    x1,
    rowH,
  };
}
