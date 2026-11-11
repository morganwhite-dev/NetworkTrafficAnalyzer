// Isometric device models built from boxes with three face shades.
// Every model is drawn around the centre of its footprint at local (0, 0, 0).

import { svg } from "./format.js";
import { iso } from "./netlayout.js";

function pts(list) {
  return list
    .map((p) =>
      iso(...p)
        .map((v) => v.toFixed(1))
        .join(","),
    )
    .join(" ");
}

/** Append a w×d×h box at (x, y, z): +y face, +x face, then the top. */
export function box(g, x, y, z, w, d, h) {
  const t = z + h;
  g.append(
    svg("polygon", {
      class: "f-left",
      points: pts([
        [x, y + d, z],
        [x + w, y + d, z],
        [x + w, y + d, t],
        [x, y + d, t],
      ]),
    }),
    svg("polygon", {
      class: "f-right",
      points: pts([
        [x + w, y, z],
        [x + w, y + d, z],
        [x + w, y + d, t],
        [x + w, y, t],
      ]),
    }),
    svg("polygon", {
      class: "f-top",
      points: pts([
        [x, y, t],
        [x + w, y, t],
        [x + w, y + d, t],
        [x, y + d, t],
      ]),
    }),
  );
}

function quad(g, cls, corners) {
  g.append(svg("polygon", { class: cls, points: pts(corners) }));
}

const MODELS = {
  laptop(g) {
    const w = 30,
      d = 22,
      ox = -w / 2,
      oy = -d / 2;
    box(g, ox, oy, 0, w, d, 2);
    box(g, ox, oy, 2, w, 2, 20);
    quad(g, "f-screen", [
      [ox + 2, oy + 2, 4],
      [ox + w - 2, oy + 2, 4],
      [ox + w - 2, oy + 2, 20],
      [ox + 2, oy + 2, 20],
    ]);
    return { height: 22, w, d };
  },
  router(g) {
    const w = 26,
      d = 16,
      ox = -w / 2,
      oy = -d / 2;
    box(g, ox, oy, 0, w, d, 5);
    box(g, ox + 2, oy + 1, 5, 2, 2, 12);
    box(g, ox + 22, oy + 1, 5, 2, 2, 12);
    for (const lx of [6, 11, 16]) {
      quad(g, "f-light", [
        [ox + lx, oy + d, 2],
        [ox + lx + 2, oy + d, 2],
        [ox + lx + 2, oy + d, 3],
        [ox + lx, oy + d, 3],
      ]);
    }
    return { height: 17, w, d };
  },
  phone(g) {
    const w = 10,
      d = 18,
      ox = -w / 2,
      oy = -d / 2;
    box(g, ox, oy, 0, w, d, 1.5);
    quad(g, "f-screen", [
      [ox + 1.5, oy + 1.5, 1.5],
      [ox + w - 1.5, oy + 1.5, 1.5],
      [ox + w - 1.5, oy + d - 1.5, 1.5],
      [ox + 1.5, oy + d - 1.5, 1.5],
    ]);
    return { height: 2, w, d };
  },
  tv(g) {
    const w = 32,
      d = 6,
      ox = -w / 2,
      oy = -d / 2;
    box(g, ox + 13, oy, 0, 6, 4, 3);
    box(g, ox, oy, 3, w, 2, 20);
    quad(g, "f-screen", [
      [ox + 2, oy + 2, 5],
      [ox + w - 2, oy + 2, 5],
      [ox + w - 2, oy + 2, 21],
      [ox + 2, oy + 2, 21],
    ]);
    return { height: 23, w, d };
  },
  server(g) {
    const w = 20,
      d = 20,
      ox = -w / 2,
      oy = -d / 2;
    for (let i = 0; i < 3; i++) {
      box(g, ox, oy, i * 6, w, d, 5);
      quad(g, "f-light", [
        [ox + 3, oy + d, i * 6 + 2],
        [ox + 5, oy + d, i * 6 + 2],
        [ox + 5, oy + d, i * 6 + 3],
        [ox + 3, oy + d, i * 6 + 3],
      ]);
    }
    return { height: 17, w, d };
  },
  unknown(g) {
    const w = 14,
      d = 14;
    box(g, -w / 2, -d / 2, 0, w, d, 10);
    return { height: 10, w, d };
  },
  others(g) {
    const w = 20,
      d = 20,
      ox = -w / 2,
      oy = -d / 2;
    for (let i = 0; i < 3; i++) box(g, ox, oy, i * 6, w, d, 5);
    return { height: 17, w, d };
  },
};

/** Build a device model inside group g. Returns its height and footprint. */
export function device(g, kind) {
  return (MODELS[kind] || MODELS.unknown)(g);
}

/** Diamond outline around a footprint, on the floor (targeting marker). */
export function footprintDiamond(w, d, pad = 8) {
  const x = -w / 2 - pad,
    y = -d / 2 - pad,
    W = w + pad * 2,
    D = d + pad * 2;
  return pts([
    [x, y, 0],
    [x + W, y, 0],
    [x + W, y + D, 0],
    [x, y + D, 0],
  ]);
}

/** Slab: a raised isometric platform S×S×h. */
export function slab(g, S, h) {
  box(g, 0, 0, 0, S, S, h);
}
