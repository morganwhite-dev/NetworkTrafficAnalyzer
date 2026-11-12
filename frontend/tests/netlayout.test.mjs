import assert from "node:assert/strict";
import { test } from "node:test";

import {
  edgeStyle, GATEWAY_SLOT, iso, LAN_SLOTS, RankHold, ribbons, screenAt, SELF_SLOT,
  slabGeometry, slabPoint, worldAt, columnRows, fitMiddle, slabLabelChars,
} from "../js/netlayout.js";

test("iso projection is 2:1", () => {
  assert.deepEqual(iso(10, 0, 0), [10, 5]);
  assert.deepEqual(iso(0, 10, 0), [-10, 5]);
  assert.deepEqual(iso(0, 0, 7), [0, -7]);
});

test("slab is grid-aligned and leaves room for callout tags above it", () => {
  const g = slabGeometry(930, 424);
  assert.equal(g.S % 24, 0);
  assert.ok(g.oy >= 80);
  assert.ok(g.rightEdge < 930);
});

test("screen ↔ world round trip", () => {
  const g = slabGeometry(930, 424);
  const w = worldAt(300, 200, g);
  const [sx, sy] = screenAt(w, g);
  assert.ok(Math.abs(sx - 300) < 1e-9 && Math.abs(sy - 200) < 1e-9);
});

test("every slot lands on the slab top", () => {
  const g = slabGeometry(930, 424);
  for (const slot of [SELF_SLOT, GATEWAY_SLOT, ...LAN_SLOTS]) {
    const w = slabPoint(...slot, g);
    assert.ok(w.x >= 0 && w.x <= g.S && w.y >= 0 && w.y <= g.S, `slot ${slot} off the slab`);
  }
});

test("the Mac-to-router trunk is horizontal on screen", () => {
  const g = slabGeometry(930, 424);
  const a = screenAt(slabPoint(...SELF_SLOT, g), g);
  const b = screenAt(slabPoint(...GATEWAY_SLOT, g), g);
  assert.ok(Math.abs(a[1] - b[1]) < 1e-9);
});

test("edge style scales with throughput", () => {
  assert.equal(edgeStyle(10).idle, true);
  const slow = edgeStyle(5_000);
  const fast = edgeStyle(20_000_000);
  assert.ok(fast.width > slow.width && fast.width <= 4 && slow.width >= 1);
  assert.ok(fast.gap < slow.gap);
  assert.ok(fast.hot && !slow.hot);
});

test("rank changes only apply after holding for 3 s", () => {
  const r = new RankHold(3);
  assert.deepEqual(r.update(["a", "b", "c"], 0), ["a", "b", "c"]);
  assert.deepEqual(r.update(["b", "a", "c"], 1), ["a", "b", "c"]);
  assert.deepEqual(r.update(["b", "a", "c"], 3.5), ["a", "b", "c"]);
  assert.deepEqual(r.update(["b", "a", "c"], 4.1), ["b", "a", "c"]);
  // membership changes apply at once
  assert.deepEqual(r.update(["b", "a", "d"], 4.2), ["b", "a", "d"]);
});

test("ribbons stack on the left and centre on their rows", () => {
  const out = ribbons([{ key: "x", share: 0.74 }, { key: "y", share: 0.2 }, { key: "z", share: 0.06 }], 900, 424);
  assert.equal(out.items.length, 3);
  assert.ok(out.items[0].thickness > out.items[1].thickness);
  assert.ok(out.items.every((i) => i.thickness >= 2));
  assert.ok(out.items[1].rowY > out.items[0].rowY);
});

test("column rows stay inside the panel", () => {
  const rows = columnRows(9, 424, 260);
  assert.equal(rows.length, 9);
  assert.ok(rows[0] >= 64 && rows.at(-1) <= 424 - 28);
});

test("slab labels fit the gap between neighbours in a row", () => {
  for (const S of [150, 240, 336, 384, 480]) {
    const { name, sub } = slabLabelChars(S);
    const gap = 0.4 * S; // LAN_SLOTS neighbours sit 0.2 of the slab width apart
    assert.ok(sub * 6.6 <= Math.max(gap, 60 + 12), `sub fits at S=${S}`);
    assert.ok(name >= 8 && sub >= 8 && name <= 18 && sub <= 30);
  }
  assert.ok(slabLabelChars(480).sub >= slabLabelChars(240).sub);
});

test("fitMiddle keeps both ends of an address", () => {
  assert.equal(fitMiddle("192.168.1.23", 20), "192.168.1.23");
  const out = fitMiddle("fe80::1d:9a08:8ab9:2f80", 14);
  assert.equal(out.length, 14);
  assert.ok(out.startsWith("fe80::") && out.endsWith("2f80") && out.includes("…"));
  assert.equal(fitMiddle("abcdef", 2), "ab");
  assert.equal(fitMiddle(null, 5), "");
});
