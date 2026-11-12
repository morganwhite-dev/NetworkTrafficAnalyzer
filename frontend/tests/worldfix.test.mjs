import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { fixAntimeridian, unwrapRing } from "../js/worldfix.js";

const rings = (g) =>
  g.type === "Polygon" ? g.coordinates : g.type === "MultiPolygon" ? g.coordinates.flat() : [];
const jumps = (ring) => ring.filter((p, i) => i && Math.abs(p[0] - ring[i - 1][0]) > 180).length;

test("a ring that crosses 180 degrees becomes continuous", () => {
  const out = unwrapRing([[170, 0], [179, 1], [-179, 2], [-170, 3], [170, 0]]);
  assert.deepEqual(out.map((p) => p[0]), [170, 179, 181, 190, 170]);
  assert.equal(jumps(out), 0);
});

test("the bundled world outline has no line-across-the-map jumps after the fix", () => {
  const world = JSON.parse(
    readFileSync(new URL("../vendor/world-110m.geojson", import.meta.url), "utf8"),
  );
  const before = world.features.flatMap((f) => rings(f.geometry)).filter((r) => jumps(r));
  assert.ok(before.length > 0, "the data really does have jumps to fix");
  const fixed = fixAntimeridian(world);
  assert.equal(fixed.features.length, world.features.length);
  assert.equal(fixed.features.flatMap((f) => rings(f.geometry)).filter((r) => jumps(r)).length, 0);
});

test("the part that sticks out past 180 is mirrored onto the other edge", () => {
  const g = {
    type: "FeatureCollection",
    features: [{ geometry: { type: "Polygon", coordinates: [[[175, 0], [-175, 0], [-175, 5], [175, 5], [175, 0]]] } }],
  };
  const out = fixAntimeridian(g).features[0].geometry.coordinates;
  assert.equal(out.length, 2);
  assert.ok(Math.max(...out[0][0].map((p) => p[0])) > 180);
  assert.ok(Math.min(...out[1][0].map((p) => p[0])) < -180 + 10);
});
