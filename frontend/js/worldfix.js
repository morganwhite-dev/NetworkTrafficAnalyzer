// Country outlines that cross the 180° line (Russia's far east, Fiji, Antarctica) arrive as rings
// that jump from +180 to -180 in one step. Leaflet draws that as a straight line across the whole
// map. Unwrap each ring so it runs on continuously, and add a copy shifted by 360° so the part
// that sticks out also shows on the other edge.

export function unwrapRing(ring) {
  if (!ring.length) return ring;
  const out = [[ring[0][0], ring[0][1]]];
  let offset = 0;
  for (let i = 1; i < ring.length; i++) {
    const step = ring[i][0] - ring[i - 1][0];
    if (step > 180) offset -= 360;
    else if (step < -180) offset += 360;
    out.push([ring[i][0] + offset, ring[i][1]]);
  }
  return out;
}

export function fixAntimeridian(geojson) {
  const features = geojson.features.map((f) => {
    const g = f.geometry;
    const polys =
      g?.type === "Polygon" ? [g.coordinates] : g?.type === "MultiPolygon" ? g.coordinates : null;
    if (!polys) return f;
    const out = [];
    for (const poly of polys) {
      const fixed = poly.map(unwrapRing);
      out.push(fixed);
      let min = Infinity;
      let max = -Infinity;
      for (const [x] of fixed[0]) {
        if (x < min) min = x;
        if (x > max) max = x;
      }
      const shift = max > 180 ? -360 : min < -180 ? 360 : 0;
      if (shift) out.push(fixed.map((r) => r.map(([x, y]) => [x + shift, y])));
    }
    return { ...f, geometry: { type: "MultiPolygon", coordinates: out } };
  });
  return { ...geojson, features };
}
