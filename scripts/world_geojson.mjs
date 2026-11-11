// Convert Natural Earth 110m countries (world-atlas, public domain) to a small
// GeoJSON file for the offline Geo-IP map. Run by scripts/vendor.sh.
import { readFileSync, writeFileSync } from "node:fs";
import { feature } from "topojson-client";

const topo = JSON.parse(readFileSync("node_modules/world-atlas/countries-110m.json", "utf8"));
const geo = feature(topo, topo.objects.countries);
const round = (c) => (typeof c[0] === "number" ? [Math.round(c[0] * 100) / 100, Math.round(c[1] * 100) / 100] : c.map(round));
for (const f of geo.features) {
  f.geometry.coordinates = round(f.geometry.coordinates);
  f.properties = {};
}
writeFileSync(process.argv[2], JSON.stringify(geo));
console.log(`world map: ${geo.features.length} countries`);
