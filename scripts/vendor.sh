#!/usr/bin/env bash
# Copy the browser libraries the dashboard uses into frontend/vendor/ and
# record their SHA-256 checksums. Run after `npm install` when bumping a
# version in package.json. The app itself never loads anything from a CDN.
set -euo pipefail
cd "$(dirname "$0")/.."
NM=node_modules
OUT=frontend/vendor
rm -rf "$OUT"
mkdir -p "$OUT/fonts" "$OUT/leaflet/images"

cp "$NM/chart.js/dist/chart.umd.min.js" "$OUT/chart.umd.min.js"
cp "$NM/leaflet/dist/leaflet.js" "$NM/leaflet/dist/leaflet.css" "$OUT/leaflet/"
cp "$NM"/leaflet/dist/images/*.png "$OUT/leaflet/images/"
for w in 400 500 700; do
  cp "$NM/@fontsource/jetbrains-mono/files/jetbrains-mono-latin-$w-normal.woff2" "$OUT/fonts/"
done
for f in LICENSE LICENSE.md; do
  [ -f "$NM/chart.js/$f" ] && cp "$NM/chart.js/$f" "$OUT/chart.LICENSE" || true
  [ -f "$NM/leaflet/$f" ] && cp "$NM/leaflet/$f" "$OUT/leaflet/LICENSE" || true
  [ -f "$NM/@tabler/icons/$f" ] && cp "$NM/@tabler/icons/$f" "$OUT/icons.LICENSE" || true
  [ -f "$NM/@fontsource/jetbrains-mono/$f" ] && cp "$NM/@fontsource/jetbrains-mono/$f" "$OUT/fonts/LICENSE" || true
done

# Offline world outline for the Geo-IP map (Natural Earth, public domain).
node scripts/world_geojson.mjs "$OUT/world-110m.geojson"
cp "$NM/world-atlas/LICENSE" "$OUT/world-110m.LICENSE" 2>/dev/null || true

# One small SVG sprite with just the icons we use (Tabler, MIT).
ICONS=(player-play player-stop trash download upload volume volume-off x eye eye-off
       arrow-down chevron-left chevron-right layout-sidebar-right-collapse
       layout-sidebar-right-expand alert-triangle)
{
  echo '<svg xmlns="http://www.w3.org/2000/svg">'
  for name in "${ICONS[@]}"; do
    body=$(perl -0777 -ne 'print $1 if /<svg[^>]*>(.*)<\/svg>/s' "$NM/@tabler/icons/icons/outline/$name.svg" | tr -d "\n" | sed -e "s/  */ /g")
    echo "<symbol id=\"i-$name\" viewBox=\"0 0 24 24\">$body</symbol>"
  done
  echo '</svg>'
} > "$OUT/icons.svg"

(cd "$OUT" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS)
echo "Vendored $(wc -l < "$OUT/SHA256SUMS" | tr -d ' ') files into $OUT"
