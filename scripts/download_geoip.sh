#!/usr/bin/env bash
# Download the free DB-IP "IP to City Lite" database (CC BY 4.0) for offline
# Geo-IP lookups. Nothing about your traffic leaves your Mac when this is used.
# The file is ~130 MB uncompressed and is refreshed monthly by DB-IP.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/data/dbip-city-lite.mmdb"
mkdir -p "$ROOT/data"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for offset in 0 1 2; do
  month="$(date -v-"${offset}"m +%Y-%m 2>/dev/null || date -d "-${offset} month" +%Y-%m)"
  url="https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz"
  echo "Trying $url"
  if curl -fL --proto '=https' --tlsv1.2 --retry 2 -o "$tmp/db.mmdb.gz" "$url"; then
    gunzip -c "$tmp/db.mmdb.gz" > "$tmp/db.mmdb"
    # Sanity check: a MaxMind DB ends with a metadata marker.
    if ! LC_ALL=C grep -aq $'\xab\xcd\xefMaxMind.com' "$tmp/db.mmdb"; then
      echo "Downloaded file doesn't look like an .mmdb database." >&2
      exit 1
    fi
    mv "$tmp/db.mmdb" "$DEST"
    echo "Saved $DEST ($(du -h "$DEST" | cut -f1)). IP geolocation by DB-IP.com, CC BY 4.0."
    exit 0
  fi
done
echo "Couldn't download the DB-IP database. Check your connection, or use --geo ip-api." >&2
exit 1
