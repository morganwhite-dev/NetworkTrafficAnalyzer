#!/usr/bin/env bash
# Download the free DB-IP "Lite" databases (CC BY 4.0) for offline lookups.
# Nothing about your traffic leaves your Mac when these are used.
#   dbip-city-lite.mmdb  where a server is (World tab)           ~130 MB
#   dbip-asn-lite.mmdb   who runs it ("Apple", "Microsoft")      ~10 MB
# Both are refreshed monthly by DB-IP.
#   scripts/download_geoip.sh          both
#   scripts/download_geoip.sh asn      only the owner table
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/data"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  local kind="$1" dest="$ROOT/data/dbip-$1-lite.mmdb"
  for offset in 0 1 2; do
    month="$(date -v-"${offset}"m +%Y-%m 2>/dev/null || date -d "-${offset} month" +%Y-%m)"
    url="https://download.db-ip.com/free/dbip-${kind}-lite-${month}.mmdb.gz"
    echo "Trying $url"
    if curl -fL --proto '=https' --tlsv1.2 --retry 2 -o "$tmp/db.mmdb.gz" "$url"; then
      gunzip -c "$tmp/db.mmdb.gz" > "$tmp/db.mmdb"
      # Sanity check: a MaxMind DB ends with a metadata marker.
      if ! LC_ALL=C grep -aq $'\xab\xcd\xefMaxMind.com' "$tmp/db.mmdb"; then
        echo "Downloaded file doesn't look like an .mmdb database." >&2
        exit 1
      fi
      mv "$tmp/db.mmdb" "$dest"
      echo "Saved $dest ($(du -h "$dest" | cut -f1)). IP data by DB-IP.com, CC BY 4.0."
      return 0
    fi
  done
  echo "Couldn't download the DB-IP $kind database. Check your connection." >&2
  return 1
}

case "${1:-all}" in
  city) fetch city ;;
  asn) fetch asn ;;
  all) fetch city && fetch asn ;;
  *) echo "Usage: $0 [all|city|asn]" >&2; exit 2 ;;
esac
