#!/usr/bin/env bash
# One-time setup: virtual environment + hash-checked dependencies.
#   scripts/setup.sh              # app only
#   scripts/setup.sh --geoip      # also download the offline Geo-IP database (~57 MB)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is needed (found $("$PY" --version 2>&1)). Try: brew install python" >&2
  exit 1
fi

if [ ! -d .venv ]; then
  echo "Creating .venv with $("$PY" --version)"
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet --require-hashes -r requirements.txt
echo "Dependencies installed."

if [ "${1:-}" = "--geoip" ]; then
  bash scripts/download_geoip.sh
fi

cat <<'MSG'

Ready. Try the demo (no root needed):
  scripts/run.sh --replay samples/demo.pcap --loop

Live capture on your Wi-Fi (en0) needs access to /dev/bpf*:
  brew install --cask wireshark-chmodbpf   # recommended, then log out and back in
  scripts/run.sh
or, without ChmodBPF:
  sudo scripts/run.sh
MSG
