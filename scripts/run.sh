#!/usr/bin/env bash
# Start the analyzer. Examples:
#   scripts/run.sh --replay samples/demo.pcap --loop   # demo, no root needed
#   scripts/run.sh                                     # live on en0 (needs ChmodBPF or sudo)
#   sudo scripts/run.sh --iface en0                    # opens capture as root, then drops to you
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "No virtual environment yet. Run scripts/setup.sh first." >&2
  exit 1
fi
export PYTHONPATH="$ROOT/backend${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m app "$@"
