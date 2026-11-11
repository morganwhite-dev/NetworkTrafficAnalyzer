#!/usr/bin/env bash
# Check the vendored browser libraries against their recorded checksums.
set -euo pipefail
cd "$(dirname "$0")/../frontend/vendor"
shasum -a 256 -c SHA256SUMS --quiet && echo "Vendored files match SHA256SUMS."
