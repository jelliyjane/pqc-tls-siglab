#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CATS_MODEL_DIR="${CATS_MODEL_DIR:-$root/models}"
exec bash "$root/scripts/run_cti_server.sh" "$@"
