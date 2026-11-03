#!/usr/bin/env bash
# Requires a reviewed, compiled runtime policy; never silently disables CTI.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CATS_CTI_POLICY:?Set CATS_CTI_POLICY to the compiled runtime policy}"
if [[ ! -r "$CATS_CTI_POLICY" ]]; then
  echo "CTI runtime policy is not readable: $CATS_CTI_POLICY" >&2
  exit 1
fi
export LD_PRELOAD="$root/build/libcats_sign_timer.so${LD_PRELOAD:+:$LD_PRELOAD}"
exec "$root/build/tls_context_selector_server" "$@"
