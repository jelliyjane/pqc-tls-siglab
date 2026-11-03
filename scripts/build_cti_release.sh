#!/usr/bin/env bash
# Build against the existing testbed OpenSSL; do not rebuild its dependencies.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prefix="${1:?Usage: build_cti_release.sh OPENSSL_PREFIX}"
lib="$prefix/lib"
if [[ -d "$prefix/lib64" ]]; then lib="$prefix/lib64"; fi
mkdir -p "$root/build"
flags=(-O2 -std=c11 -Wall -Wextra -Werror -pthread
       "-I$prefix/include" "-I$root/src" "-L$lib" "-Wl,-rpath,$lib")
cc "${flags[@]}" -DCATS_CONTEXT_ACQUISITION \
  "$root/src/tls_context_selector_server.c" "$root/src/cats_context.c" \
  -lssl -lcrypto -ldl -lm -o "$root/build/tls_context_selector_server"
cc "${flags[@]}" -fPIC -shared "$root/src/cats_sign_timer.c" \
  -ldl -o "$root/build/libcats_sign_timer.so"
cc "${flags[@]}" "$root/src/cats_context.c" "$root/src/test_cats_context.c" \
  -lm -o "$root/build/test_cats_context"
cc "${flags[@]}" "$root/src/cats_context.c" "$root/src/test_cats_context_live.c" \
  -lm -o "$root/build/test_cats_context_live"
cc "${flags[@]}" "$root/src/test_tcp_selection_window.c" \
  -o "$root/build/test_tcp_selection_window"
"$prefix/bin/openssl" version
"$root/build/test_cats_context"
"$root/build/test_cats_context_live"
"$root/build/test_tcp_selection_window"
python3 "$root/scripts/test_cti_policy.py" --openssl-prefix "$prefix" \
  --server-binary "$root/build/tls_context_selector_server" \
  --sign-timer "$root/build/libcats_sign_timer.so" --pqc
if [[ -f "$root/models/fixtures.json" ]]; then
  python3 "$root/scripts/test_cats_model.py" --models "$root/models"
fi
