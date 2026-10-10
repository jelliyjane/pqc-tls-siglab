#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_BUILD="${CATS_BUILD_DIR:-${TASK_ROOT}/build/context-acquisition}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-${TASK_ROOT}/install/openssl}"
TASK_LIB="${OPENSSL_PREFIX}/lib64"
if [[ ! -d "${TASK_LIB}" ]]; then TASK_LIB="${OPENSSL_PREFIX}/lib"; fi
mkdir -p "${TASK_BUILD}"
flags=(-O2 -g -std=c11 -Wall -Wextra -Werror -pthread -I"${TASK_ROOT}/src")
sslflags=(-I"${OPENSSL_PREFIX}/include" -L"${TASK_LIB}" -Wl,-rpath,"${TASK_LIB}")
cc "${flags[@]}" "${TASK_ROOT}/src/cats_context.c" "${TASK_ROOT}/src/test_cats_context.c" -lm -o "${TASK_BUILD}/test_cats_context"
cc "${flags[@]}" "${TASK_ROOT}/src/cats_context.c" "${TASK_ROOT}/src/test_cats_context_live.c" -lm -o "${TASK_BUILD}/test_cats_context_live"
cc "${flags[@]}" "${sslflags[@]}" -fPIC -shared "${TASK_ROOT}/src/cats_sign_timer.c" -ldl -o "${TASK_BUILD}/libcats_sign_timer.so"
cc "${flags[@]}" "${sslflags[@]}" "${TASK_ROOT}/src/cats_context.c" "${TASK_ROOT}/src/bench_cats_context.c" -lssl -lcrypto -ldl -lm -o "${TASK_BUILD}/bench_cats_context"
cc "${flags[@]}" "${sslflags[@]}" -DCATS_CONTEXT_ACQUISITION "${TASK_ROOT}/src/cats_context.c" "${TASK_ROOT}/src/tls_context_selector_server.c" -lssl -lcrypto -ldl -lm -o "${TASK_BUILD}/tls_context_selector_server"
"${TASK_BUILD}/test_cats_context"
"${TASK_BUILD}/test_cats_context_live"
