#!/usr/bin/env bash
set -euo pipefail

ROOT="${PQC_TLS_TESTBED:-$PWD}"
SRC="${ROOT}/src-work"
INSTALL="${ROOT}/install"
JOBS="${JOBS:-$(nproc)}"

OPENSSL_REPO="${OPENSSL_REPO:-https://github.com/openssl/openssl.git}"
OPENSSL_REF="${OPENSSL_REF:-openssl-3.5.7}"
LIBOQS_REPO="${LIBOQS_REPO:-https://github.com/open-quantum-safe/liboqs.git}"
LIBOQS_REF="${LIBOQS_REF:-main}"
OQSPROVIDER_REPO="${OQSPROVIDER_REPO:-https://github.com/open-quantum-safe/oqs-provider.git}"
OQSPROVIDER_REF="${OQSPROVIDER_REF:-main}"

mkdir -p "${SRC}" "${INSTALL}"

clone_or_update() {
  local repo="$1"
  local ref="$2"
  local dir="$3"

  if [ ! -d "${dir}/.git" ]; then
    git clone "${repo}" "${dir}"
  fi
  git -C "${dir}" fetch --all --tags
  git -C "${dir}" checkout "${ref}"
}

clone_or_update "${OPENSSL_REPO}" "${OPENSSL_REF}" "${SRC}/openssl"
clone_or_update "${LIBOQS_REPO}" "${LIBOQS_REF}" "${SRC}/liboqs"
clone_or_update "${OQSPROVIDER_REPO}" "${OQSPROVIDER_REF}" "${SRC}/oqs-provider"

(
  cd "${SRC}/openssl"
  ./Configure --prefix="${INSTALL}/openssl" --openssldir="${INSTALL}/openssl/ssl"
  make -j"${JOBS}"
  make install_sw
)

cmake -S "${SRC}/liboqs" -B "${SRC}/build-liboqs" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${INSTALL}/liboqs" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_DIST_BUILD=ON \
  -DOQS_OPT_TARGET=auto
cmake --build "${SRC}/build-liboqs" -j"${JOBS}"
cmake --install "${SRC}/build-liboqs"

cmake -S "${SRC}/oqs-provider" -B "${SRC}/build-oqs-provider" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${INSTALL}/oqs-provider" \
  -DOPENSSL_ROOT_DIR="${INSTALL}/openssl" \
  -Dliboqs_DIR="${INSTALL}/liboqs/lib/cmake/liboqs"
cmake --build "${SRC}/build-oqs-provider" -j"${JOBS}"
cmake --install "${SRC}/build-oqs-provider"

cc -O2 -Wall -Wextra \
  -I"${INSTALL}/openssl/include" \
  "${ROOT}/src/tls_maxcert_client.c" \
  -L"${INSTALL}/openssl/lib" -lssl -lcrypto \
  -Wl,-rpath,"${INSTALL}/openssl/lib" \
  -o "${INSTALL}/tls_maxcert_client"

echo "Build complete."
echo "Run: source ${ROOT}/scripts/env.sh"
