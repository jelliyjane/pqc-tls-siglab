#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${PQC_TLS_TESTBED:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SRC="${ROOT}/src-work"
INSTALL="${ROOT}/install"
JOBS="${JOBS:-$(nproc)}"

OPENSSL_REPO="${OPENSSL_REPO:-https://github.com/openssl/openssl.git}"
OPENSSL_REF="${OPENSSL_REF:-openssl-3.5.7}"
LIBOQS_REPO="${LIBOQS_REPO:-https://github.com/jelliyjane/liboqs-pqc-tls-siglab.git}"
LIBOQS_REF="${LIBOQS_REF:-fa33db143fb12a2e1e306b51ab3c8c98432a46c4}"
OQSPROVIDER_REPO="${OQSPROVIDER_REPO:-https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab.git}"
OQSPROVIDER_REF="${OQSPROVIDER_REF:-88910827255acea27a218374ccf3bce7446f542d}"

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

OPENSSL_TIMING_PATCH="${ROOT}/patches/openssl-3.5-s-client-handshake-time.patch"
if ! grep -q 'OPT_HANDSHAKE_TIME' "${SRC}/openssl/apps/s_client.c"; then
  git -C "${SRC}/openssl" apply "${OPENSSL_TIMING_PATCH}"
fi

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
  -DOQS_OPT_TARGET=auto \
  -DOQS_ENABLE_SIG_FAEST=ON \
  -DOQS_ENABLE_SIG_HAWK=ON \
  -DOQS_ENABLE_SIG_QRUOV_ROUND2=ON \
  -DOQS_ENABLE_SIG_SDITH=ON
cmake --build "${SRC}/build-liboqs" -j"${JOBS}"
cmake --install "${SRC}/build-liboqs"

LIBOQS_CMAKE_DIR="$(find "${INSTALL}/liboqs" -type d -path '*/cmake/liboqs' -print -quit)"
if [ -z "${LIBOQS_CMAKE_DIR}" ]; then
  echo "Unable to locate the installed liboqs CMake package." >&2
  exit 1
fi

cmake -S "${SRC}/oqs-provider" -B "${SRC}/build-oqs-provider" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${INSTALL}/oqs-provider" \
  -DOPENSSL_ROOT_DIR="${INSTALL}/openssl" \
  -Dliboqs_DIR="${LIBOQS_CMAKE_DIR}"
cmake --build "${SRC}/build-oqs-provider" -j"${JOBS}"
cmake --install "${SRC}/build-oqs-provider"

OPENSSL_LIBDIR="${INSTALL}/openssl/lib"
if [ -d "${INSTALL}/openssl/lib64" ]; then
  OPENSSL_LIBDIR="${INSTALL}/openssl/lib64"
fi

cc -O2 -Wall -Wextra \
  -I"${INSTALL}/openssl/include" \
  "${ROOT}/src/tls_maxcert_client.c" \
  -L"${OPENSSL_LIBDIR}" -lssl -lcrypto \
  -Wl,-rpath,"${OPENSSL_LIBDIR}" \
  -o "${INSTALL}/tls_maxcert_client"

echo "Build complete."
echo "Run: source ${ROOT}/scripts/env.sh"
echo "TLS timer: openssl s_client -handshake_time"
