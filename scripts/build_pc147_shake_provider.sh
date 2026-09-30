#!/usr/bin/env bash
# Build the additional provider separately; never install over the standard one.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQC_TLS_TESTBED="${PQC_TLS_TESTBED:-$ROOT}"
export PQC_TLS_TESTBED
source "$ROOT/scripts/env.sh"
SOURCE="$PQC_TLS_TESTBED/src-work/oqs-provider-shake98-repro"
BUILD="$PQC_TLS_TESTBED/src-work/build-oqs-provider-shake98-repro"
PIN=da0d3156af41915792cb99ce7a64b1a7633ce8f6
PATCH="$ROOT/repro/pc147/provider-shake98.patch"
if [[ ! -x "$OPENSSL_ROOT/bin/openssl" ]]; then
    echo 'Build the pinned baseline first: bash scripts/build_aws.sh' >&2
    exit 1
fi
if [[ -e "$SOURCE" || -e "$BUILD" ]]; then
    echo 'Reproduction paths already exist; refusing to alter an existing build.' >&2
    exit 1
fi
LIBOQS_CMAKE_DIR="$(find "$LIBOQS_ROOT" -type d -path '*/cmake/liboqs' -print -quit)"
[[ -n "$LIBOQS_CMAKE_DIR" ]] || { echo 'Installed liboqs CMake configuration missing' >&2; exit 1; }
git clone https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab.git "$SOURCE"
git -C "$SOURCE" checkout --detach "$PIN"
git -C "$SOURCE" apply --check "$PATCH"
git -C "$SOURCE" apply "$PATCH"
# Generated C sources are included in the patch; generation is not required here.
cmake -S "$SOURCE" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" \
    -Dliboqs_DIR="$LIBOQS_CMAKE_DIR"
cmake --build "$BUILD" -j"${JOBS:-2}"
CRYPTO_DIR="$OPENSSL_ROOT/lib"
[[ ! -d "$OPENSSL_ROOT/lib64" ]] || CRYPTO_DIR="$OPENSSL_ROOT/lib64"
python3 "$ROOT/repro/pc147/inspect_provider.py" \
    --libcrypto "$CRYPTO_DIR/libcrypto.so.3" \
    --provider-dir "$BUILD/lib" --provider-build shake98 \
    --mapping "$ROOT/repro/pc147/algorithm_mapping.json"
echo "Separate SHAKE provider available at: $BUILD/lib"
