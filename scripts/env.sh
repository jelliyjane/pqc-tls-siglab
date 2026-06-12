#!/usr/bin/env bash

ROOT="${PQC_TLS_TESTBED:-$HOME/pqc-tls-testbed}"
INSTALL_DIR="${ROOT}/install"

export OPENSSL_ROOT="${INSTALL_DIR}/openssl"
export LIBOQS_ROOT="${INSTALL_DIR}/liboqs"
export OQSPROV_ROOT="${INSTALL_DIR}/oqs-provider"
export OQSPROV_MODULES="${OQSPROV_ROOT}/lib"

export PATH="${OPENSSL_ROOT}/bin:${PATH}"
export LD_LIBRARY_PATH="${LIBOQS_ROOT}/lib:${OPENSSL_ROOT}/lib:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="${OPENSSL_ROOT}/lib/ossl-modules"

oqs_openssl() {
  "${OPENSSL_ROOT}/bin/openssl" "$@" \
    -provider-path "${OQSPROV_MODULES}" \
    -provider oqsprovider \
    -provider default
}
