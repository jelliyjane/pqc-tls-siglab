#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${PQC_TLS_TESTBED:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
INSTALL_DIR="${ROOT}/install"

export OPENSSL_ROOT="${INSTALL_DIR}/openssl"
export LIBOQS_ROOT="${INSTALL_DIR}/liboqs"
export OQSPROV_ROOT="${INSTALL_DIR}/oqs-provider"
OPENSSL_LIBDIR="${OPENSSL_ROOT}/lib"
if [ -d "${OPENSSL_ROOT}/lib64" ]; then
  OPENSSL_LIBDIR="${OPENSSL_ROOT}/lib64"
fi

OQSPROV_MODULES="${OQSPROV_ROOT}/lib"
if [ -f "${OPENSSL_LIBDIR}/ossl-modules/oqsprovider.so" ]; then
  OQSPROV_MODULES="${OPENSSL_LIBDIR}/ossl-modules"
fi
export OQSPROV_MODULES

LIBOQS_LIBDIR="${LIBOQS_ROOT}/lib"
if [ -d "${LIBOQS_ROOT}/lib64" ]; then
  LIBOQS_LIBDIR="${LIBOQS_ROOT}/lib64"
fi

export PATH="${OPENSSL_ROOT}/bin:${PATH}"
export LD_LIBRARY_PATH="${LIBOQS_LIBDIR}:${OPENSSL_LIBDIR}:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="${OPENSSL_LIBDIR}/ossl-modules"

oqs_openssl() {
  "${OPENSSL_ROOT}/bin/openssl" "$@" \
    -provider-path "${OQSPROV_MODULES}" \
    -provider oqsprovider \
    -provider default
}

# Testbed-local OID overrides for OQS SLH-DSA SHA2 and SHAKE variants.
# OpenSSL 3.5 default provider already registers the standard SLH-DSA OIDs;
# these private OIDs keep oqsprovider variants usable for TLS experiments.
export OQS_OID_SLHDSASHA2128S=1.3.9999.200.1
export OQS_OID_SLHDSASHA2128F=1.3.9999.200.2
export OQS_OID_SLHDSASHA2192S=1.3.9999.200.3
export OQS_OID_SLHDSASHA2192F=1.3.9999.200.4
export OQS_OID_SLHDSASHA2256S=1.3.9999.200.5
export OQS_OID_SLHDSASHA2256F=1.3.9999.200.6
export OQS_OID_SLHDSASHAKE128S=1.3.9999.200.7
export OQS_OID_SLHDSASHAKE128F=1.3.9999.200.8
export OQS_OID_SLHDSASHAKE192S=1.3.9999.200.9
export OQS_OID_SLHDSASHAKE192F=1.3.9999.200.10
export OQS_OID_SLHDSASHAKE256S=1.3.9999.200.11
export OQS_OID_SLHDSASHAKE256F=1.3.9999.200.12
