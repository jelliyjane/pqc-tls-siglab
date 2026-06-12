#!/usr/bin/env bash
set -euo pipefail

ALG="${1:?usage: test_tls_sigalg.sh <sigalg> [--large-cert]}"
MODE="${2:-}"

ROOT="${PQC_TLS_TESTBED:-$PWD}"
INSTALL="${ROOT}/install"
CERTDIR="${ROOT}/certs"
PORT="${PORT:-44330}"
OPENSSL="${OPENSSL_ROOT:-${INSTALL}/openssl}/bin/openssl"
PROVPATH="${OQSPROV_MODULES:-${INSTALL}/oqs-provider/lib}"

export LD_LIBRARY_PATH="${LIBOQS_ROOT:-${INSTALL}/liboqs}/lib:${OPENSSL_ROOT:-${INSTALL}/openssl}/lib:${LD_LIBRARY_PATH:-}"

mkdir -p "${CERTDIR}"

"${OPENSSL}" genpkey \
  -provider-path "${PROVPATH}" -provider oqsprovider -provider default \
  -algorithm "${ALG}" -out "${CERTDIR}/${ALG}.key"

"${OPENSSL}" req -new -x509 \
  -provider-path "${PROVPATH}" -provider oqsprovider -provider default \
  -key "${CERTDIR}/${ALG}.key" -out "${CERTDIR}/${ALG}.crt" \
  -days 1 -subj "/CN=${ALG}"

"${OPENSSL}" x509 -in "${CERTDIR}/${ALG}.crt" -outform DER -out "${CERTDIR}/${ALG}.der"

"${OPENSSL}" s_server -accept "${PORT}" -tls1_3 \
  -cert "${CERTDIR}/${ALG}.crt" -key "${CERTDIR}/${ALG}.key" \
  -provider-path "${PROVPATH}" -provider oqsprovider -provider default \
  -www >/tmp/pqc-tls-server.log 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" >/dev/null 2>&1 || true' EXIT
sleep 0.25

START_NS="$(date +%s%N)"
if [ "${MODE}" = "--large-cert" ]; then
  "${INSTALL}/tls_maxcert_client" "127.0.0.1" "${PORT}" "${ALG}" "${PROVPATH}" >/tmp/pqc-tls-client.log 2>&1
else
  "${OPENSSL}" s_client -connect "127.0.0.1:${PORT}" -tls1_3 -sigalgs "${ALG}" \
    -provider-path "${PROVPATH}" -provider oqsprovider -provider default \
    -servername localhost </dev/null >/tmp/pqc-tls-client.log 2>&1
fi
END_NS="$(date +%s%N)"

SIZE="$(stat -c%s "${CERTDIR}/${ALG}.der")"
MS="$(( (END_NS - START_NS) / 1000000 ))"

echo "alg=${ALG}"
echo "cert_der_size=${SIZE}B"
echo "tls_handshake=${MS}ms"
