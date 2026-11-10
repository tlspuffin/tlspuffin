#!/bin/bash
# Generates the X9.146 dual-algorithm certificate used by seed_cve_2026_5393, from the existing
# alice-key.pem / alice.pem (generate.sh) and an ML-DSA-44 test key shipped with wolfSSL:
#
#   alice-dual-alg.{der,pem}  server certificate for alice-key.pem, issued by alice.pem, carrying
#                             an ML-DSA-44 public key in the subjectAltPublicKeyInfo extension
#                             (2.5.29.72). No alternative signature extensions (2.5.29.73/74), so
#                             wolfSSL does not check an alternative signature on it.
#
# Usage: generate-dual-alg.sh <wolfSSL vendor dir built with dual_alg_certs (ML-DSA)>
#   e.g. generate-dual-alg.sh ../../vendor/wolfssl590-asan-dualalg
# Requires clang (the vendor library is ASan-instrumented) and OpenSSL >= 3.0.

set -euo pipefail
cd "$(dirname "$0")"
V=$(realpath "$1")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# 1. ML-DSA-44 public key as SubjectPublicKeyInfo DER, exported with wolfSSL (OpenSSL 3.0 has no
#    ML-DSA support)
clang -fsanitize=address -I"$V/include" gen/mldsa_export.c "$V/lib/libwolfssl.a" -lm -lpthread -o "$T/mldsa_export"
ASAN_OPTIONS=detect_leaks=0 "$T/mldsa_export" "$V/src/vendor/certs/mldsa/mldsa44_seed-priv.der" \
    "$T/mldsa44-spki.der" "$T/mldsa44-priv.der"

# 2. Certificate: alice-key.pem issued by alice.pem, with the ML-DSA-44 key as alternative key.
#    Fixed serial and dates (same validity start as alice.pem) so the output is reproducible.
SPKI_HEX=$(od -An -v -tx1 "$T/mldsa44-spki.der" | tr -d ' \n')
mkdir -p "$T/ca"
touch "$T/ca/index.txt"
echo 5393 > "$T/ca/serial"
cat > "$T/ca.cnf" <<EOF
[ca]
default_ca = mini
[mini]
dir = $T/ca
database = \$dir/index.txt
serial = \$dir/serial
new_certs_dir = \$dir
default_md = sha256
policy = anything
unique_subject = no
copy_extensions = none
[anything]
commonName = supplied
countryName = optional
[v3]
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
2.5.29.72 = DER:$SPKI_HEX
EOF
openssl req -new -key alice-key.pem -subj "/CN=tlspuffin-dual-alg/C=SK" -out "$T/alice-dual-alg.csr"
openssl ca -batch -config "$T/ca.cnf" -cert alice.pem -keyfile alice-key.pem -in "$T/alice-dual-alg.csr" \
    -out alice-dual-alg.pem -startdate 20231113000000Z -enddate 22970828000000Z -extensions v3 -notext
openssl x509 -in alice-dual-alg.pem -out alice-dual-alg.der -outform DER
openssl verify -CAfile alice.pem alice-dual-alg.pem
