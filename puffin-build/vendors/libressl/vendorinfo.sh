# LibreSSL part of the vendor metadata script, sourced by
# puffin-build/cmake/builder/cmake/vendorinfo.sh.in (see there for the contract).

CLAIM_SYMBOLS=(register_claimer) # tlspuffin-claims

function detected_version() {
    local v
    v=$(header_define "${INSTALL_DIR}/include/openssl/opensslv.h" LIBRESSL_VERSION_TEXT)
    printf '%s\n' "${v#LibreSSL }"
}
