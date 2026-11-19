# wolfSSL part of the vendor metadata script, sourced by
# puffin-build/cmake/builder/cmake/vendorinfo.sh.in (see there for the contract).

CLAIM_SYMBOLS=(register_claimer) # tlspuffin-claims

function detected_version() {
    header_define "${INSTALL_DIR}/include/wolfssl/version.h" LIBWOLFSSL_VERSION_STRING
}
