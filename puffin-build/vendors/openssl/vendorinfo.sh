# OpenSSL part of the vendor metadata script, sourced by
# puffin-build/cmake/builder/cmake/vendorinfo.sh.in (see there for the contract).

CLAIM_SYMBOLS=(register_claimer) # tlspuffin-claims

function detected_version() {
    local h="${INSTALL_DIR}/include/openssl/opensslv.h" v
    # 3.x defines OPENSSL_VERSION_STR; 1.x only "OpenSSL 1.1.1g  21 Apr 2020".
    v=$(header_define "$h" OPENSSL_VERSION_STR)
    if [ -z "$v" ]; then
        v=$(header_define "$h" OPENSSL_VERSION_TEXT)
        v=$(printf '%s\n' "$v" | awk '{ print $2 }')
    fi
    printf '%s\n' "$v"
}
