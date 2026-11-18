# wolfSSH part of the vendor metadata script, sourced by
# puffin-build/cmake/builder/cmake/vendorinfo.sh.in (see there for the contract).

# The session-id accessor added by instrument_claims.cmake: the harness's claims need it.
CLAIM_SYMBOLS=(puffin_wolfssh_get_session_id)

function detected_version() {
    header_define "${INSTALL_DIR}/include/wolfssh/version.h" LIBWOLFSSH_VERSION_STRING
}
