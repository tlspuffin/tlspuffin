# libssh part of the vendor metadata script, sourced by
# puffin-build/cmake/builder/cmake/vendorinfo.sh.in (see there for the contract).

# The session-id accessor added by instrument_claims.cmake: the harness's claims need it.
CLAIM_SYMBOLS=(puffin_ssh_get_session_id)

function detected_version() {
    local h="${INSTALL_DIR}/include/libssh/libssh_version.h" maj min mic
    maj=$(header_define "$h" LIBSSH_VERSION_MAJOR)
    min=$(header_define "$h" LIBSSH_VERSION_MINOR)
    mic=$(header_define "$h" LIBSSH_VERSION_MICRO)
    [ -n "$maj" ] && [ -n "$min" ] && [ -n "$mic" ] && printf '%s.%s.%s\n' "$maj" "$min" "$mic"
}
