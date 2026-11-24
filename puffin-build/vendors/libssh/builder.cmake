use_languages(C)

# Expose the session id (exchange hash H of the first KEX, RFC 4253 §7.2) to the
# claim layer so the decryption recipe can source H from the PUT instead of
# reconstructing it from a (mutation-stale) hard-coded client KEXINIT. Pure
# observation; no behaviour change. instrument_claims.cmake handles the session-id
# field of every version in presets.toml.
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/src/packet.c -P "${CMAKE_CURRENT_LIST_DIR}/instrument_claims.cmake")
# The host-key record of the entity-authentication invariant C1: wraps the client's one host-key
# signature verification (packet_cb.c) to record that it succeeded. Pure observation; not applied
# where packet_cb.c has no single such call (libssh 0.8.x), see instrument_hostkey.cmake.
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/src/packet_cb.c -P "${CMAKE_CURRENT_LIST_DIR}/instrument_hostkey.cmake")

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DWITH_EXAMPLES=OFF
    -DWITH_GSSAPI=OFF
    -DWITH_SFTP=OFF
    -DWITH_NACL=OFF
    -DBUILD_SHARED_LIBS=OFF
    # libssh 0.8.x builds its main target shared unconditionally and only emits a
    # static archive under these knobs; newer libssh (0.9+) ignores them and uses
    # BUILD_SHARED_LIBS=OFF. Setting both keeps every version producing libssh.a.
    -DBUILD_STATIC_LIB=ON
    -DWITH_STATIC_LIB=ON
    -DCMAKE_POLICY_DEFAULT_CMP0148:STRING=OLD

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims
    -Wno-error
    -Wstrict-prototypes

    # SANCOV
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN
    $<$<BOOL:${asan}>:-fsanitize=address>
    $<$<BOOL:${asan}>:-static-libsan>

    # LLVM_COV
    $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
    $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
    $<$<BOOL:${llvm_cov}>:-O0>

    # GCOV
    $<$<BOOL:${gcov}>:-ftest-coverage>
    $<$<BOOL:${gcov}>:-fprofile-arcs>
    $<$<BOOL:${gcov}>:-O0>
)
