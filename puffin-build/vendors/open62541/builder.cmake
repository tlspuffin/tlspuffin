use_languages(C)

# ============================================================================
# Vendored open62541 v1.5.6 (commit cd69ed6f). Two patch groups below:
#   (A) always-applied harness/correctness patches, and
#   (B) deliberately *planted* bug patches (disabled by default) used only to
#       validate that the fuzzer re-discovers known bugs.
#
# GROUND-TRUTH WARNING: any patch here modifies the vendored source tree that a
# *fresh/stock* server would also be built from. Do NOT enable a planted-bug
# patch (group B) for a build you intend to use as a clean baseline, and be
# aware that `Modifications-of-CLI-client-and-server` edits the example server
# sources (see its note). For a pristine control, build open62541 at cd69ed6f
# with NO patches from this directory.
# ============================================================================

# --- (A) Always applied ---

# Bug-fix-of-ClientUserId: GENUINE upstream bug in v1.5.6. In
#   Service_ActivateSession, UA_CertificateUtils_getSubjectName() is called with
#   its two arguments swapped vs. the declared signature
#   (getSubjectName(UA_ByteString *certificate, UA_String *subjectName); the
#   stock code passes &session->clientUserIdOfSession as `certificate` and
#   &userCertToken->certificateData as `subjectName`) -> type confusion when a
#   client authenticates with an X509 user certificate. The patch restores the
#   correct order. Author: V. Diemunsch (ANSSI). NOTE: not verified to be filed
#   as an upstream open62541 issue; treat "upstream-reported" as UNCONFIRMED.
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-fix-of-ClientUserId.patch)

# Modifications-of-CLI-client-and-server: NOT a bug fix. Adapts the example
#   binaries (examples/ci_server.c, examples/client_connect.c) for Puffin
#   (cert/key CLI args, reverse-connect, etc.). It touches ONLY example sources,
#   and this build sets -DUA_BUILD_EXAMPLES=OFF, so it has no effect on the PUT
#   produced here. It is kept applied only so a standalone example server can be
#   built from the same tree for TCP-mode testing.
#   /!\ GROUND-TRUTH HAZARD: an example server built from this patched tree is
#   NOT pristine upstream. For clean/stock TCP baselines, build examples from an
#   unpatched cd69ed6f checkout instead (as the /tmp/o62-stock control was).
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Modifications-of-CLI-client-and-server.patch)

# Instrumentation-to-debug: MISNAMED -- besides UA_LOG_* trace lines it carries
#   real behavioural changes the in-process harness relies on:
#     * tolerate errno 48 (EADDRINUSE) on the listen socket (port reuse across
#       fork-restarts) instead of failing,
#     * a bounded server-shutdown iteration loop (i < 10),
#     * client certificate thumbprint hex-formatting (for claims).
#   Removing it risks breaking fork-restart and teardown. Author: V. Diemunsch.
#   TODO: split the pure logging out and rename the behavioural part.
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Instrumentation-to-debug.patch)

# Bound-sync-disconnect: Puffin harness-resilience fix (not an upstream bug).
#   open62541's disconnectSecureChannel(sync=true) drains the event loop with an
#   UNBOUNDED `while(channel.state != CLOSED) el->run()`. Under fuzzing the
#   SecureChannel can be left wedged in a non-CLOSED/corrupted state, so the loop
#   spins forever (30s+ silent hang at agent teardown -> false Timeout
#   objectives). Reached via UA_Client_disconnect AND, internally,
#   UA_Client_delete. The patch bounds the loop (10000 iters). Verified: a known
#   hang trace 30s+ -> 85ms; bad-switch still detected. NOTE: the underlying
#   SecureChannel-lifecycle defect (use-after-free of the channel) is NOT fixed
#   here -- this only makes the harness resilient to it.
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bound-sync-disconnect.patch)

# Fix-securechannel-uaf: Puffin harness-resilience fix (genuine open62541 UAF).
#   In serverNetworkCallbackLocked, the CLOSING path calls deleteServerSecureChannel()
#   which UA_free()s the channel but leaves *connectionContext dangling; a later
#   callback on the same connection id then use-after-frees it (deleteServerSecureChannel
#   again, or UA_SecureChannel_loadBuffer on the receive path). Under the in-process
#   fuzzing event loop this fires routinely and, happening during crash-handling/teardown,
#   DOUBLE-FAULTS LibAFL's restart -> kills the whole campaign. Patch nulls the context
#   after delete so a later callback early-returns instead of touching freed memory. This
#   is the fix the eventloop_puffin_tcp.c KNOWN-ISSUE comment prescribes; it is the
#   remaining piece (with Bound-sync-disconnect + -DNDEBUG) for full crash resilience.
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Fix-securechannel-uaf.patch)

# Fix-securechannel-uaf-clo: companion to the patch above; fixes the UAF that
#   actually kills with-bit campaigns (the KNOWN ISSUE in eventloop_puffin_tcp.c).
#   On a CLO, Service_CloseSecureChannel frees the channel; the delayed CLOSING
#   callback (TCP_delayedClose -> serverNetworkCallbackLocked:801) then runs
#   deleteServerSecureChannel() on the freed channel -> heap-use-after-free at
#   ua_server_binary.c:118 (`while(channel->sessions)`), a double-free. A later
#   receive likewise hits UA_SecureChannel_loadBuffer on the freed channel. These
#   fire during LibAFL's crash-handling window (child exits 0, "Storing state ...
#   did not work") -> the campaign dies. Fix: before deleting/using `channel`,
#   verify it is still registered via puffinChannelStillRegistered() (walks
#   bpm->channels comparing POINTERS ONLY, never dereferencing the freed channel);
#   guards the CLOSING delete, the receive-path loadBuffer, and the message loop.
#   With -DNDEBUG + Bound-sync-disconnect + Fix-securechannel-uaf this is the piece
#   intended to complete crash resilience (campaigns no longer die mid-run).
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Fix-securechannel-uaf-clo.patch)

# --- (B) Planted bugs (DISABLED by default) ---
# Deliberately injected defects (V. Diemunsch) used to validate the fuzzer's
# bug-finding. Enable exactly one for a targeted reproduction / evaluation build;
# leave ALL disabled for normal campaigns and for any clean baseline.
#   Buffer_overflow            -- generic buffer overflow
#   Bug-Certificate-Thumbprint -- certificate thumbprint handling
#   Bug-bad-certificate        -- certificate validation
#   Bug-bad-policy             -- security-policy handling
#   Bug-bad-switch             -- OOB write in Service_ActivateSession
#                                 (session->clientUserIdOfSession.data[512]='!')
#   Bug-dead-session           -- activation of a dead session
#                                 (ua_services_session.c:1068)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Buffer_overflow.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-Certificate-Thumbprint.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-certificate.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-policy.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-switch.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-dead-session.patch)

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DCMAKE_BUILD_TYPE=Debug
    -DUA_ARCHITECTURE=none
    -DUA_BUILD_EXAMPLES=OFF
    -DUA_ENABLE_DA=OFF
    -DUA_ENABLE_DISCOVERY=ON
    -DUA_ENABLE_ENCRYPTION=OPENSSL
    -DUA_ENABLE_PUBSUB=OFF
    -DUA_ENABLE_PUBSUB_INFORMATIONMODEL=OFF
    -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=OFF
    -DUA_MULTITHREADING=0
    -DUA_NAMESPACE_ZERO=MINIMAL
    -DUA_ENABLE_DEBUG_SANITIZER=$<IF:$<BOOL:${asan}>,ON,OFF>

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -Wstrict-prototypes

    # -DNDEBUG: compile out all C assert()/UA_assert() (~348 of them). WHY: unlike
    # TLS/SSH vendors (built -O0, asserts off), open62541 is built Debug (asserts ON),
    # and it has assert()s on the harness TEARDOWN path -- notably
    # UA_Server_delete's `assert(state == STOPPED)` (ua_server.c:463) -- that fire
    # whenever the async server hasn't fully drained (routine under fuzzing). That
    # abort happens during the Rust Drop / crash-handling window, which LibAFL cannot
    # recover from ("Storing state in crashed fuzzer did not work"), so the WHOLE
    # campaign dies after a handful of crashes (empirically ~7-40k execs). This is the
    # root cause of OPC UA campaign death (TLS/SSH stay crash-robust because they have
    # no such teardown assert). ASAN bug detection is UNAFFECTED (ASAN != assert), and
    # a safety scan found no side-effecting assert() (none rely on the expression
    # running). To KEEP asserts for debugging (accepting campaign death), comment this
    # line out and keep CMAKE_BUILD_TYPE=Debug.
    -DNDEBUG

    # SANCOV
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN / UBSAN
    $<$<BOOL:${asan}>:-DOPENSSL_NO_BUF_FREELISTS>
    $<$<BOOL:${asan}>:-fsanitize=address,undefined>
    $<$<BOOL:${asan}>:-static-libsan>
    $<$<NOT:$<BOOL:${asan}>>:-fno-sanitize=all>

    # LLVM_COV
    $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
    $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
    $<$<BOOL:${llvm_cov}>:-O0>

    # LLVM GCOV
    $<$<BOOL:${gcov}>:-ftest-coverage>
    $<$<BOOL:${gcov}>:-fprofile-arcs>
    $<$<BOOL:${gcov}>:-O0>

)

