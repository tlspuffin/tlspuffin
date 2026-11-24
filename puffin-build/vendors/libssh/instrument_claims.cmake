# PUFFIN fuzzing instrumentation for libssh (applied to src/packet.c).
#
# Adds puffin_ssh_get_session_id(), which the public API does not offer: the SSH
# session identifier (exchange hash H of the first KEX, RFC 4253 §7.2). The harness
# puts it in its claims, and the seeds derive from it the keys that decrypt the
# replies of the PUT. Also puffin_ssh_server_authenticated(), the server-side safety accessor of the
# entity-authentication oracle (invariant S1). Pure observation -- they never alter protocol behaviour.
#
# It is appended to packet.c, whose includes give the session and crypto structs, so
# it needs no anchor in the source. libssh 0.8.3 has no session_id_len (see below).
#
# Why this is a bespoke cmake-script patch and NOT the TLS claim mechanism:
# tlspuffin instruments claims with static `.patch` diffs plus a shared
# `tlspuffin-claims` include, and each TLS library exports a library-level
# `register_claimer` symbol. SSH has no such library-level claim symbol (the
# claimer lives in the sshpuffin harness), and a frozen `.patch` diff would rot
# across libssh releases, whereas appending a function stays valid. Both mechanisms
# still enter through the same cmake `PATCH_COMMANDS`/`patch()` build phase, so
# this stays consistent with the TLS vendors at the invocation level; only the
# per-vendor patch body is SSH-specific by necessity.

file(READ "${FILE}" content)

# Idempotent: PATCH_COMMANDS may re-run against already-patched source.
if(content MATCHES "puffin_ssh_get_session_id")
  message(STATUS "PUFFIN libssh instrument: already applied to ${FILE}; skipping")
  return()
endif()

set(accessor "
/* ===== PUFFIN fuzzing instrumentation: the session id, for the claims ===== */
int puffin_ssh_get_session_id(ssh_session session, const unsigned char **out, size_t *len);
__attribute__((visibility(\"default\")))
int puffin_ssh_get_session_id(ssh_session session, const unsigned char **out, size_t *len)
{
    if (session == NULL || session->current_crypto == NULL ||
        session->current_crypto->session_id == NULL) {
        return -1;
    }
    *out = session->current_crypto->session_id;
#if LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 9, 0)
    /* libssh 0.8.x has no session_id_len: the session id is digest_len bytes long */
    *len = session->current_crypto->digest_len;
#else
    *len = session->current_crypto->session_id_len;
#endif
    return 0;
}

/* Entity-auth invariant S1 (server side): 1 iff the session is user-authenticated
 * (SSH_SESSION_FLAG_AUTHENTICATED, which a server sets only in ssh_auth_reply_success, when one of
 * its auth callbacks approved the client). The harness combines it with its own record of having
 * approved a credential: authenticated without that approval is a bypass, impossible honestly.
 * Pure observation. */
int puffin_ssh_server_authenticated(ssh_session session);
__attribute__((visibility(\"default\")))
int puffin_ssh_server_authenticated(ssh_session session)
{
    if (session == NULL) {
        return 0;
    }
    return (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) ? 1 : 0;
}
")

file(APPEND "${FILE}" "${accessor}")
message(STATUS "PUFFIN libssh instrument: added the session-id accessor to ${FILE}")
