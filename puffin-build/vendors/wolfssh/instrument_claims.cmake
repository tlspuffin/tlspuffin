# PUFFIN fuzzing instrumentation for wolfSSH (applied to src/ssh.c).
#
# Exposes puffin_wolfssh_get_session_id() -- the SSH session identifier --
# and the safety accessors of the entity-authentication oracle (below).
# puffin_wolfssh_get_session_id(): the SSH session identifier
# (exchange hash H of the first KEX, RFC 4253 §7.2), read from the internal
# WOLFSSH struct (ssh->sessionId / sessionIdSz). wolfSSH has no public getter and
# does not install internal.h, so the decryption recipe has no other way to
# obtain H and derive the server-to-client keys. This mirrors the libssh
# instrument (puffin_ssh_get_session_id); together they let the differential
# source H from each PUT instead of reconstructing it from a hard-coded (and
# therefore mutation-stale) client KEXINIT.
#
# Pure observation -- it never alters protocol behaviour. src/ssh.c already
# includes <wolfssh/internal.h>, so the WOLFSSH struct is fully in scope; the
# accessor is appended at end of file, so there is no anchor to drift across
# wolfSSH versions.
#
# For why SSH claim instrumentation is a bespoke cmake-script patch rather than
# the TLS `patch()` + `tlspuffin-claims` (`register_claimer`) mechanism, see the
# rationale in vendors/libssh/instrument_claims.cmake.

file(READ "${FILE}" content)

# Idempotent: PATCH_COMMANDS may re-run against already-patched source.
if(content MATCHES "puffin_wolfssh_get_session_id")
  message(STATUS "PUFFIN wolfssh instrument: already applied to ${FILE}; skipping")
  return()
endif()

set(accessor "
/* ===== PUFFIN fuzzing instrumentation: the session id, for the claims ===== */
/* Exchange hash H of the first KEX == SSH session id (RFC 4253 §7.2). Read from
 * the internal WOLFSSH struct; wolfSSH exposes no public getter. Default
 * visibility so the harness (which declares it __attribute__((weak))) links it. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_get_session_id(WOLFSSH *ssh, const unsigned char **out, unsigned int *len)
{
    if (ssh == NULL || ssh->sessionIdSz == 0) {
        return -1;
    }
    *out = ssh->sessionId;
    *len = ssh->sessionIdSz;
    return 0;
}

/* CVE-2025-14942 oracle (client side): 1 iff the client believes the server accepted user
 * authentication (serverState >= SERVER_USERAUTH_ACCEPT_DONE) while it is still in its initial
 * key exchange (isKeying, connectState < CONNECT_KEYED). The vulnerable client accepts such an
 * out-of-order message; the fixed one rejects it. It cannot happen honestly: serverState reaches
 * ACCEPT_DONE only after the client sent its user-auth request, past CONNECT_KEYED -- which also
 * excludes a legitimate post-auth rekey (connectState is then CONNECT_DONE). Pure observation. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_authed_while_keying(WOLFSSH *ssh)
{
    if (ssh == NULL) {
        return 0;
    }
    return (ssh->isKeying != 0 && ssh->serverState >= SERVER_USERAUTH_ACCEPT_DONE
            && ssh->connectState < CONNECT_KEYED) ? 1 : 0;
}

/* CVE-2025-11625 oracle (client side): 1 iff the client finished its initial key exchange
 * (connectState >= CONNECT_KEYED). The harness combines it with its own record of whether its
 * host-key-check callback ever ran -- only DoKexDhReply, which verifies the server's signature over
 * H, calls it: KEYED without a checked host key is the bypass (a NEWKEYS accepted before any
 * KEX_ECDH_REPLY), impossible honestly. Pure observation. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_client_keyed(WOLFSSH *ssh)
{
    if (ssh == NULL) {
        return 0;
    }
    return (ssh->connectState >= CONNECT_KEYED) ? 1 : 0;
}

/* Entity-auth invariant S1 (server side): 1 iff the server considers the client authenticated
 * (clientState >= CLIENT_USERAUTH_DONE, wolfSSH's record of its peer's progress, which it sets only
 * once a user authentication succeeded). The harness combines it with its own record of having
 * approved a credential: authenticated without that approval is a bypass, impossible honestly.
 * Pure observation. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_server_user_authed(WOLFSSH *ssh)
{
    if (ssh == NULL) {
        return 0;
    }
    return (ssh->clientState >= CLIENT_USERAUTH_DONE) ? 1 : 0;
}
")

file(APPEND "${FILE}" "${accessor}")
message(STATUS "PUFFIN wolfssh instrument: appended session-id accessor to ${FILE}")
