# PUFFIN fuzzing instrumentation for wolfSSH (applied to src/ssh.c).
#
# Exposes puffin_wolfssh_get_session_id() -- the SSH session identifier
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
/* ===== PUFFIN fuzzing instrumentation (matching-conversation / decryption) ===== */
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

/* CVE-2025-14942 oracle (client side). Returns 1 iff the client believes the
 * server accepted user authentication (serverState >= SERVER_USERAUTH_ACCEPT_DONE)
 * while its OWN handshake is still in the initial key exchange (isKeying != 0 and
 * connectState < CONNECT_KEYED, i.e. it has not even finished the first NEWKEYS).
 * That is the out-of-order auth accept the vulnerable client permits and the fixed
 * client rejects (message not allowed). It cannot occur honestly: serverState only
 * reaches ACCEPT_DONE after the client sends userauth, which is past CONNECT_KEYED
 * -- so a legitimate \"none\" authentication and a legitimate post-auth rekey (where
 * connectState == CONNECT_DONE) are both excluded. Pure observation of
 * ssh->isKeying / ssh->serverState / ssh->connectState; never alters behaviour. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_authed_while_keying(WOLFSSH *ssh)
{
    if (ssh == NULL) {
        return 0;
    }
    return (ssh->isKeying != 0
            && ssh->serverState >= SERVER_USERAUTH_ACCEPT_DONE
            && ssh->connectState < CONNECT_KEYED)
        ? 1 : 0;
}

/* CVE-2025-11625 oracle (client side). Returns 1 iff the client has finished its
 * initial key exchange (connectState >= CONNECT_KEYED, i.e. it processed a NEWKEYS
 * and left the `while (ssh->isKeying)` connect loop). The harness combines this
 * with its own record of whether the client's host-key-check callback ever fired
 * (set only inside DoKexDhReply): a client that is KEYED but never verified a host
 * key accepted a NEWKEYS before any KEX_ECDH_REPLY -- the host-authentication
 * bypass the vulnerable client permits (it then sends userauth in the clear, since
 * it never ran SendNewKeys) and the fixed client rejects (NEWKEYS while still
 * self-keying -> WS_INVALID_STATE_E). An honest client reaches CONNECT_KEYED only
 * after DoKexDhReply, where the host-key signature over H is verified and the
 * callback fires, so KEYED-without-host-key cannot occur honestly. Pure
 * observation of ssh->connectState; never alters behaviour. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_client_keyed(WOLFSSH *ssh)
{
    if (ssh == NULL) {
        return 0;
    }
    return (ssh->connectState >= CONNECT_KEYED) ? 1 : 0;
}
")

file(APPEND "${FILE}" "${accessor}")
message(STATUS "PUFFIN wolfssh instrument: appended session-id accessor to ${FILE}")
