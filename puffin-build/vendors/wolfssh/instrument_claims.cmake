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
")

file(APPEND "${FILE}" "${accessor}")
message(STATUS "PUFFIN wolfssh instrument: appended session-id accessor to ${FILE}")
