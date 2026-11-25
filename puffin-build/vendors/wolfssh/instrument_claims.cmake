# PUFFIN fuzzing instrumentation for wolfSSH (applied to src/ssh.c).
#
# Exposes two accessors read from the internal WOLFSSH struct, which the harness puts in its
# claims. wolfSSH has no public getter and does not install internal.h, so the decryption recipe
# has no other way to obtain them:
# - puffin_wolfssh_get_session_id(): the SSH session identifier (exchange hash H of the first KEX,
#   RFC 4253 §7.2; ssh->sessionId / sessionIdSz), from which the seeds derive the server-to-client
#   keys;
# - puffin_wolfssh_get_kex_secret(): the exchange hash H and the shared secret K of the key exchange
#   behind the outbound keys (ssh->h / hSz, ssh->k / kSz), from which the differential derives the
#   keys of every epoch of the PUT's output, also after a rekey.
# They mirror the libssh instrument (puffin_ssh_get_session_id, puffin_ssh_get_kex_secret); together
# they let the differential source the key material from each PUT instead of reconstructing it from
# a hard-coded (and therefore mutation-stale) client KEXINIT.
#
# Pure observation -- they never alter protocol behaviour. src/ssh.c already
# includes <wolfssh/internal.h>, so the WOLFSSH struct is fully in scope; the
# accessors are appended at end of file, so there is no anchor to drift across
# wolfSSH versions.
#
# For why SSH claim instrumentation is a bespoke cmake-script patch rather than
# the TLS `patch()` + `tlspuffin-claims` (`register_claimer`) mechanism, see the
# rationale in vendors/libssh/instrument_claims.cmake.

file(READ "${FILE}" content)

set(session_id_accessor "
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
")

set(kex_secret_accessor "
/* ===== PUFFIN fuzzing instrumentation: the secrets of a key exchange, for the claims ===== */
/* The exchange hash H and the shared secret K of the key exchange behind the outbound keys. wolfSSH
 * writes them into ssh->h and ssh->k while the key exchange runs, before its own NEWKEYS, so they
 * are only given once SendNewKeys has cleared WOLFSSH_SELF_IS_KEYING: then the outbound keys are
 * derived from them. Each rekey overwrites them (its H is not the session id), so the harness reads
 * them again each time the outbound keys may have switched, and keeps every epoch's. -1 before the
 * first key exchange (hSz is 0; kSz starts as the buffer's size in wolfSSH 1.5.0) and during one. */
__attribute__((visibility(\"default\")))
int puffin_wolfssh_get_kex_secret(WOLFSSH *ssh, const unsigned char **h, unsigned int *h_len,
                                  const unsigned char **k, unsigned int *k_len)
{
    if (ssh == NULL || (ssh->isKeying & WOLFSSH_SELF_IS_KEYING) || ssh->hSz == 0 ||
        ssh->kSz == 0) {
        return -1;
    }
    *h = ssh->h;
    *h_len = ssh->hSz;
    *k = ssh->k;
    *k_len = ssh->kSz;
    return 0;
}
")

# Idempotent: PATCH_COMMANDS may re-run against already-patched source, and a source patched by an
# earlier version of this script has the session-id accessor only.
set(added "")
if(NOT content MATCHES "puffin_wolfssh_get_session_id")
  file(APPEND "${FILE}" "${session_id_accessor}")
  string(APPEND added " session-id")
endif()
if(NOT content MATCHES "puffin_wolfssh_get_kex_secret")
  file(APPEND "${FILE}" "${kex_secret_accessor}")
  string(APPEND added " kex-secret")
endif()
if(added STREQUAL "")
  message(STATUS "PUFFIN wolfssh instrument: already applied to ${FILE}; skipping")
else()
  message(STATUS "PUFFIN wolfssh instrument: appended the${added} accessor(s) to ${FILE}")
endif()
