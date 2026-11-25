# PUFFIN fuzzing instrumentation for libssh (applied to src/packet.c).
#
# Adds two accessors the public API does not offer, which the harness puts in its claims:
# - puffin_ssh_get_session_id(): the SSH session identifier (exchange hash H of the first KEX,
#   RFC 4253 §7.2), from which the seeds derive the keys that decrypt the replies of the PUT;
# - puffin_ssh_get_kex_secret(): the exchange hash H and the shared secret K of the key exchange
#   behind the outbound keys, from which the differential derives the keys of every epoch of the
#   PUT's output, also after a rekey.
# Pure observation -- they never alter protocol behaviour.
#
# They are appended to packet.c, whose includes give the session and crypto structs (and
# ssh_packet_get_current_crypto), so they need no anchor in the source. libssh 0.8.3 has no
# session_id_len and no direction bookkeeping (see below).
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

set(session_id_accessor "
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
")

set(kex_secret_accessor "
/* ===== PUFFIN fuzzing instrumentation: the secrets of a key exchange, for the claims ===== */
/* The exchange hash H and the shared secret K (unsigned big-endian, copied into <k>) of the key
 * exchange behind the outbound keys: the one in force, or the pending one as soon as this side
 * has sent its NEWKEYS (ssh_packet_set_newkeys marks it used for the outbound direction). -1 when
 * there is none, and for a K the key derivation does not encode as an mpint: the hybrids of
 * libssh 0.12, ML-KEM (kept in hybrid_shared_secret) and sntrup761x25519 (kept in shared_secret,
 * but derived from as a fixed-length string, ssh_make_padded_bignum_string). libssh 0.8.x keeps
 * no direction bookkeeping, and has no AES-GCM, the only cipher the differential decrypts:
 * nothing to give there. */
int puffin_ssh_get_kex_secret(ssh_session session, const unsigned char **h, size_t *h_len,
                              unsigned char *k, size_t k_cap, size_t *k_len);
__attribute__((visibility(\"default\")))
int puffin_ssh_get_kex_secret(ssh_session session, const unsigned char **h, size_t *h_len,
                              unsigned char *k, size_t k_cap, size_t *k_len)
{
#if LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 9, 0)
    (void)session;
    (void)h;
    (void)h_len;
    (void)k;
    (void)k_cap;
    (void)k_len;
    return -1;
#else
    struct ssh_crypto_struct *crypto = NULL;
    size_t n;

    if (session == NULL) {
        return -1;
    }
    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_OUT);
    if (crypto == NULL || crypto->secret_hash == NULL || crypto->digest_len == 0 ||
        crypto->shared_secret == NULL) {
        return -1;
    }
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 12, 0)
    if (crypto->hybrid_shared_secret != NULL ||
        crypto->kex_type == SSH_KEX_SNTRUP761X25519_SHA512 ||
        crypto->kex_type == SSH_KEX_SNTRUP761X25519_SHA512_OPENSSH_COM) {
        return -1;
    }
#endif
    n = bignum_num_bytes(crypto->shared_secret);
    if (n == 0 || n > k_cap) {
        return -1;
    }
    bignum_bn2bin(crypto->shared_secret, n, k);
    *h = crypto->secret_hash;
    *h_len = crypto->digest_len;
    *k_len = n;
    return 0;
#endif
}
")

# Idempotent: PATCH_COMMANDS may re-run against already-patched source, and a source patched by an
# earlier version of this script has the session-id accessor only.
set(added "")
if(NOT content MATCHES "puffin_ssh_get_session_id")
  file(APPEND "${FILE}" "${session_id_accessor}")
  string(APPEND added " session-id")
endif()
if(NOT content MATCHES "puffin_ssh_get_kex_secret")
  file(APPEND "${FILE}" "${kex_secret_accessor}")
  string(APPEND added " kex-secret")
endif()
if(added STREQUAL "")
  message(STATUS "PUFFIN libssh instrument: already applied to ${FILE}; skipping")
else()
  message(STATUS "PUFFIN libssh instrument: added the${added} accessor(s) to ${FILE}")
endif()
