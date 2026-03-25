#ifndef BORINGSSL_CLAIMS_H
#define BORINGSSL_CLAIMS_H

#include <claim-interface.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // ---------------------------------------------------------------------------
    // Snapped TLS 1.3 secrets — captured in msg_callback while hs is alive.
    // BoringSSL frees hs when the handshake completes, so these must be
    // snapshotted before progress() flushes the deferred claim queue.
    // ---------------------------------------------------------------------------

    typedef struct
    {
        uint8_t master_secret[CLAIM_MAX_SECRET_SIZE];
        size_t master_secret_len;
        uint8_t client_app_traffic[CLAIM_MAX_SECRET_SIZE];
        size_t client_app_traffic_len;
        uint8_t server_app_traffic[CLAIM_MAX_SECRET_SIZE];
        size_t server_app_traffic_len;
        uint8_t exporter_secret[CLAIM_MAX_SECRET_SIZE];
        size_t exporter_secret_len;
        uint8_t early_traffic[CLAIM_MAX_SECRET_SIZE];
        size_t early_traffic_len;
    } SnappedTLS13Secrets;

    // ---------------------------------------------------------------------------
    // Functions implemented in claims.cc (C++), called from put.c (C)
    // ---------------------------------------------------------------------------

    /** Populate a Claim struct from the current SSL state.
     *  agent_opaque is the AGENT pointer (struct AGENT_TYPE *). */
    void boringssl_fill_claim(void *agent_opaque, Claim *claim);

    /** Extract transcript hash safely (returns 0 if not initialised). */
    int boringssl_extract_transcript_safe(const SSL *ssl, uint8_t *out, size_t out_max);

    /** Extract transcript hash including an additional message.
     *  BoringSSL fires msg_callback BEFORE updating the transcript, so
     *  the live transcript at callback time is missing the current message. */
    int boringssl_extract_transcript_with_msg(const SSL *ssl,
                                              const uint8_t *msg,
                                              size_t msg_len,
                                              uint8_t *out,
                                              size_t out_max);

    /** Associate an AGENT pointer with an SSL object via ex_data. */
    void boringssl_set_agent_for_ssl(SSL *ssl, void *agent);

    /** Store CH+SH transcript and handshake secret on the agent.
     *  Called from PUFFIN_store_ch_sh_transcript (BoringSSL patch). */
    void boringssl_store_ch_sh_data(void *agent_opaque,
                                    const uint8_t *hash,
                                    size_t hash_len,
                                    void *hs_opaque);

    /** Snapshot TLS 1.3 secrets from hs while it's still alive.
     *  Call from msg_callback when a Finished message is seen. */
    void boringssl_snapshot_secrets(void *agent_opaque);

    /** Extract CH+SH transcript and handshake secret using BoringSSL patch
     *  getter API.  Call after BoringSSL has processed ServerHello. */
    void boringssl_extract_ch_sh_and_secrets(void *agent_opaque);

    // ---------------------------------------------------------------------------
    // Functions implemented in put.c (C), called from claims.cc (C++)
    //
    // These provide access to AGENT_TYPE fields without exposing the struct
    // definition to C++ code.
    // ---------------------------------------------------------------------------

    /** Get the SSL* from an agent. */
    SSL *boringssl_agent_get_ssl(void *agent_opaque);

    /** Store CH+SH transcript hash on the agent. */
    void
    boringssl_agent_set_ch_sh_transcript(void *agent_opaque, const uint8_t *hash, size_t hash_len);

    /** Store handshake secret on the agent. */
    void boringssl_agent_set_handshake_secret(void *agent_opaque, const uint8_t *data, size_t len);

    /** Get stored handshake secret from agent (NULL if not stored). */
    void boringssl_agent_get_stored_handshake_secret(void *agent_opaque,
                                                     const uint8_t **out,
                                                     size_t *out_len);

    /** Get cached client random from agent (NULL if not cached). */
    void boringssl_agent_get_cached_client_random(void *agent_opaque,
                                                  const uint8_t **out,
                                                  size_t *out_len);

    /** Get cached server random from agent (NULL if not cached). */
    void boringssl_agent_get_cached_server_random(void *agent_opaque,
                                                  const uint8_t **out,
                                                  size_t *out_len);

    /** Retroactively fix up queued CLAIM_TRANSCRIPT_CH_SH entries that have
     *  zero transcript (client side: msg_callback fires before patch). */
    void boringssl_agent_fixup_ch_sh_transcript(void *agent_opaque,
                                                const uint8_t *hash,
                                                size_t hash_len);

    /** Store snapped TLS 1.3 secrets on the agent. */
    void boringssl_agent_store_snapped_secrets(void *agent_opaque,
                                               const SnappedTLS13Secrets *secrets);

    /** Get snapped TLS 1.3 secrets from agent. Returns false if not snapped. */
    bool boringssl_agent_get_snapped_secrets(void *agent_opaque, SnappedTLS13Secrets *out);

#ifdef __cplusplus
}
#endif

#endif // BORINGSSL_CLAIMS_H
