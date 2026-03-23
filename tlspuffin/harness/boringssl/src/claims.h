#ifndef BORINGSSL_CLAIMS_H
#define BORINGSSL_CLAIMS_H

#include <openssl/ssl.h>
#include <claim-interface.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Functions implemented in claims.cc (C++), called from put.c (C)
// ---------------------------------------------------------------------------

/** Populate a Claim struct from the current SSL state.
 *  agent_opaque is the AGENT pointer (struct AGENT_TYPE *). */
void boringssl_fill_claim(void *agent_opaque, Claim *claim);

/** Extract transcript hash safely (returns 0 if not initialised). */
int boringssl_extract_transcript_safe(const SSL *ssl, uint8_t *out, size_t out_max);

/** Associate an AGENT pointer with an SSL object via ex_data. */
void boringssl_set_agent_for_ssl(SSL *ssl, void *agent);

/** Store CH+SH transcript and handshake secret on the agent.
 *  Called from PUFFIN_store_ch_sh_transcript (BoringSSL patch). */
void boringssl_store_ch_sh_data(void *agent_opaque,
                                 const uint8_t *hash,
                                 size_t hash_len,
                                 void *hs_opaque);

// ---------------------------------------------------------------------------
// Functions implemented in put.c (C), called from claims.cc (C++)
//
// These provide access to AGENT_TYPE fields without exposing the struct
// definition to C++ code.
// ---------------------------------------------------------------------------

/** Get the SSL* from an agent. */
SSL *boringssl_agent_get_ssl(void *agent_opaque);

/** Store CH+SH transcript hash on the agent. */
void boringssl_agent_set_ch_sh_transcript(void *agent_opaque,
                                           const uint8_t *hash,
                                           size_t hash_len);

/** Store handshake secret on the agent. */
void boringssl_agent_set_handshake_secret(void *agent_opaque,
                                           const uint8_t *data,
                                           size_t len);

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

#ifdef __cplusplus
}
#endif

#endif // BORINGSSL_CLAIMS_H
