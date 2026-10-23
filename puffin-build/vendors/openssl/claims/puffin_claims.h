/*
 * tlspuffin claim instrumentation: declarations and hooks shared by all OpenSSL versions.
 *
 * This header is copied into ssl/ by the vendor builder and included from ssl_local.h (see
 * apply_hooks.cmake), so everything here must only depend on the public OpenSSL headers.
 */
#ifndef PUFFIN_CLAIMS_H
#define PUFFIN_CLAIMS_H

#include <string.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include "claim-interface.h"

void fill_claim(SSL *s, Claim *claim);

/* Fields added to the connection structure (struct ssl_st before 3.2, struct ssl_connection_st
 * after). */
#define PUFFIN_CLAIM_FIELDS                                                                        \
    void (*claim)(Claim claim, void *ctx);                                                         \
    void *claim_ctx;

/* The public SSL object that owns the connection `s`. */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#define PUFFIN_SSL_OF(s) SSL_CONNECTION_GET_SSL(s)
#else
#define PUFFIN_SSL_OF(s) (s)
#endif

/*
 * TLS 1.3 key schedule: claim the transcript used to derive a secret, classified by the HKDF label.
 */
static inline size_t puffin_min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

static inline int
puffin_label_matches(const unsigned char *label, size_t labellen, const char *expected)
{
    return memcmp(label, expected, puffin_min_size(strlen(expected), labellen)) == 0;
}

static inline ClaimType puffin_hkdf_claim_type(const unsigned char *label, size_t labellen)
{
    if (puffin_label_matches(label, labellen, "ext binder") ||
        puffin_label_matches(label, labellen, "res binder") ||
        puffin_label_matches(label, labellen, "c e traffic") ||
        puffin_label_matches(label, labellen, "e exp master"))
        return CLAIM_TRANSCRIPT_CH_SH;

    if (puffin_label_matches(label, labellen, "c hs traffic") ||
        puffin_label_matches(label, labellen, "s hs traffic"))
        return CLAIM_TRANSCRIPT_CH_SH;

    if (puffin_label_matches(label, labellen, "c ap traffic") ||
        puffin_label_matches(label, labellen, "s ap traffic") ||
        puffin_label_matches(label, labellen, "exp master"))
        return CLAIM_TRANSCRIPT_CH_SERVER_FIN;

    if (puffin_label_matches(label, labellen, "res master"))
        return CLAIM_TRANSCRIPT_CH_CLIENT_FIN;

    return CLAIM_TRANSCRIPT_UNKNOWN;
}

#define PUFFIN_TLS13_HKDF_CLAIM(s, label, labellen, data, datalen)                                 \
    do                                                                                             \
    {                                                                                              \
        if ((data) != NULL)                                                                        \
        {                                                                                          \
            Claim claim = {-1};                                                                    \
            claim.typ = puffin_hkdf_claim_type((label), (labellen));                               \
            memcpy(claim.transcript.data, (data), (datalen));                                      \
            claim.transcript.length = (datalen);                                                   \
            (s)->claim(claim, (s)->claim_ctx);                                                     \
        }                                                                                          \
    } while (0)

/* Server side: claim the transcript hash up to the client Certificate message. */
#define PUFFIN_CLAIM_CERT_TRANSCRIPT(s)                                                            \
    do                                                                                             \
    {                                                                                              \
        Claim claim = {-1};                                                                        \
        claim.typ = CLAIM_TRANSCRIPT_CH_CERT;                                                      \
        memcpy(claim.transcript.data, (s)->cert_verify_hash, (s)->cert_verify_hash_len);           \
        claim.transcript.length = (s)->cert_verify_hash_len;                                       \
        (s)->claim(claim, (s)->claim_ctx);                                                         \
    } while (0)

ClaimType puffin_read_claim_type(int hand_state);
ClaimType puffin_write_claim_type(int hand_state);

/* Claim emitted after a message has been processed (read side). */
#define PUFFIN_CLAIM_READ(s, st, ret)                                                              \
    do                                                                                             \
    {                                                                                              \
        if ((ret) != MSG_PROCESS_ERROR)                                                            \
        {                                                                                          \
            Claim claim = {-1};                                                                    \
            claim.write = 0;                                                                       \
            claim.typ = puffin_read_claim_type((st)->hand_state);                                  \
            fill_claim(PUFFIN_SSL_OF(s), &claim);                                                  \
            (s)->claim(claim, (s)->claim_ctx);                                                     \
        }                                                                                          \
    } while (0)

/* Claim emitted after a message has been constructed (write side). */
#define PUFFIN_CLAIM_WRITE(s, st)                                                                  \
    do                                                                                             \
    {                                                                                              \
        Claim claim = {-1};                                                                        \
        claim.write = 1;                                                                           \
        claim.typ = puffin_write_claim_type((st)->hand_state);                                     \
        fill_claim(PUFFIN_SSL_OF(s), &claim);                                                      \
        (s)->claim(claim, (s)->claim_ctx);                                                         \
    } while (0)

#endif /* PUFFIN_CLAIMS_H */
