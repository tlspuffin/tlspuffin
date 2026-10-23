/*
 * tlspuffin claim registration and extraction, appended to ssl/ssl_lib.c at patch time.
 */
#include "claim-interface.h"

void register_claimer(const void *tls_like, void (*claim)(Claim claim, void *ctx), void *claim_ctx)
{
    SSL *ssl = ((SSL *)tls_like);

    ssl->claim = claim;
    ssl->claim_ctx = claim_ctx;
}

void *deregister_claimer(const void *tls_like)
{
    SSL *ssl = ((SSL *)tls_like);

    void *ret = ssl->claim_ctx;

    ssl->claim = 0;
    ssl->claim_ctx = 0;
    return ret;
}

void fill_claim(SSL *s, Claim *claim)
{
    switch (s->version)
    {
    case TLS1_2_VERSION:
        claim->version.data = CLAIM_TLS_VERSION_V1_2;
    case TLS1_3_VERSION:
        claim->version.data = CLAIM_TLS_VERSION_V1_3;
    default:
        claim->version.data = CLAIM_TLS_VERSION_UNDEFINED;
    }

    claim->server = s->server;

    // session ids
    // todo

    // randoms
    memcpy(claim->client_random.data, s->s3->client_random, 32);
    memcpy(claim->server_random.data, s->s3->server_random, 32);

    // ciphers
    ClaimCiphers claim_ciphers = {0};
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(s);
    int available_ciphers_len = sk_SSL_CIPHER_num(ciphers);
    claim_ciphers.length = available_ciphers_len;
    for (int j = 0; j < available_ciphers_len; ++j)
    {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, j);
        if (j < CLAIM_MAX_AVAILABLE_CIPHERS)
        {
            claim_ciphers.ciphers[j].data = c->id & 0xffff;
        }
    }
    claim->available_ciphers = claim_ciphers;

    // cert
    const X509 *cert = SSL_get_certificate(s);
    if (cert != NULL)
    {
        // todo
    }

    // peer cert
    // todo

    // todo early_secret, handshake_secret etc.

    // 1.2 secret
    if (s->session != 0 && s->version == TLS1_2_VERSION)
    {
        memcpy(claim->master_secret_12.secret,
               s->session->master_key,
               s->session->master_key_length);
    }

    // chosen cipher
    // todo

    // signature algorithm
    // todo

    // peer signature algorithm
    // todo

    // temporary/ephemeral peer key
    // todo

    // temporary/ephemeral peer key
    // todo

    // TLS 1.3: Group ID of s->s3->tmp.pkey
    // todo
}
