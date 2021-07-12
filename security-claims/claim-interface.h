#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

typedef enum ClaimType {
    CLAIM_CIPHERS
} ClaimType;

static const int CLAIM_MAX_AVAILABLE_CIPHERS = 128;

typedef struct Claim {
    ClaimType typ;

    // length of the key used in RSA certificate
    int cert_rsa_key_length;

    int master_secret_len;
    unsigned char master_secret[64];

    // OpenSSL 1.1.1k supports 60 ciphers on arch linux, add roughly double the space here
    int available_ciphers_len;
    unsigned short available_ciphers[CLAIM_MAX_AVAILABLE_CIPHERS];

    unsigned short chosen_cipher;
} Claim;

/**
 * registers a
 *
 * @param claim function which is called each time a claim is made
 * @param ctx the ctx to pass along
 */
void register_claimer(const void *tls_like, void (* claim)(Claim claim, void* ctx), void* ctx);

/**
 * Sets the internal callbacks to NULL and returns the reference to the claimer
 */
void* deregister_claimer(const void *tls_like);

#endif
