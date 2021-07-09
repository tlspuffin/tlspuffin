#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

typedef enum ClaimType {
    CLAIM_CLIENT_CIPHERS
} ClaimType;

typedef struct Claim {
    int cert_rsa_key_length;
    ClaimType typ;
    unsigned char master_secret[64];
    unsigned short available_ciphers[64];
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
