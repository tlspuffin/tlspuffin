#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

typedef enum ClaimType {
    CLAIM_UNKNOWN,

    CLAIM_CLIENT_HELLO,
    CLAIM_CCS,
    CLAIM_END_OF_EARLY_DATA,
    CLAIM_CERTIFICATE,
    CLAIM_KEY_EXCHANGE,
    CLAIM_CERTIFICATE_VERIFY,
    CLAIM_FINISHED,
    CLAIM_KEY_UPDATE,

    //CLAIM_CCS,
    CLAIM_HELLO_REQUEST,
    CLAIM_SERVER_HELLO,
    //CLAIM_CERTIFICATE,
    //CLAIM_CERTIFICATE_VERIFY,
    //CLAIM_KEY_EXCHANGE,
    CLAIM_CERTIFICATE_REQUEST,
    CLAIM_SERVER_DONE,
    CLAIM_SESSION_TICKET,
    CLAIM_CERTIFICATE_STATUS,
    //CLAIM_FINISHED,
    CLAIM_EARLY_DATA,
    CLAIM_ENCRYPTED_EXTENSIONS,
    //CLAIM_KEY_UPDATE,
} ClaimType;

static const int CLAIM_MAX_AVAILABLE_CIPHERS = 128;

typedef struct Claim {
    ClaimType typ;

    // writing or processing messages
    int write;

    // length of the key used in RSA certificate
    int cert_rsa_key_length;
    int cert_key_length;

    int peer_tmp_security_bits;

    int cipher_bits;

    int master_secret_len;
    unsigned char master_secret[64];

    // OpenSSL 1.1.1k supports 60 ciphers on arch linux, add roughly double the space here
    int available_ciphers_len;
    unsigned short available_ciphers[CLAIM_MAX_AVAILABLE_CIPHERS];

    unsigned short chosen_cipher;
} Claim;

typedef void (* claim_t)(Claim claim, void* ctx);

/**
 * registers a
 *
 * @param claim function which is called each time a claim is made
 * @param ctx the ctx to pass along
 */
void register_claimer(const void *tls_like, claim_t claimer, void* ctx);

/**
 * Sets the internal callbacks to NULL and returns the reference to the claimer
 */
void* deregister_claimer(const void *tls_like);

#endif
