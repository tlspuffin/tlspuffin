#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

static const int CLAIM_MAX_AVAILABLE_CIPHERS = 128;
static const int MAX_SECRET_SIZE = 64; /* longest known is SHA512 */

typedef enum ClaimType {
    CLAIM_UNKNOWN,

    // client types
    CLAIM_CLIENT_HELLO,
    CLAIM_CCS,
    CLAIM_END_OF_EARLY_DATA,
    CLAIM_CERTIFICATE,
    CLAIM_KEY_EXCHANGE,
    CLAIM_CERTIFICATE_VERIFY,
    CLAIM_FINISHED,
    CLAIM_KEY_UPDATE,

    // Additional Server types
    CLAIM_HELLO_REQUEST,
    CLAIM_SERVER_HELLO,
    CLAIM_CERTIFICATE_REQUEST,
    CLAIM_SERVER_DONE,
    CLAIM_SESSION_TICKET,
    CLAIM_CERTIFICATE_STATUS,
    CLAIM_EARLY_DATA,
    CLAIM_ENCRYPTED_EXTENSIONS,
} ClaimType;

typedef enum ClaimKeyType {
    CLAIM_KEY_TYPE_UNKNOWN,
    CLAIM_KEY_TYPE_DSA,
    CLAIM_KEY_TYPE_RSA,
    CLAIM_KEY_TYPE_DH,
    CLAIM_KEY_TYPE_EC,
} ClaimKeyType;

typedef struct ClaimSecret {
    unsigned char secret[MAX_SECRET_SIZE];
} ClaimSecret;

typedef struct ClaimCertData {
    ClaimKeyType key_type;
    int key_length;
} ClaimCertData;

typedef struct ClaimCiphers {
    // OpenSSL 1.1.1k supports 60 ciphers on arch linux, add roughly double the space here
    int len;
    unsigned short ciphers[CLAIM_MAX_AVAILABLE_CIPHERS];
} ClaimCiphers;

typedef struct Claim {
    ClaimType typ;

    // writing or processing messages
    int write;

    ClaimCertData cert;
    ClaimCertData peer_cert;

    ClaimKeyType peer_tmp_type;
    int peer_tmp_security_bits;

    /*
    * The TLS1.3 secrets.
    */
    ClaimSecret early_secret;
    ClaimSecret handshake_secret;
    ClaimSecret master_secret;
    ClaimSecret resumption_master_secret;
    ClaimSecret client_finished_secret;
    ClaimSecret server_finished_secret;
    ClaimSecret server_finished_hash;
    ClaimSecret handshake_traffic_hash;
    ClaimSecret client_app_traffic_secret;
    ClaimSecret server_app_traffic_secret;
    ClaimSecret exporter_master_secret;
    ClaimSecret early_exporter_master_secret;

    ClaimCiphers available_ciphers;
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
