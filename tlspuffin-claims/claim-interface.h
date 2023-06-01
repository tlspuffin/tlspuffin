#ifndef TLSPUFFIN_CLAIM_INTERFACE_H
#define TLSPUFFIN_CLAIM_INTERFACE_H

#define CLAIM_MAX_AVAILABLE_CIPHERS 256
#define CLAIM_MAX_SECRET_SIZE 64 /* longest known is SHA512 */
#define CLAIM_SESSION_ID_LENGTH 32

typedef enum ClaimTLSVersion {
    CLAIM_TLS_VERSION_UNDEFINED = 0,
    CLAIM_TLS_VERSION_V1_2 = 1,
    CLAIM_TLS_VERSION_V1_3 = 2,
} TLSVersion;

typedef enum ClaimType {
    CLAIM_NOT_SET = -1,
    CLAIM_UNKNOWN,

    // Transcript types
    CLAIM_TRANSCRIPT_UNKNOWN,
    CLAIM_TRANSCRIPT_CH,
    CLAIM_TRANSCRIPT_PARTIAL_CH,
    CLAIM_TRANSCRIPT_CH_SH,
    CLAIM_TRANSCRIPT_CH_SERVER_FIN,
    CLAIM_TRANSCRIPT_CH_CERT,
    CLAIM_TRANSCRIPT_CH_CLIENT_FIN,

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
    CLAIM_KEY_TYPE_NOT_SET,
    CLAIM_KEY_TYPE_UNKNOWN,
    CLAIM_KEY_TYPE_DSA,
    CLAIM_KEY_TYPE_RSA,
    CLAIM_KEY_TYPE_DH,
    CLAIM_KEY_TYPE_EC,
    CLAIM_KEY_TYPE_POLY1305,
    CLAIM_KEY_TYPE_SIPHASH,
    CLAIM_KEY_TYPE_X25519,
    CLAIM_KEY_TYPE_ED25519,
    CLAIM_KEY_TYPE_X448,
    CLAIM_KEY_TYPE_ED448,
} ClaimKeyType;

typedef struct ClaimSecret {
    unsigned char secret[CLAIM_MAX_SECRET_SIZE];
} ClaimSecret;

typedef struct ClaimCertData {
    ClaimKeyType key_type;
    int key_length;
} ClaimCertData;

typedef struct ClaimCipher {
    unsigned short data;
} ClaimCipher;

typedef struct ClaimCiphers {
    // OpenSSL 1.1.1k supports 60 ciphers on arch linux, add roughly double the space here
    int length;
    ClaimCipher ciphers[CLAIM_MAX_AVAILABLE_CIPHERS];
} ClaimCiphers;

typedef struct ClaimVersion {
    TLSVersion data;
} ClaimVersion;

typedef struct ClaimRandom {
    unsigned char data[CLAIM_SESSION_ID_LENGTH];
} ClaimRandom;

typedef struct ClaimSessionId {
    int length;
    unsigned char data[CLAIM_SESSION_ID_LENGTH];
} ClaimSessionId;

typedef struct ClaimTranscript {
    int length;
    unsigned char data[CLAIM_MAX_SECRET_SIZE]; // it contains a hash -> use CLAIM_MAX_SECRET_SIZE
} ClaimTranscript;

typedef struct Claim {
    ClaimType typ;

    // writing or processing messages
    int write;

    ClaimVersion version;

    int server;

    // Session ID
    ClaimSessionId session_id;

    // Randoms
    ClaimRandom server_random;
    ClaimRandom client_random;

    // Cert info
    ClaimCertData cert;
    ClaimCertData peer_cert;

    // Peer ephemeral key
    ClaimKeyType peer_tmp_skey_type;
    int peer_tmp_skey_security_bits;

    // Ephemeral key
    ClaimKeyType tmp_skey_type;
    int tmp_skey_group_id;

    int signature_algorithm;
    int peer_signature_algorithm;

    // The TLS1.3 secrets.
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

    // TLS 1.2
    ClaimSecret master_secret_12;

    // Ciphers
    ClaimCiphers available_ciphers;
    ClaimCipher chosen_cipher;

    // Transcript
    ClaimTranscript transcript;
} Claim;

typedef void (*claim_t)(Claim claim, void *ctx);

/**
 * registers a
 *
 * @param claim function which is called each time a claim is made
 * @param ctx the ctx to pass along
 */
void register_claimer(const void *tls_like, claim_t claimer, void *ctx);

/**
 * Sets the internal callbacks to NULL and returns the reference to the claimer
 */
void *deregister_claimer(const void *tls_like);

#endif // TLSPUFFIN_CLAIM_INTERFACE_H
