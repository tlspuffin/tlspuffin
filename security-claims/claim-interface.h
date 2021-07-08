#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

#include <openssl/ssl.h>

typedef struct Claim {
    int cert_rsa_key_length;
    OSSL_HANDSHAKE_STATE state;
    unsigned char master_secret[64];
} Claim;

Claim current_claim(const void* tls_like);


#endif
