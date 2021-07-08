#ifndef TLSPUFFIN_DETECTOR_H
#define TLSPUFFIN_DETECTOR_H

typedef struct Claim {
    int used_rsa_key_length;
} Claim;

Claim current_claim(const void* tls_like);

#endif
