#include "rng.h"
#include <openssl/rand.h>

void rng_init()
{
    // BoringSSL with -DFUZZ is already deterministic.
}

void rng_reseed(const uint8_t *buffer, size_t length)
{
    (void)buffer; // Avoid unused parameter warning.
    (void)length;

    // Our patched BoringSSL has RAND_reset_for_fuzzing
    RAND_reset_for_fuzzing();
}
