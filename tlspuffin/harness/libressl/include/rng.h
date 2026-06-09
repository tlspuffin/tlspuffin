#ifndef PUFFIN_HARNESS_TLS_OPENSSL_RNG_H
#define PUFFIN_HARNESS_TLS_OPENSSL_RNG_H

#include <stddef.h>
#include <stdint.h>

void rng_init();
void rng_reseed(const uint8_t *buffer, size_t length);

#endif // PUFFIN_HARNESS_TLS_OPENSSL_RNG_H
