#ifndef SSHPUFFIN_RNG_H
#define SSHPUFFIN_RNG_H

#include <stddef.h>
#include <stdint.h>

/* Install a deterministic OpenSSL RAND_METHOD. Must be called once at
 * registration so that libssh's ephemeral keys, cookies, and padding become
 * reproducible. */
void rng_init(void);

/* Reset the deterministic RNG. A NULL or too-short buffer resets to the
 * default seed; otherwise the first 8 bytes are used as the seed. */
void rng_reseed(const uint8_t *buffer, size_t length);

#endif /* SSHPUFFIN_RNG_H */
