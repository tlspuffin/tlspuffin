/*
 * sshpuffin/harness/libssh/src/rng.c
 *
 * Deterministic PRNG for the libssh PUT.
 *
 * libssh is built against OpenSSL (HAVE_LIBCRYPTO), so all of its randomness
 * — X25519 ephemeral keys, the KEXINIT cookie, packet padding — flows through
 * OpenSSL's RAND interface. By installing a custom RAND_METHOD seeded from a
 * fixed value we make a full SSH handshake byte-for-byte reproducible, which is
 * a prerequisite for differential fuzzing (otherwise two runs of the *same*
 * PUT already diverge on every random field).
 *
 * Mirrors tlspuffin/harness/openssl/src/rng.c.
 */

#include "rng.h"

#include <openssl/rand.h>

#define DEFAULT_RNG_SEED 42ULL

static uint64_t seed = DEFAULT_RNG_SEED;

/* SplitMix64-ish LCG: deterministic, fast, good enough for fuzzing. */
static int rng_rand_bytes(unsigned char *buf, int num)
{
    for (int i = 0; i < num; ++i)
    {
        seed = 6364136223846793005ULL * seed + 1442695040888963407ULL;
        buf[i] = (unsigned char)(seed >> 33);
    }
    return 1;
}

static int rng_rand_seed_cb(const void *buf, int num)
{
    rng_reseed((const uint8_t *)buf, (size_t)num);
    return 1;
}

static int rng_rand_add_cb(const void *buf, int num, double add_entropy)
{
    (void)buf;
    (void)num;
    (void)add_entropy;
    return 1;
}

static int rng_rand_status_cb(void)
{
    return 1;
}

static void rng_rand_cleanup_cb(void)
{
}

static RAND_METHOD custom_rand_meth = {
    rng_rand_seed_cb,
    rng_rand_bytes,
    rng_rand_cleanup_cb,
    rng_rand_add_cb,
    rng_rand_bytes, /* pseudorand */
    rng_rand_status_cb,
};

void rng_init(void)
{
    RAND_set_rand_method(&custom_rand_meth);
}

void rng_reseed(const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || length < sizeof(uint64_t))
    {
        seed = DEFAULT_RNG_SEED;
        return;
    }
    seed = *((const uint64_t *)buffer);
}
