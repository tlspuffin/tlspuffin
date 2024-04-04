// based on https://stackoverflow.com/a/7510354
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>

#define DEFAULT_RNG_SEED 42
static uint64_t seed = DEFAULT_RNG_SEED;

#define UNUSED(x) (void)(x)

void deterministic_rng_set();
void deterministic_rng_reseed(const uint8_t *buffer, size_t length);

// Seed the RNG. srand() takes an unsigned int, so we just use the first
// sizeof(uint64_t) bytes in the buffer to seed the RNG.
static int stdlib_rand_seed(const void *buf, int num)
{
    deterministic_rng_reseed(buf, num);
    return 1;
}

// Fill the buffer with random bytes.  For each byte in the buffer, we generate
// a random number and clamp it to the range of a byte, 0-255.
static int stdlib_rand_bytes(unsigned char *buf, int num)
{
    for (int index = 0; index < num; ++index)
    {
        seed = 6364136223846793005ULL * seed + 1;
        buf[index] = seed >> 33;
    }
    return 1;
}

static void stdlib_rand_cleanup()
{
}

static int stdlib_rand_add(const void *buf, int num, double add_entropy)
{
    UNUSED(buf);
    UNUSED(num);
    UNUSED(add_entropy);
    return 1;
}

static int stdlib_rand_status()
{
    return 1;
}

RAND_METHOD stdlib_rand_meth = {
    stdlib_rand_seed,
    stdlib_rand_bytes,
    stdlib_rand_cleanup,
    stdlib_rand_add,
    stdlib_rand_bytes,
    stdlib_rand_status,
};

void deterministic_rng_set() {
    RAND_set_rand_method(&stdlib_rand_meth);
}

void deterministic_rng_reseed(const uint8_t *buffer, size_t length) {
    if (buffer == NULL || length < sizeof(uint64_t)) {
        seed = DEFAULT_RNG_SEED;
    }

    seed = *((uint64_t *)buffer);
}
