// based on https://stackoverflow.com/a/7510354
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>

void put_rng_init();
void put_rng_reseed(const uint8_t *buffer, size_t length);

#ifndef thread_local
// since C11 the standard include _Thread_local
#if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
#define thread_local _Thread_local

// note that __GNUC__ covers clang and ICC
#elif defined __GNUC__ || defined __SUNPRO_C || defined __xlC__
#define thread_local __thread

#else
#error "no support for thread-local declarations"
#endif
#endif

#ifndef USE_CUSTOM_PRNG // use OpenSSL's default PRNG

void put_rng_init()
{
    // nothing to do: use the default PRNG
}

void put_rng_reseed(const uint8_t *buffer, size_t length)
{
    RAND_seed(buffer, length);
}

#else // use our custom PRNG

#define DEFAULT_RNG_SEED 42

static thread_local uint64_t seed = DEFAULT_RNG_SEED;

#define UNUSED(x) (void)(x)

static int stdlib_rand_seed(const void *buf, int num)
{
    put_rng_reseed(buf, num);
    return 1;
}

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

void put_rng_init()
{
    RAND_set_rand_method(&stdlib_rand_meth);
}

void put_rng_reseed(const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || length < sizeof(uint64_t))
    {
        seed = DEFAULT_RNG_SEED;
        return;
    }

    seed = *((uint64_t *)buffer);
}

#endif // USE_CUSTOM_PRNG
