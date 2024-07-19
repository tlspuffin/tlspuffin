#include <stdint.h>
#include <stdlib.h>

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

#define DEFAULT_RNG_SEED 42

static thread_local uint64_t seed = DEFAULT_RNG_SEED;

void deterministic_rng_set();
void deterministic_rng_reseed(const uint8_t *buffer, size_t length);

static int rand_bytes(uint8_t *buf, size_t num)
{
    for (size_t index = 0; index < num; ++index)
    {
        seed = 6364136223846793005ULL * seed + 1;
        buf[index] = seed >> 33;
    }
    return 1;
}

static uint32_t rand_int()
{
    uint32_t result = 0;
    rand_bytes((uint8_t *)&result, sizeof(uint32_t));

    return result;
}

void deterministic_rng_set()
{
    // nothing to do: PRNG is set at compile time
}

void deterministic_rng_reseed(const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || length < sizeof(uint64_t))
    {
        seed = DEFAULT_RNG_SEED;
        return;
    }

    seed = *((uint64_t *)buffer);
}

uint32_t arc4random(void)
{
    return rand_int();
}

void arc4random_buf(void *buf, size_t n)
{
    rand_bytes(buf, n);
}
