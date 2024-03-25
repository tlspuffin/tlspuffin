// based on https://stackoverflow.com/a/7510354
#include <openssl/rand.h>
#include <stdlib.h>

unsigned int tlspuffin_seed = 42;
const unsigned int m = 0xFFFFFFFF;
const unsigned int a = 22695477;
const unsigned int c = 1;

#define UNUSED(x) (void)(x)

// Seed the RNG. srand() takes an unsigned int, so we just use the first
// sizeof(unsigned int) bytes in the buffer to seed the RNG.
static int stdlib_rand_seed(const void *buf, int num)
{
    if (num < 1)
    {
        return 0;
    }
    tlspuffin_seed = *((unsigned int *) buf);
    return 1;
}

// Fill the buffer with random bytes.  For each byte in the buffer, we generate
// a random number and clamp it to the range of a byte, 0-255.
static int stdlib_rand_bytes(unsigned char *buf, int num)
{
    for (int index = 0; index < num; ++index)
    {
        tlspuffin_seed = 6364136223846793005ULL*tlspuffin_seed + 1;
        buf[index] = tlspuffin_seed>>33;
    }
    return 1;
}

static void stdlib_rand_cleanup() {}
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

RAND_METHOD stdlib_rand_meth = { stdlib_rand_seed,
                                 stdlib_rand_bytes,
                                 stdlib_rand_cleanup,
                                 stdlib_rand_add,
                                 stdlib_rand_bytes,
                                 stdlib_rand_status
};

void make_openssl_deterministic()
{
    RAND_set_rand_method(&stdlib_rand_meth);
}
