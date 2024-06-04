#ifndef PUT_ID
#error "missing preprocessor definition PUT_ID"
#endif

#include <openssl/ssl.h>
#include <stdio.h>
#include <tlspuffin/put.h>

static C_PUT_TYPE OPENSSL_PUT = {
    .create = NULL,
    .destroy = NULL,

    .deterministic_rng_set = NULL,
    .deterministic_rng_reseed = NULL,

    .progress = NULL,
    .reset = NULL,
    .describe_state = NULL,
    .is_state_successful = NULL,
    .shutdown = NULL,

    .add_inbound = NULL,
    .take_outbound = NULL,
};

void REGISTER(void *data, void (*const register_put)(void *, const C_PUT_TYPE *))
{
    register_put(data, &OPENSSL_PUT);
}
