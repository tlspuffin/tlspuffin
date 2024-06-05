#include <openssl/ssl.h>
#include <stdio.h>
#include <tlspuffin/put.h>

static C_PUT_INTERFACE OPENSSL_PUT = {
    .create = NULL,
    .destroy = NULL,

    .rng_reseed = NULL,

    .progress = NULL,
    .reset = NULL,
    .describe_state = NULL,
    .is_state_successful = NULL,
    .shutdown = NULL,

    .add_inbound = NULL,
    .take_outbound = NULL,
};

void REGISTER()
{
    REGISTER_PUT(&OPENSSL_PUT, NULL, 0);
}
