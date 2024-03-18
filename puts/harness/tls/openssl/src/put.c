#ifndef PUT_ID
#error "missing preprocessor definition PUT_ID"
#endif

#include <openssl/ssl.h>
#include <stdio.h>
#include <tlspuffin/put.h>

#define xstr(s) str(s)
#define str(s) #s

static const C_PUT_TYPE OPENSSL_PUT = {
    .harness =
        {
            .name = "openssl",
            .version = "",
        },

    .library =
        {
            .vendor_name = "",
            .vendor_version = "",

            .config_name = "",
            .config_hash = "",
        },

    .create = NULL,
    .destroy = NULL,

    .progress = NULL,
    .reset = NULL,
    .rename = NULL,
    .describe_state = NULL,
    .is_state_successful = NULL,
    .set_deterministic = NULL,
    .shutdown = NULL,

    .add_inbound = NULL,
    .take_outbound = NULL,
};

void REGISTER(void (*const register_put)(const C_PUT_TYPE *))
{
    register_put(&OPENSSL_PUT);
}
