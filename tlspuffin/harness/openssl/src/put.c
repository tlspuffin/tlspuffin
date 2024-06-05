#include <openssl/ssl.h>
#include <puffin/tls.h>
#include <stdio.h>

#define xstr(s) str(s)
#define str(s) #s

struct AGENT
{
    // TODO
};

static const TLS_PUT_INTERFACE OPENSSL_PUT = {
    .create = NULL,
    .rng_reseed = NULL,
    .supports = NULL,

    .agent_interface =
        {
            .destroy = NULL,
            .progress = NULL,
            .reset = NULL,
            .describe_state = NULL,
            .is_state_successful = NULL,

            .add_inbound = NULL,
            .take_outbound = NULL,
        },
};

const TLS_PUT_INTERFACE *REGISTER()
{
    return &OPENSSL_PUT;
}
