#include <stdlib.h>

#include "put.h"

const char *openssl_version()
{
    return "0.0.1-dummy-cputopenssl";
}

typedef struct SSL
{
    int dummy_field;
} SSL;

void *new_ssl()
{
    SSL *result = (SSL *)malloc(8 * sizeof(SSL));
    result->dummy_field = 42;

    return result;
}

void openssl_progress(void *put, uint8_t agent_name)
{
}

void openssl_reset(void *put, uint8_t agent_name)
{
}

void openssl_rename(void *put, uint8_t agent_name)
{
}

const char *openssl_describe_state(void *put)
{
    return "";
}

bool openssl_is_successful(void *put)
{
    return false;
}

void openssl_set_deterministic(void *put)
{
}

const char *openssl_shutdown(void *put)
{
    return "";
}

int openssl_add_inbound(void *put, const uint8_t *bytes, size_t length)
{
    return 0;
}

int openssl_take_outbound(void *put, uint8_t **bytes, size_t *length)
{
    return 0;
}

const C_PUT_TYPE CPUT = {
    .new = new_ssl,
    .version = openssl_version,

    .progress = openssl_progress,
    .reset = openssl_reset,
    .rename_agent = openssl_rename,
    .describe_state = openssl_describe_state,
    .is_state_successful = openssl_is_successful,
    .set_deterministic = openssl_set_deterministic,
    .shutdown = openssl_shutdown,

    .add_inbound = openssl_add_inbound,
    .take_outbound = openssl_take_outbound,
};