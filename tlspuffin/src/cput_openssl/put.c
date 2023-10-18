#include <stdlib.h>
#include <openssl/ssl.h>

#include "put.h"

const char *openssl_version()
{
    return OPENSSL_FULL_VERSION_STR;
}

void *new_ssl()
{
    SSL_library_init();
    return NULL;
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

int openssl_add_inbound(void *put, const uint8_t *bytes, size_t length, size_t *written)
{
    return 0;
}

int openssl_take_outbound(void *put, uint8_t **bytes)
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