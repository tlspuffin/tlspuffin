#ifndef PUT_ID
#error "missing preprocessor definition PUT_ID"
#endif

#include <stdio.h>
#include <tlspuffin/put.h>

#define xstr(s) str(s)
#define str(s) #s

static const C_PUT_TYPE OPENSSL_PUT = {
    .create = NULL,
    .destroy = NULL,
    .version = NULL,

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

#define AT_INIT PUT_ID

void AT_INIT() {
    printf("init for PUT tls/openssl/%s\n", xstr(PUT_ID));
    TLSPUFFIN.register_put(&OPENSSL_PUT);
}