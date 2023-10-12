#include <stdlib.h>

#include "put.h"

const char *cput_version()
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

const C_PUT_TYPE CPUT = {
    .new = new_ssl,
    .version = cput_version,
};