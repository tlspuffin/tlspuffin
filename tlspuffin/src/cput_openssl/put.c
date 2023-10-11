#include <stdlib.h>

typedef struct SSL {
    int dummy_field;
} SSL;

SSL* new_ssl() {
    SSL* result = (SSL*) malloc(8*sizeof(SSL));
    result->dummy_field = 42;

    return result;
}

const char* version() {
    return "0.0.1-dummy-cputopenssl";
}