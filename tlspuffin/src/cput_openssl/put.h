#include <stdlib.h>

typedef struct C_PUT_TYPE
{
    void *(*new)();
    const char *(*version)();
} C_PUT_TYPE;

const C_PUT_TYPE CPUT;