#include <stdlib.h>
#include <stdbool.h>

typedef struct C_PUT_TYPE
{
    void *(*new)();
    const char *(*version)();

    void (*progress)(void *put, uint8_t agent_name);
    void (*reset)(void *put, uint8_t agent_name);
    void (*rename_agent)(void *put, uint8_t agent_name);
    const char *(*describe_state)(void *put);
    bool (*is_state_successful)(void *put);
    void (*set_deterministic)(void *put);
    const char *(*shutdown)(void *put);

    int (*add_inbound)(void *put, const uint8_t *bytes, size_t length);
    int (*take_outbound)(void *put, uint8_t **bytes, size_t *length);
} C_PUT_TYPE;

const C_PUT_TYPE CPUT;