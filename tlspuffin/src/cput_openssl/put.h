#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

// FIXME: C/Rust duplication of type definitions
//
//     All the types related to the descriptor are equivalent of the Rust
//     structs and enums. To avoid discrepancy, we could generate a header from
//     Rust using `cbindgen` or use the C definition in Rust using `bindgen`.
//
//     Another solution would be to expose functions to retrieve config
//     informations from Rust. This has the advantage to completely hide the
//     rust structs at the price of a small performance cost each time one of
//     these functions is called.

typedef void *RESULT;

typedef enum
{
    V1_3,
    V1_2
} TLS_VERSION;

typedef enum
{
    CLIENT,
    SERVER
} AGENT_TYPE;

typedef struct
{
    const uint8_t *const bytes;
    const size_t length;
} PEM;

typedef enum
{
    RESULT_OK,
    RESULT_IO_WOULD_BLOCK,
    RESULT_ERROR_FATAL,
    RESULT_ERROR_OTHER
} RESULT_CODE;

typedef struct
{
    uint8_t name;
    AGENT_TYPE type;
    TLS_VERSION tls_version;
    bool client_authentication;
    bool server_authentication;
    const PEM cert;
    const PEM pkey;
    const PEM *const *const store;
} AGENT_DESCRIPTOR;

typedef struct C_PUT_TYPE
{
    void *(*const create)(AGENT_DESCRIPTOR *descriptor);
    const char *(*const version)();

    void (*const progress)(void *agent);
    void (*const reset)(void *agent);
    void (*const rename_agent)(void *agent, uint8_t agent_name);
    const char *(*const describe_state)(void *agent);
    bool (*const is_state_successful)(void *agent);
    void (*const set_deterministic)(void *agent);
    const char *(*const shutdown)(void *agent);

    RESULT (*const add_inbound)(void *agent, const uint8_t *bytes, size_t length, size_t *written);
    RESULT (*const take_outbound)(void *agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
} C_PUT_TYPE;

typedef struct
{
    void (*const error)(const char *message);
    void (*const warn)(const char *message);
    void (*const info)(const char *message);
    void (*const debug)(const char *message);
    void (*const trace)(const char *message);

    RESULT (*const make_result)(RESULT_CODE code, const char *description);
} C_TLSPUFFIN;

const C_PUT_TYPE CPUT;

extern const C_TLSPUFFIN TLSPUFFIN;